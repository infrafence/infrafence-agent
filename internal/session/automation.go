package session

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Recurring automation: a deployment tool or control panel (Coolify,
// Ansible, a backup job) that logs in as root with the same key from the
// same address every few minutes or every hour is not a person. Scored like
// a person, each of its sessions comes out at night, as root, during other
// detectors' alerts, and the dashboard gets a critical ssh_session every
// hour. A login is recurring automation when the same user, source
// address and key fingerprint have logged in at a regular cadence:
//
//   - public key logins only (the fingerprint sshd logs), at least
//     autoMinLogins of them (autoMinLoginsPublic from a public address),
//     this one included, in the last autoWindow, the first of the series
//     at least autoMinAge ago: an intruder with a stolen key who starts
//     logging in every few minutes is scored normally for hours first;
//   - logins less than autoBurst apart count as one (a tool opening several
//     connections at once);
//   - the gaps between them are regular: at least autoRegularShare of them
//     within 10% (or a minute) of the median gap, which lies between a
//     minute and a day; a private (RFC 1918) source needs autoRegularSharePrivate.
//
// A new key, a new address or a password login has no history and keeps the
// normal scoring. Such a session is still recorded: risk factor
// recurring_automation, the context factors (unknown address, night,
// other detectors' alerts) left out, the commands it ran still counted.
//
// The history is bounded (autoMaxKeys keys, autoMaxLogins logins each, a
// week) and saved, 0600, so a restart does not forget it.
const (
	autoWindow              = 7 * 24 * time.Hour
	autoMinLogins           = 6
	autoMinLoginsPublic     = 12
	autoMinAge              = 6 * time.Hour
	autoBurst               = 30 * time.Second
	autoMinGap              = time.Minute
	autoMaxGap              = 25 * time.Hour
	autoRegularShare        = 0.75
	autoRegularSharePrivate = 0.6
	autoMaxKeys             = 500
	autoMaxLogins           = 24
	autoSaveEvery           = 5 * time.Minute
)

type automationLog struct {
	mu     sync.Mutex
	path   string
	logins map[string][]int64 // "user ip fingerprint" -> login times (Unix seconds), oldest first
	first  map[string]int64   // "user ip fingerprint" -> first login of the series (Unix seconds)
	dirty  bool
	saved  time.Time
}

func newAutomationLog() *automationLog {
	return &automationLog{logins: map[string][]int64{}, first: map[string]int64{}}
}

func autoKey(user, ip, fp string) string { return user + " " + ip + " " + fp }

// record adds a login at t and reports whether it is recurring automation.
func (a *automationLog) record(user, ip, fp string, t time.Time) bool {
	if fp == "" || user == "" || ip == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	k := autoKey(user, ip, fp)
	now := t.Unix()
	times := a.logins[k]
	// Keep the window, oldest first.
	kept := times[:0]
	for _, x := range times {
		if now-x < int64(autoWindow/time.Second) && x <= now {
			kept = append(kept, x)
		}
	}
	times = kept
	if len(times) == 0 || a.first[k] == 0 || a.first[k] > now {
		a.first[k] = now // a new series
	}
	if n := len(times); n == 0 || now-times[n-1] >= int64(autoBurst/time.Second) {
		times = append(times, now)
		if len(times) > autoMaxLogins {
			times = times[len(times)-autoMaxLogins:]
		}
		a.dirty = true
	}
	a.logins[k] = times
	if len(a.logins) > autoMaxKeys {
		a.evictLocked()
	}
	if a.dirty && a.path != "" && t.Sub(a.saved) >= autoSaveEvery {
		a.saveLocked(t)
	}
	if now-a.first[k] < int64(autoMinAge/time.Second) {
		return false
	}
	return regularCadence(times, isPrivateIP(ip))
}

// regularCadence: enough logins, at regular gaps.
func regularCadence(times []int64, private bool) bool {
	if len(times) < autoMinLogins || !private && len(times) < autoMinLoginsPublic {
		return false
	}
	gaps := make([]int64, 0, len(times)-1)
	for i := 1; i < len(times); i++ {
		gaps = append(gaps, times[i]-times[i-1])
	}
	sorted := append([]int64(nil), gaps...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	med := sorted[len(sorted)/2]
	if med < int64(autoMinGap/time.Second) || med > int64(autoMaxGap/time.Second) {
		return false
	}
	tol := max(med/10, 60)
	regular := 0
	for _, g := range gaps {
		if g >= med-tol && g <= med+tol {
			regular++
		}
	}
	share := autoRegularShare
	if private {
		share = autoRegularSharePrivate
	}
	return float64(regular) >= share*float64(len(gaps))
}

// evictLocked drops the keys whose last login is oldest.
func (a *automationLog) evictLocked() {
	keys := make([]string, 0, len(a.logins))
	for k := range a.logins {
		keys = append(keys, k)
	}
	last := func(k string) int64 {
		t := a.logins[k]
		if len(t) == 0 {
			return 0
		}
		return t[len(t)-1]
	}
	sort.Slice(keys, func(i, j int) bool { return last(keys[i]) < last(keys[j]) })
	for _, k := range keys[:len(keys)-autoMaxKeys] {
		delete(a.logins, k)
		delete(a.first, k)
	}
	a.dirty = true
}

type automationFile struct {
	Logins map[string][]int64 `json:"logins"`
	First  map[string]int64   `json:"first"`
}

// load reads the saved history from path and saves to it from now on.
func (a *automationLog) load(path string, now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.path = path
	a.saved = now
	f, err := os.Open(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[session] read %s: %v", path, err)
		}
		return
	}
	data, err := io.ReadAll(io.LimitReader(f, 4<<20))
	f.Close()
	if err != nil {
		return
	}
	var in automationFile
	if err := json.Unmarshal(data, &in); err != nil {
		log.Printf("[session] %s is not valid, ignored: %v", path, err)
		return
	}
	cut := now.Add(-autoWindow).Unix()
	for k, times := range in.Logins {
		if len(strings.Fields(k)) != 3 {
			continue
		}
		var kept []int64
		for _, x := range times {
			if x > cut && x <= now.Unix() {
				kept = append(kept, x)
			}
		}
		sort.Slice(kept, func(i, j int) bool { return kept[i] < kept[j] })
		if len(kept) > autoMaxLogins {
			kept = kept[len(kept)-autoMaxLogins:]
		}
		if len(kept) > 0 {
			a.logins[k] = kept
			a.first[k] = kept[0]
			if f := in.First[k]; f > 0 && f < kept[0] {
				a.first[k] = f
			}
		}
	}
	if len(a.logins) > autoMaxKeys {
		a.evictLocked()
	}
}

func (a *automationLog) saveLocked(now time.Time) {
	data, err := json.Marshal(automationFile{Logins: a.logins, First: a.first})
	if err != nil {
		return
	}
	a.saved = now
	if err := writeFileAtomic(a.path, data); err != nil {
		log.Printf("[session] save %s: %v", a.path, err)
		return
	}
	a.dirty = false
}

func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".ssh-automation-*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Chmod(0o600)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}
