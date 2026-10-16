package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/firewall"
	"github.com/infrafence/infrafence-agent/internal/watcher"
)

// The last known protection, kept in /var/lib/infrafence/protection-state.json
// (0600, replaced atomically) so a restart while the dashboard is unreachable
// or refuses the agent (401, 403) does not drop it:
//
//   - the allow list, the blocked countries, monitor mode and the brute-force
//     settings of the last successful sync;
//   - every active ban with its expiry (the dashboard's, or localBanFor for
//     the agent's own detections);
//   - the outbox: bans the agent made itself that the dashboard has not
//     confirmed yet.
//
// At startup it is restored before the firewall setup (bans, allow list)
// and before any watcher runs (allow list, monitor mode, countries). The
// first successful sync replaces all of it with the dashboard's state, except
// the bans still in the outbox: they are reported first and spared by that
// sync's cleanup.

var protStatePath = "/var/lib/infrafence/protection-state.json"

const (
	// localBanFor is how long the agent's own bans last on this server
	// until the dashboard gives them an expiry (its first escalation step).
	localBanFor = 24 * time.Hour
	// reportedGrace spares a reported ban that the next sync does not list
	// yet (fetched before the report arrived).
	reportedGrace = 10 * time.Minute
	// maxBanOutbox bounds the bans waiting to be reported.
	maxBanOutbox = 5000
	// protSaveDelay groups the writes of a burst of bans.
	protSaveDelay = 2 * time.Second
	// evictionReportEvery limits the ban_capacity_reached warning.
	evictionReportEvery = 10 * time.Minute
)

type protPersisted struct {
	SavedAt int64 `json:"saved_at"`
	// Synced: the settings below come from a successful sync.
	Synced         bool           `json:"synced"`
	WhitelistIPs   []string       `json:"whitelist_ips"`
	WhitelistCIDRs []string       `json:"whitelist_cidrs"`
	Countries      []string       `json:"blocked_countries"`
	MonitorMode    bool           `json:"monitor_mode"`
	BFThreshold    int            `json:"bf_threshold,omitempty"`
	BFWindow       int            `json:"bf_window,omitempty"`
	Bans           []firewall.Ban `json:"bans"`
	Outbox         []pendingBan   `json:"outbox,omitempty"`
}

// pendingBan is a ban the agent made itself, kept until the dashboard lists
// it in a sync (or reportedGrace after it was reported without being listed:
// the dashboard decided otherwise).
type pendingBan struct {
	IP     string `json:"ip"`
	Reason string `json:"reason"`
	Count  int    `json:"count"`
	At     int64  `json:"at"`
	// Reported is when the dashboard accepted the report; zero: not yet.
	Reported int64 `json:"reported,omitempty"`
}

var prot = struct {
	sync.Mutex
	settings protPersisted // Synced, whitelist, countries, mode, bf
	outbox   map[string]*pendingBan
	saveAt   *time.Timer
}{outbox: map[string]*pendingBan{}}

// Replaced in tests.
var protNow = time.Now

// loadProtectionState reads the state file. A missing file is no state; an
// unreadable or corrupt one is logged and set aside (.corrupt) and the agent
// starts with no saved state rather than failing.
func loadProtectionState() *protPersisted {
	data, err := os.ReadFile(protStatePath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[protection] read %s: %v — starting without the saved state", protStatePath, err)
		}
		return nil
	}
	var st protPersisted
	if err := json.Unmarshal(data, &st); err != nil {
		log.Printf("[protection] %s is not valid (%v) — starting without the saved state", protStatePath, err)
		_ = os.Rename(protStatePath, protStatePath+".corrupt")
		return nil
	}
	return &st
}

// restoreBeforeFirewall puts back, before firewall.Init, the bans and the
// allow list, and loads the outbox. Settings from a sync are kept for
// restoreSettings.
func restoreBeforeFirewall(st *protPersisted) {
	if st == nil {
		return
	}
	prot.Lock()
	if st.Synced {
		prot.settings = protPersisted{
			Synced:         true,
			WhitelistIPs:   cleanList(st.WhitelistIPs),
			WhitelistCIDRs: cleanList(st.WhitelistCIDRs),
			Countries:      cleanList(st.Countries),
			MonitorMode:    st.MonitorMode,
			BFThreshold:    st.BFThreshold,
			BFWindow:       st.BFWindow,
		}
	}
	for _, p := range st.Outbox {
		if ip := net.ParseIP(p.IP); ip != nil && len(prot.outbox) < maxBanOutbox {
			p.IP = ip.String()
			pp := p
			prot.outbox[p.IP] = &pp
		}
	}
	settings := prot.settings
	prot.Unlock()

	n := firewall.RestoreBans(st.Bans)
	if settings.Synced {
		firewall.RestoreAllowList(append(append(append([]string{}, settings.WhitelistIPs...), panelAllowedIPs()...), settings.WhitelistCIDRs...))
	}
	saved := "never"
	if st.SavedAt > 0 {
		saved = time.Unix(st.SavedAt, 0).UTC().Format(time.RFC3339)
	}
	log.Printf("[protection] restored from %s (saved %s): %d ban(s), %d allow-list entries, %d blocked countries, %d ban(s) to report",
		protStatePath, saved, n, len(settings.WhitelistIPs)+len(settings.WhitelistCIDRs), len(settings.Countries), len(st.Outbox))
}

// banWatchers are the watchers that ban; nil ones are skipped.
type banWatchers struct {
	auth *watcher.Watcher
	web  *watcher.WebWatcher
	mail *watcher.MailWatcher
	db   *watcher.DBWatcher
	ftp  *watcher.FTPWatcher
}

// restoreSettings applies the saved sync settings to the watchers, the geo
// lookup and the country blocks, before the watchers run and before the
// first sync (which replaces them when it succeeds).
func restoreSettings(ws banWatchers, setBlocked func([]string), applyCountries func([]string)) {
	prot.Lock()
	s := prot.settings
	prot.Unlock()
	if !s.Synced {
		return
	}
	ips := append(append([]string{}, s.WhitelistIPs...), panelAllowedIPs()...)
	if ws.auth != nil {
		ws.auth.UpdateConfig(watcher.Config{Threshold: s.BFThreshold, Window: time.Duration(s.BFWindow) * time.Second})
		ws.auth.SetMonitorMode(s.MonitorMode)
		ws.auth.UpdateWhitelist(ips, s.WhitelistCIDRs)
	}
	if ws.web != nil {
		ws.web.SetMonitorMode(s.MonitorMode)
		ws.web.UpdateWhitelist(ips, s.WhitelistCIDRs)
	}
	if ws.mail != nil {
		ws.mail.SetMonitorMode(s.MonitorMode)
		ws.mail.UpdateWhitelist(ips, s.WhitelistCIDRs)
	}
	if ws.db != nil {
		ws.db.SetMonitorMode(s.MonitorMode)
		ws.db.UpdateWhitelist(ips, s.WhitelistCIDRs)
	}
	if ws.ftp != nil {
		ws.ftp.SetMonitorMode(s.MonitorMode)
		ws.ftp.UpdateWhitelist(ips, s.WhitelistCIDRs)
	}
	if setBlocked != nil {
		setBlocked(s.Countries)
	}
	if applyCountries != nil && !s.MonitorMode && len(s.Countries) > 0 {
		applyCountries(s.Countries)
	}
	intelState.Lock()
	intelState.monitorMode = s.MonitorMode
	intelState.whitelist = append(append([]string{}, ips...), s.WhitelistCIDRs...)
	intelState.Unlock()
}

// noteSyncedSettings records the settings of a successful sync (the
// dashboard's allow list, without the panel's) and saves them.
func noteSyncedSettings(wlIPs, wlCIDRs, countries []string, monitorMode bool, bfThreshold, bfWindow int) {
	prot.Lock()
	prot.settings = protPersisted{
		Synced:         true,
		WhitelistIPs:   cleanList(wlIPs),
		WhitelistCIDRs: cleanList(wlCIDRs),
		Countries:      cleanList(countries),
		MonitorMode:    monitorMode,
		BFThreshold:    bfThreshold,
		BFWindow:       bfWindow,
	}
	prot.Unlock()
	scheduleProtectionSave()
}

// scheduleProtectionSave writes the state protSaveDelay from now; changes
// meanwhile are part of the same write.
func scheduleProtectionSave() {
	prot.Lock()
	defer prot.Unlock()
	if prot.saveAt != nil {
		return
	}
	prot.saveAt = time.AfterFunc(protSaveDelay, func() {
		prot.Lock()
		prot.saveAt = nil
		prot.Unlock()
		saveProtectionState()
	})
}

// saveProtectionState writes the state file now.
func saveProtectionState() {
	bans := firewall.Bans()
	prot.Lock()
	st := prot.settings
	st.SavedAt = protNow().Unix()
	st.Bans = bans
	for _, p := range prot.outbox {
		st.Outbox = append(st.Outbox, *p)
	}
	prot.Unlock()
	sort.Slice(st.Outbox, func(i, j int) bool { return st.Outbox[i].At < st.Outbox[j].At })
	if err := writeFileAtomic(protStatePath, st); err != nil {
		log.Printf("[protection] save %s: %v", protStatePath, err)
	}
}

// noteLocalBan records a ban the agent made itself, to report.
func noteLocalBan(ip, reason string, count int) {
	prot.Lock()
	if len(prot.outbox) >= maxBanOutbox {
		oldest := ""
		for k, p := range prot.outbox {
			if oldest == "" || p.At < prot.outbox[oldest].At {
				oldest = k
			}
		}
		log.Printf("[protection] %d bans waiting to be reported: the oldest (%s) will not be", maxBanOutbox, oldest)
		delete(prot.outbox, oldest)
	}
	prot.outbox[ip] = &pendingBan{IP: ip, Reason: reason, Count: count, At: protNow().Unix()}
	prot.Unlock()
	scheduleProtectionSave()
}

// noteBanReported marks a local ban accepted by the dashboard.
func noteBanReported(ip string) {
	prot.Lock()
	if p := prot.outbox[ip]; p != nil {
		p.Reported = protNow().Unix()
	}
	prot.Unlock()
	scheduleProtectionSave()
}

// Replaced in tests.
var (
	reportBan  = func(client *api.Client, req api.BanRequest) error { return client.ReportBan(req) }
	banInForce = firewall.IsBanned
)

// flushLocalBans reports the local bans the dashboard was not told about,
// oldest first, after a successful sync. A ban no longer in force (expired
// here, lifted from the panel or the dashboard) is dropped, not reported:
// the dashboard would enforce it again. It stops at the first failure.
func flushLocalBans(client *api.Client) {
	prot.Lock()
	var todo []pendingBan
	for _, p := range prot.outbox {
		if p.Reported == 0 {
			todo = append(todo, *p)
		}
	}
	prot.Unlock()
	if len(todo) == 0 {
		return
	}
	sort.Slice(todo, func(i, j int) bool { return todo[i].At < todo[j].At })
	sent, dropped := 0, 0
	for _, p := range todo {
		if !banInForce(p.IP) {
			prot.Lock()
			delete(prot.outbox, p.IP)
			prot.Unlock()
			dropped++
			continue
		}
		if err := reportBan(client, api.BanRequest{IPAddress: p.IP, Reason: p.Reason, BanCount: p.Count}); err != nil {
			log.Printf("[protection] %d ban(s) still to report: %v", len(todo)-sent-dropped, err)
			break
		}
		noteBanReported(p.IP)
		sent++
	}
	if sent+dropped > 0 {
		log.Printf("[protection] reported %d ban(s) made while the dashboard could not be told; %d no longer in force, dropped", sent, dropped)
		scheduleProtectionSave()
	}
}

// localBansToKeep returns the local bans a sync's cleanup must not remove:
// not reported yet, or reported less than reportedGrace ago and not listed
// by this sync. Bans the sync lists are confirmed and leave the outbox, and
// so do reported ones past the grace that it does not list.
func localBansToKeep(listed map[string]bool) map[string]bool {
	now := protNow().Unix()
	keep := map[string]bool{}
	changed := false
	prot.Lock()
	for ip, p := range prot.outbox {
		switch {
		case listed[ip]:
			delete(prot.outbox, ip)
			changed = true
		case p.Reported == 0 || now-p.Reported < int64(reportedGrace/time.Second):
			keep[ip] = true
		default:
			delete(prot.outbox, ip)
			changed = true
		}
	}
	prot.Unlock()
	if changed {
		scheduleProtectionSave()
	}
	return keep
}

func outboxLen() int {
	prot.Lock()
	defer prot.Unlock()
	return len(prot.outbox)
}

// banExpiries turns the sync's bans into firewall bans with their expiry.
func banExpiries(bans []api.Ban) []firewall.Ban {
	out := make([]firewall.Ban, 0, len(bans))
	for _, b := range bans {
		fb := firewall.Ban{IP: b.IPAddress}
		if b.ExpiresAt != nil {
			fb.Expires, _ = parseBanExpiry(*b.ExpiresAt)
		}
		out = append(out, fb)
	}
	return out
}

// unexpiredBans leaves out the bans whose expiry is at or before now.
func unexpiredBans(bans []api.Ban, now time.Time) []api.Ban {
	kept := bans[:0:0]
	for _, b := range bans {
		if b.ExpiresAt != nil {
			if t, ok := parseBanExpiry(*b.ExpiresAt); ok && !t.After(now) {
				continue
			}
		}
		kept = append(kept, b)
	}
	return kept
}

// parseBanExpiry reads the dashboard's expires_at (RFC 3339, or "2006-01-02
// 15:04:05" in UTC). Unreadable: no expiry, and the dashboard lifts the ban
// at a sync.
func parseBanExpiry(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, true
	}
	if t, err := time.Parse(time.DateTime, s); err == nil {
		return t, true
	}
	return time.Time{}, false
}

// runBanExpiry lifts expired bans every interval, also while the dashboard
// cannot be reached; onExpired gets the lifted addresses.
func runBanExpiry(interval time.Duration, onExpired func([]string)) {
	for range time.Tick(interval) {
		if gone := firewall.ExpireBans(time.Now()); len(gone) > 0 && onExpired != nil {
			onExpired(gone)
		}
	}
}

// evictionReporter turns the firewall's evictions into one
// ban_capacity_reached warning every evictionReportEvery at most, counting
// what was evicted in between.
type evictionReporter struct {
	mu      sync.Mutex
	last    time.Time
	pending int
	report  func([]api.EventRequest) error
	now     func() time.Time
}

func (r *evictionReporter) evicted(ips []string, capacity int) {
	r.mu.Lock()
	r.pending += len(ips)
	now := r.now()
	if !r.last.IsZero() && now.Sub(r.last) < evictionReportEvery {
		r.mu.Unlock()
		return
	}
	n := r.pending
	r.pending, r.last = 0, now
	r.mu.Unlock()
	log.Printf("[firewall] WARNING: ban capacity (%d) reached: %d oldest ban(s) removed to make room", capacity, n)
	sample := ips
	if len(sample) > 10 {
		sample = sample[:10]
	}
	if r.report != nil {
		_ = r.report([]api.EventRequest{{
			Type:     "ban_capacity_reached",
			Severity: "warning",
			Details: map[string]string{
				"capacity": strconv.Itoa(capacity),
				"evicted":  strconv.Itoa(n),
				"sample":   strings.Join(sample, ","),
				"hint":     fmt.Sprintf("the oldest bans are removed first; %s", capacityHint()),
			},
			OccurredAt: now.UTC().Format(time.RFC3339),
		}})
	}
}

func capacityHint() string {
	if firewall.HasIpset() {
		return "the ipset holds 65536 entries"
	}
	return "install ipset for more than 500 bans"
}

func cleanList(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// noteSuspendedSync records a sync that says the agent is suspended (plan
// limit): the watchers only monitor, also after a restart.
func noteSuspendedSync() {
	prot.Lock()
	changed := prot.settings.Synced && !prot.settings.MonitorMode
	if changed {
		prot.settings.MonitorMode = true
	}
	prot.Unlock()
	if changed {
		scheduleProtectionSave()
	}
}

// The bans ModSecurity refuses (the dashboard's, from the last sync), so
// the ones that expire locally are lifted there too.
var modsecBans struct {
	sync.Mutex
	ips []string
}

func modsecSetBans(ips []string) {
	modsecBans.Lock()
	defer modsecBans.Unlock()
	modsecBans.ips = append([]string(nil), ips...)
	if err := modsecEngine.UpdateBannedIPs(modsecBans.ips); err != nil {
		log.Printf("[modsec] ban rules: %v", err)
	}
}

// modsecDropBans lifts expired bans from the ModSecurity list.
func modsecDropBans(gone []string) {
	if modsecEngine == nil {
		return
	}
	expired := map[string]bool{}
	for _, ip := range gone {
		expired[ip] = true
	}
	modsecBans.Lock()
	defer modsecBans.Unlock()
	kept := modsecBans.ips[:0:0]
	for _, ip := range modsecBans.ips {
		if p := net.ParseIP(ip); p == nil || !expired[p.String()] {
			kept = append(kept, ip)
		}
	}
	if len(kept) == len(modsecBans.ips) {
		return
	}
	modsecBans.ips = kept
	if err := modsecEngine.UpdateBannedIPs(kept); err != nil {
		log.Printf("[modsec] ban rules: %v", err)
	}
}
