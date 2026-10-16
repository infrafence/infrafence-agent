package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/backoff"
	"github.com/infrafence/infrafence-agent/internal/firewall"
	"github.com/infrafence/infrafence-agent/internal/verify"
)

type refusalHost struct {
	mu                          sync.Mutex
	disabled, enabled, detached int
	stopped                     int
	events                      []api.EventRequest
}

func (h *refusalHost) report(e []api.EventRequest) error {
	h.mu.Lock()
	h.events = append(h.events, e...)
	h.mu.Unlock()
	return nil
}

// withRefusal isolates the switch-off: the state file and motd in temporary
// directories, the firewall and web server replaced, a clock the test sets.
func withRefusal(t *testing.T, pamUsesMotd bool) (*refusalHost, *backoff.Gate, *time.Time) {
	t.Helper()
	now, _ := withProtState(t)
	h := &refusalHost{}
	dir := t.TempDir()
	saved := []any{motdDir, pamDir, refusalNow, disableFirewall, enableFirewall, detachWebserver, stopRealtimeMalware, sshSnapshot, sshCheck}
	motdDir = filepath.Join(dir, "motd.d")
	pamDir = filepath.Join(dir, "pam.d")
	_ = os.Mkdir(pamDir, 0o755)
	if pamUsesMotd {
		_ = os.WriteFile(filepath.Join(pamDir, "sshd"), []byte("session optional pam_motd.so\n"), 0o644)
	}
	refusalNow = func() time.Time { return *now }
	disableFirewall = func() []string { h.mu.Lock(); h.disabled++; h.mu.Unlock(); return []string{"chain:INFRAFENCE"} }
	enableFirewall = func() error { h.mu.Lock(); h.enabled++; h.mu.Unlock(); return nil }
	detachWebserver = func() { h.mu.Lock(); h.detached++; h.mu.Unlock() }
	stopRealtimeMalware = func() { h.mu.Lock(); h.stopped++; h.mu.Unlock() }
	sshSnapshot = func() verify.State { return verify.State{} }
	sshCheck = func(verify.State) verify.Result { return verify.Result{SSHOK: true, SitesOK: true} }
	g := backoff.NewWith(func() time.Time { return *now }, func() float64 { return 0 }, t.Logf)
	protCtl.Lock()
	savedCtl := struct {
		at   time.Time
		motd bool
		g    *backoff.Gate
	}{protCtl.disabledAt, protCtl.motdCreated, protCtl.gate}
	protCtl.disabledAt, protCtl.motdCreated, protCtl.gate = time.Time{}, false, g
	protCtl.Unlock()
	t.Cleanup(func() {
		motdDir, pamDir = saved[0].(string), saved[1].(string)
		refusalNow = saved[2].(func() time.Time)
		disableFirewall = saved[3].(func() []string)
		enableFirewall = saved[4].(func() error)
		detachWebserver, stopRealtimeMalware = saved[5].(func()), saved[6].(func())
		sshSnapshot = saved[7].(func() verify.State)
		sshCheck = saved[8].(func(verify.State) verify.Result)
		protCtl.Lock()
		protCtl.disabledAt, protCtl.motdCreated, protCtl.gate = savedCtl.at, savedCtl.motd, savedCtl.g
		protCtl.Unlock()
		firewall.SetDisabled(false)
	})
	return h, g, now
}

// 24 hours of refusals switch protection off, not one minute less; an
// unreachable dashboard never does.
func TestRefusalSwitchesOffAfter24h(t *testing.T) {
	h, g, now := withRefusal(t, true)
	g.Refused(403, []byte(`{"error":"suspended"}`))
	step := func(d time.Duration) {
		*now = now.Add(d)
		g.Refused(403, []byte(`{"error":"suspended"}`))
		checkRefusal(g, refusalLimit, h.report)
	}
	for i := 0; i < 47; i++ {
		step(30 * time.Minute)
	}
	step(29 * time.Minute) // 23h59m
	if protectionDisabled() || h.disabled != 0 {
		t.Fatal("switched off before 24 hours")
	}
	step(time.Minute)
	if !protectionDisabled() || h.disabled != 1 || h.detached != 1 || h.stopped != 1 {
		t.Fatalf("not switched off: %+v", h)
	}
	b, err := os.ReadFile(filepath.Join(motdDir, "infrafence"))
	if err != nil || !strings.Contains(string(b), "https://infrafence.com/billing") {
		t.Fatalf("motd: %q %v", b, err)
	}
	if st, _, at := protectionStatus(); st != "disabled" || at.IsZero() {
		t.Fatalf("status %s %s", st, at)
	}
	if len(h.events) != 1 || h.events[0].Type != "protection_disabled" {
		t.Fatalf("events %+v", h.events)
	}
	if w := g.Refused(401, nil); w != backoff.Suspended && g.Wait() == 0 {
		t.Fatalf("not idle: %s", w)
	}
	// Once only.
	step(time.Hour)
	if h.disabled != 1 {
		t.Fatal("switched off twice")
	}

	// Accepted again: back on, motd gone, clock reset on the next OK.
	if !enableProtection(h.report) || protectionDisabled() || h.enabled != 1 {
		t.Fatalf("not back on: %+v", h)
	}
	if _, err := os.Stat(filepath.Join(motdDir, "infrafence")); !os.IsNotExist(err) {
		t.Fatalf("motd left: %v", err)
	}
	if _, err := os.Stat(motdDir); !os.IsNotExist(err) {
		t.Fatalf("the motd.d the agent created is left: %v", err)
	}
	g.OK()
	if st, since, _ := protectionStatus(); st != "active" || !since.IsZero() {
		t.Fatalf("status %s since %s", st, since)
	}
	if enableProtection(h.report) {
		t.Fatal("enabled twice")
	}
}

// The clock and the switch-off survive a restart through the state file.
func TestRefusalPersistsAcrossRestart(t *testing.T) {
	h, g, now := withRefusal(t, false)
	start := *now
	unauth := []byte(`{"message":"Unauthenticated."}`)
	for i := 0; i <= 50; i++ {
		g.Refused(401, unauth)
		*now = now.Add(30 * time.Minute)
	}
	*now = now.Add(-30 * time.Minute)
	checkRefusal(g, refusalLimit, h.report)
	if !protectionDisabled() {
		t.Fatal("not switched off")
	}
	// No motd.d and no pam_motd: nothing written, nothing created.
	if _, err := os.Stat(motdDir); !os.IsNotExist(err) {
		t.Fatalf("motd.d created on a host that does not use it: %v", err)
	}
	saveProtectionState()

	// Restart.
	st := loadProtectionState()
	if st == nil || st.RefusedSince != start.Unix() || st.DisabledAt == 0 {
		t.Fatalf("saved %+v", st)
	}
	protCtl.Lock()
	protCtl.disabledAt = time.Time{}
	protCtl.Unlock()
	g2 := backoff.NewWith(func() time.Time { return *now }, func() float64 { return 0 }, t.Logf)
	restoreRefusal(st, g2)
	// Off again, and InfraFence's rules removed again (a reboot may have
	// restored them).
	if !protectionDisabled() || h.disabled != 2 || !g2.RefusedSince().Equal(start) {
		t.Fatalf("after restart: disabled=%v removals=%d since=%s", protectionDisabled(), h.disabled, g2.RefusedSince())
	}
	if w := g2.Refused(401, unauth); w < 27*time.Minute {
		t.Fatalf("not idle after the restart: %s", w)
	}
}

// A clock that restarted mid-way still counts from the first refusal; a
// success resets it.
func TestRefusalClockResetBySuccessOrOutage(t *testing.T) {
	h, g, now := withRefusal(t, false)
	unauth := []byte(`{"message":"Unauthenticated."}`)
	refuseFor := func(d time.Duration) {
		for end := now.Add(d); now.Before(end); *now = now.Add(30 * time.Minute) {
			g.Refused(401, unauth)
		}
		g.Refused(401, unauth)
	}
	refuseFor(20 * time.Hour)
	g.OK()
	refuseFor(5 * time.Hour)
	checkRefusal(g, refusalLimit, h.report)
	if protectionDisabled() {
		t.Fatal("a success in between did not reset the clock")
	}
	// An outage in between: not 24 hours of refusal either.
	refuseFor(20 * time.Hour)
	g.Unreachable()
	*now = now.Add(time.Hour)
	refuseFor(5 * time.Hour)
	checkRefusal(g, refusalLimit, h.report)
	if protectionDisabled() {
		t.Fatal("an outage counted as refusal")
	}
	// One refusal, a day of outage, one refusal: never.
	g.Unreachable()
	g.Refused(401, unauth)
	*now = now.Add(26 * time.Hour)
	g.Unreachable()
	g.Refused(401, unauth)
	checkRefusal(g, refusalLimit, h.report)
	if protectionDisabled() {
		t.Fatal("a refusal after a day of outage switched protection off")
	}
}

func TestRefusalLimitFor(t *testing.T) {
	t.Setenv("INFRAFENCE_TEST_REFUSAL_LIMIT", "90s")
	if d := refusalLimitFor("1.0.23"); d != refusalLimit {
		t.Fatalf("release build honours the test limit: %s", d)
	}
	if d := refusalLimitFor("1.0.23-5-gabc-test"); d != 90*time.Second {
		t.Fatalf("test build: %s", d)
	}
}
