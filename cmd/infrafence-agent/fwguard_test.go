package main

import (
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/firewall"
)

// fakeGuard drives a firewallGuard on a fake clock: missing says what the
// quick check finds, ensureErr and repairs what Ensure returns, csfPID who
// holds csf's lock (0: nobody).
type fakeGuard struct {
	*firewallGuard
	t, start        time.Time
	missing         bool
	checkErr        error
	checkTakes      time.Duration
	ensureErr       error
	repairs         []string
	csfPID          int
	checks, ensures int
	repaired        int             // Ensure calls that repaired something
	ensureAt        []time.Duration // since the start
	events          []api.EventRequest
}

func newFakeGuard() *fakeGuard {
	f := &fakeGuard{t: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)}
	f.start = f.t
	f.firewallGuard = &firewallGuard{
		now: func() time.Time { return f.t },
		needsRepair: func() (bool, error) {
			f.checks++
			f.t = f.t.Add(f.checkTakes)
			return f.missing, f.checkErr
		},
		csfHolder: func() (int, bool) { return f.csfPID, f.csfPID != 0 },
		ensure: func() (firewall.EnsureResult, error) {
			f.ensures++
			f.ensureAt = append(f.ensureAt, f.t.Sub(f.start))
			if f.ensureErr != nil {
				return firewall.EnsureResult{}, f.ensureErr
			}
			if !f.missing {
				return firewall.EnsureResult{}, nil
			}
			f.missing = false
			f.repaired++
			return firewall.EnsureResult{Repairs: f.repairs}, nil
		},
		report: func(e []api.EventRequest) error { f.events = append(f.events, e...); return nil },
	}
	f.firewallGuard.start()
	return f
}

// run ticks once a second for d.
func (f *fakeGuard) run(d time.Duration) {
	for end := f.t.Add(d); f.t.Before(end); {
		f.t = f.t.Add(guardTick)
		f.tick()
	}
}

func (f *fakeGuard) count(typ string) (n int, last api.EventRequest) {
	for _, e := range f.events {
		if e.Type == typ {
			n++
			last = e
		}
	}
	return n, last
}

// A flushed firewall is repaired at the next quick check, then once more
// 2 s later (a tool still adding ACCEPT rules); one event.
func TestGuardQuickRepairAndFollowUp(t *testing.T) {
	f := newFakeGuard()
	f.repairs = []string{"chain", "jump:INPUT"}
	f.run(7 * time.Second)
	f.missing = true
	f.run(6 * time.Second)
	if f.ensures != 2 {
		t.Fatalf("ensures = %d at %v, want the repair and its follow-up", f.ensures, f.ensureAt)
	}
	if d := f.ensureAt[1] - f.ensureAt[0]; d != guardFollowUp {
		t.Errorf("follow-up %v after the repair, want %v", d, guardFollowUp)
	}
	if n, e := f.count("firewall_rules_restored"); n != 1 || e.Details["restored"] != "chain, jump:INPUT" || e.Details["count"] != "1" {
		t.Errorf("restored events = %d, last %+v", n, e.Details)
	}
	if n, _ := f.count("firewall_conflict"); n != 0 {
		t.Error("conflict after a single rebuild")
	}
	if f.backoff != 0 {
		t.Errorf("back-off %v after a single rebuild", f.backoff)
	}
}

// Ensure failing: retries back off 5, 10, 20, 40, 60, 60 s; five quiet
// minutes reset it.
func TestGuardBackoffOnErrors(t *testing.T) {
	f := newFakeGuard()
	f.missing = true
	f.ensureErr = errors.New("iptables-restore: timed out")
	f.run(4 * time.Minute)
	var gaps []time.Duration
	for i := 1; i < len(f.ensureAt); i++ {
		gaps = append(gaps, f.ensureAt[i]-f.ensureAt[i-1])
	}
	want := []time.Duration{5, 10, 20, 40, 60, 60}
	for i, w := range want {
		if i >= len(gaps) || gaps[i] != w*time.Second {
			t.Fatalf("gaps between attempts %v, want %v s first", gaps, want)
		}
	}
	f.ensureErr = nil
	f.run(guardQuiet + 2*time.Minute)
	if f.backoff != 0 {
		t.Errorf("back-off %v after a quiet period", f.backoff)
	}
}

// A failing quick check (iptables timing out) backs off too: it is not
// re-run every 5 s.
func TestGuardBackoffOnCheckErrors(t *testing.T) {
	f := newFakeGuard()
	f.checkErr = errors.New("iptables -S INPUT: timed out")
	f.run(50 * time.Second) // before the first full check
	// 5 s, then +5, +10, +20 s: 4 checks, not 10.
	if f.checks != 4 {
		t.Errorf("checks = %d in 50 s with failing iptables, want 4", f.checks)
	}
	if f.ensures != 0 {
		t.Errorf("ensures = %d after failed checks", f.ensures)
	}
}

// Another tool rewriting the firewall every few seconds: back-off grows,
// one conflict, and restored events stay at one a minute with a count.
func TestGuardBackToBackAndEventRateLimit(t *testing.T) {
	f := newFakeGuard()
	f.repairs = []string{"chain"}
	for i := 0; i < 30; i++ { // flushed again every 6 s for 3 minutes
		f.missing = true
		f.run(6 * time.Second)
	}
	if f.backoff < 20*time.Second {
		t.Errorf("back-off %v while the firewall is rewritten every 6 s", f.backoff)
	}
	if n, _ := f.count("firewall_conflict"); n != 1 {
		t.Errorf("conflict events = %d, want 1 (once an hour)", n)
	}
	n, last := f.count("firewall_rules_restored")
	if n < 3 || n > 4 {
		t.Errorf("restored events = %d in 3 minutes, want one a minute", n)
	}
	if last.Details["count"] == "1" {
		t.Errorf("later events do not aggregate: %+v", last.Details)
	}
	f.run(2 * time.Minute) // the last batch goes out
	total := 0
	for _, e := range f.events {
		if e.Type == "firewall_rules_restored" {
			c, err := strconv.Atoi(e.Details["count"])
			if err != nil {
				t.Fatalf("count %q", e.Details["count"])
			}
			total += c
		}
	}
	if total != f.repaired {
		t.Errorf("events count %d repairs, Ensure repaired %d times", total, f.repaired)
	}
}

// csf holding its lock: no repair for up to 2 minutes; after that the same
// holder no longer delays repairs; a new holder is waited for again.
func TestGuardWaitsForCSF(t *testing.T) {
	f := newFakeGuard()
	f.repairs = []string{"chain"}
	f.csfPID = 4242
	f.missing = true
	f.run(90 * time.Second)
	if f.ensures != 0 {
		t.Fatalf("repaired while csf held its lock (%v)", f.ensureAt)
	}
	f.csfPID = 0
	f.run(6 * time.Second)
	if f.ensures == 0 {
		t.Fatal("not repaired once csf was done")
	}

	// A hung csf: forced after 2 minutes, then not delayed again.
	f = newFakeGuard()
	f.repairs = []string{"chain"}
	f.csfPID = 4242
	f.missing = true
	f.run(guardCSFWait + 10*time.Second)
	if f.ensures == 0 {
		t.Fatal("never repaired with csf hung on its lock")
	}
	f.run(10 * time.Minute) // the back-off from repeated repairs resets in between
	f.missing = true
	at := f.t.Sub(f.start)
	f.run(10 * time.Second)
	if f.missing {
		t.Errorf("same hung holder delayed a repair again: ensures at %v, flushed at %v", f.ensureAt, at)
	}
	n := f.ensures

	// A new holder is waited for.
	f.csfPID = 4343
	f.missing = true
	n = f.ensures
	f.run(30 * time.Second)
	if f.ensures != n {
		t.Error("repaired while a new csf run held the lock")
	}
}

// A slow check (a huge rule set) spaces the next ones out.
func TestGuardSlowCheckSpacing(t *testing.T) {
	f := newFakeGuard()
	f.checkTakes = 2 * time.Second
	f.run(55 * time.Second)
	// 5 s, then every 20 s (10 x 2 s): 3 checks, not 9.
	if f.checks != 3 {
		t.Errorf("checks = %d in 55 s with a 2 s check, want 3", f.checks)
	}
}
