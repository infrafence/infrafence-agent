package main

import (
	"bytes"
	"log"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// guardLog collects what the guard logs during a test.
func guardLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &buf
}

// imunifyGuard is a fake guard on a host with Imunify360, which puts its
// INPUT and OUTPUT jumps first every minute.
func imunifyGuard(early bool) *fakeGuard {
	f := newFakeGuard()
	f.repairs = []string{"jump-order:INPUT", "jump-order:OUTPUT", "jump-order:ip6tables:INPUT"}
	f.ahead = map[string]string{
		"jump-order:INPUT":           "INPUT_imunify360",
		"jump-order:OUTPUT":          "OUTPUT_imunify360",
		"jump-order:ip6tables:INPUT": "INPUT_imunify360",
	}
	f.periodicOwner = func(chain string) string {
		if strings.Contains(chain, "imunify360") {
			return "Imunify360"
		}
		return ""
	}
	f.earlyDrop = func() bool { return early }
	return f
}

// everyMinute lets the tool recreate its rules once a minute for d.
func (f *fakeGuard) everyMinute(d time.Duration) {
	for end := f.t.Add(d); f.t.Before(end); {
		f.missing = true
		f.run(time.Minute)
	}
}

// Imunify360 recreating its rules every minute: the first restore is
// logged at once, the next ones once an hour as a count; info events
// only, no conflict and no back-off.
func TestGuardExpectedRestoresSummarizedHourly(t *testing.T) {
	buf := guardLog(t)
	f := imunifyGuard(true)
	f.everyMinute(2*time.Hour + 5*time.Minute)
	out := buf.String()

	if f.repaired < 115 {
		t.Fatalf("repaired %d times in 2 hours, want about 120", f.repaired)
	}
	if n := strings.Count(out, "guard: restored"); n != 1 {
		t.Errorf("%d immediate restore lines, want the first only:\n%s", n, out)
	}
	if !strings.Contains(out, "after Imunify360 recreated its rules (expected") || !strings.Contains(out, "bans hold meanwhile in the raw table") {
		t.Errorf("first restore not explained:\n%s", out)
	}
	if n := strings.Count(out, "jump order restored"); n != 2 {
		t.Errorf("%d hourly summaries in 2 hours, want 2:\n%s", n, out)
	}
	if n, _ := f.count("firewall_conflict"); n != 0 {
		t.Errorf("%d firewall_conflict events for an expected rebuild", n)
	}
	total := 0
	for _, e := range f.events {
		if e.Type != "firewall_rules_restored" {
			t.Errorf("unexpected event %s", e.Type)
			continue
		}
		if e.Severity != "info" || e.Details["expected_after"] != "Imunify360" || e.Details["bans_held"] != "true" {
			t.Errorf("event %+v, want info after Imunify360", e)
		}
		c, _ := strconv.Atoi(e.Details["count"])
		total += c
	}
	if len(f.events) != 3 {
		t.Errorf("%d events in 2 hours, want the first and 2 summaries", len(f.events))
	}
	// The restores of the last minutes are still counted, not reported.
	if total+f.expN != f.repaired {
		t.Errorf("events count %d restores (+%d pending), Ensure restored %d times", total, f.expN, f.repaired)
	}
	if f.backoff != 0 {
		t.Errorf("back-off %v from expected restores", f.backoff)
	}
}

// Without the raw-table early drop the first line says the bans were not
// held meanwhile.
func TestGuardExpectedRestoreWithoutEarlyDrop(t *testing.T) {
	buf := guardLog(t)
	f := imunifyGuard(false)
	f.everyMinute(2 * time.Minute)
	if !strings.Contains(buf.String(), "bans are not enforced meanwhile") {
		t.Errorf("log:\n%s", buf.String())
	}
	// Banned traffic its chains accept got through meanwhile: a warning,
	// at most once an hour.
	if len(f.events) != 1 || f.events[0].Details["bans_held"] != "false" || f.events[0].Severity != "warning" {
		t.Errorf("events %+v", f.events)
	}
}

// A restore not explained by a periodic tool's jump being first is logged
// and reported at once, as before: something else was repaired too, the
// chain ahead belongs to no such tool, or the tool is not installed.
func TestGuardUnexplainedRestoresStayLoud(t *testing.T) {
	for name, tweak := range map[string]func(*fakeGuard){
		"jump removed":   func(f *fakeGuard) { f.repairs = append(f.repairs, "jump:INPUT") },
		"other chain":    func(f *fakeGuard) { f.ahead["jump-order:INPUT"] = "ufw-before-input" },
		"no ahead":       func(f *fakeGuard) { delete(f.ahead, "jump-order:OUTPUT") },
		"also an ACCEPT": func(f *fakeGuard) { f.ahead["jump-order:INPUT"] = "INPUT_imunify360,ACCEPT" },
		"not installed":  func(f *fakeGuard) { f.periodicOwner = func(string) string { return "" } },
		"no detection":   func(f *fakeGuard) { f.periodicOwner = nil },
	} {
		t.Run(name, func(t *testing.T) {
			buf := guardLog(t)
			f := imunifyGuard(true)
			tweak(f)
			f.everyMinute(5 * time.Minute)
			if n := strings.Count(buf.String(), "guard: restored"); n != f.repaired || n < 4 {
				t.Errorf("%d restore lines for %d restores", n, f.repaired)
			}
			if strings.Contains(buf.String(), "expected") {
				t.Errorf("called expected:\n%s", buf.String())
			}
			if n, e := f.count("firewall_rules_restored"); n == 0 || e.Severity != "warning" {
				t.Errorf("restored events = %d, last %+v", n, e)
			}
			if n, _ := f.count("firewall_conflict"); n != 1 {
				t.Errorf("conflict events = %d, want 1", n)
			}
		})
	}
}

// Expected restores neither make a real repair right after them look
// back-to-back nor hide it.
func TestGuardExpectedThenRealRepair(t *testing.T) {
	buf := guardLog(t)
	f := imunifyGuard(true)
	f.everyMinute(3 * time.Minute)
	f.repairs, f.ahead = []string{"chain"}, nil
	f.missing = true
	f.run(10 * time.Second)
	if !strings.Contains(buf.String(), "guard: restored [chain]") {
		t.Errorf("real repair not logged:\n%s", buf.String())
	}
	if n, e := f.count("firewall_rules_restored"); n == 0 || e.Severity != "warning" {
		t.Errorf("restored events = %d, last %+v", n, e)
	}
	if f.backoff != 0 {
		t.Errorf("back-off %v: an expected restore counted as back-to-back", f.backoff)
	}
}

// An "Imunify360" chain put first every few seconds is not its
// once-a-minute rebuild: reported as usual, with a conflict.
func TestGuardExpectedTooOftenStaysLoud(t *testing.T) {
	buf := guardLog(t)
	f := imunifyGuard(true)
	for i := 0; i < 30; i++ {
		f.missing = true
		f.run(10 * time.Second)
	}
	if n := strings.Count(buf.String(), "guard: restored"); n < 10 {
		t.Errorf("%d restore lines for %d restores every 10 s", n, f.repaired)
	}
	if n, _ := f.count("firewall_conflict"); n != 1 {
		t.Errorf("conflict events = %d, want 1", n)
	}
}
