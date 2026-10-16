package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/firewall"
)

// withProtState isolates the protection state: a temporary state file, an
// empty outbox and settings, a clock the test sets, and no real reports.
func withProtState(t *testing.T) (now *time.Time, reports *[]api.BanRequest) {
	t.Helper()
	savedPath, savedNow, savedReport, savedInForce := protStatePath, protNow, reportBan, banInForce
	protStatePath = filepath.Join(t.TempDir(), "protection-state.json")
	clock := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	now = &clock
	protNow = func() time.Time { return *now }
	var mu sync.Mutex
	var sent []api.BanRequest
	reportBan = func(_ *api.Client, req api.BanRequest) error {
		mu.Lock()
		defer mu.Unlock()
		sent = append(sent, req)
		return nil
	}
	banInForce = func(string) bool { return true }
	prot.Lock()
	savedSettings, savedOutbox := prot.settings, prot.outbox
	prot.settings, prot.outbox = protPersisted{}, map[string]*pendingBan{}
	prot.Unlock()
	t.Cleanup(func() {
		prot.Lock()
		if prot.saveAt != nil {
			prot.saveAt.Stop()
			prot.saveAt = nil
		}
		prot.settings, prot.outbox = savedSettings, savedOutbox
		prot.Unlock()
		protStatePath, protNow, reportBan, banInForce = savedPath, savedNow, savedReport, savedInForce
		firewall.RestoreAllowList(nil) // set by restoreBeforeFirewall
	})
	return now, &sent
}

// The state is written atomically (no temporary file left, 0600) and read
// back as it was.
func TestProtectionStateRoundTrip(t *testing.T) {
	withProtState(t)
	noteSyncedSettings([]string{"198.51.100.7", "198.51.100.7"}, []string{"192.0.2.0/24"}, []string{"CN", "RU"}, false, 5, 60)
	noteLocalBan("203.0.113.9", "ssh_brute_force", 6)
	saveProtectionState()

	fi, err := os.Stat(protStatePath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600", fi.Mode().Perm())
	}
	entries, _ := os.ReadDir(filepath.Dir(protStatePath))
	if len(entries) != 1 {
		t.Fatalf("files left next to the state: %v", entries)
	}
	st := loadProtectionState()
	if st == nil || !st.Synced {
		t.Fatalf("state not read back: %+v", st)
	}
	if !reflect.DeepEqual(st.WhitelistIPs, []string{"198.51.100.7"}) || !reflect.DeepEqual(st.WhitelistCIDRs, []string{"192.0.2.0/24"}) ||
		!reflect.DeepEqual(st.Countries, []string{"CN", "RU"}) || st.BFThreshold != 5 || st.BFWindow != 60 {
		t.Fatalf("settings: %+v", st)
	}
	if len(st.Outbox) != 1 || st.Outbox[0].IP != "203.0.113.9" || st.Outbox[0].Reported != 0 {
		t.Fatalf("outbox: %+v", st.Outbox)
	}

	// A restart: the outbox and the settings come back.
	prot.Lock()
	prot.settings, prot.outbox = protPersisted{}, map[string]*pendingBan{}
	prot.Unlock()
	restoreBeforeFirewall(st)
	if outboxLen() != 1 {
		t.Fatal("outbox not restored")
	}
	prot.Lock()
	got := prot.settings.Countries
	prot.Unlock()
	if !reflect.DeepEqual(got, []string{"CN", "RU"}) {
		t.Fatalf("countries after restore: %v", got)
	}
}

// A corrupt or truncated state file is set aside: the agent starts with no
// saved state instead of failing, and the next save writes a good file.
func TestProtectionStateCorrupt(t *testing.T) {
	withProtState(t)
	for _, bad := range []string{"{not json", `{"bans": [`, "\x00\x01\x02"} {
		if err := os.WriteFile(protStatePath, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if st := loadProtectionState(); st != nil {
			t.Fatalf("%q: got state %+v", bad, st)
		}
		if _, err := os.Stat(protStatePath + ".corrupt"); err != nil {
			t.Fatalf("%q: not set aside: %v", bad, err)
		}
		restoreBeforeFirewall(nil) // must not panic
	}
	if st := loadProtectionState(); st != nil {
		t.Fatal("a missing file is no state")
	}
	saveProtectionState()
	if st := loadProtectionState(); st == nil {
		t.Fatal("no state after saving again")
	}
}

// Bans made while the dashboard refuses the agent are reported at the
// first successful sync and survive its cleanup until the dashboard lists
// them.
func TestLocalBanOutbox(t *testing.T) {
	now, reports := withProtState(t)
	failing := errors.New("server returned 403: suspended")
	reportBan = func(_ *api.Client, req api.BanRequest) error { return failing }

	noteLocalBan("203.0.113.1", "ssh_brute_force", 5)
	*now = now.Add(time.Second)
	noteLocalBan("203.0.113.2", "web_attack", 1)
	*now = now.Add(time.Second)
	noteLocalBan("203.0.113.3", "ftp_brute_force", 3)

	// Refused: nothing leaves the outbox, the cleanup spares all three.
	flushLocalBans(nil)
	if keep := localBansToKeep(nil); len(keep) != 3 {
		t.Fatalf("kept %v, want all three", keep)
	}

	// Accepted again: oldest first; one is no longer in force (expired
	// here) and is dropped, not reported.
	var sent []string
	reportBan = func(_ *api.Client, req api.BanRequest) error {
		sent = append(sent, req.IPAddress+"/"+req.Reason)
		*reports = append(*reports, req)
		return nil
	}
	banInForce = func(ip string) bool { return ip != "203.0.113.2" }
	flushLocalBans(nil)
	if !reflect.DeepEqual(sent, []string{"203.0.113.1/ssh_brute_force", "203.0.113.3/ftp_brute_force"}) {
		t.Fatalf("reported %v", sent)
	}
	if (*reports)[0].BanCount != 5 {
		t.Fatalf("ban count %d", (*reports)[0].BanCount)
	}
	// The sync fetched before the reports does not list them: still kept.
	keep := localBansToKeep(map[string]bool{})
	if !reflect.DeepEqual(keep, map[string]bool{"203.0.113.1": true, "203.0.113.3": true}) {
		t.Fatalf("kept %v", keep)
	}
	flushLocalBans(nil)
	if len(sent) != 2 {
		t.Fatalf("reported twice: %v", sent)
	}
	// The next sync lists .1: confirmed. .3 is never listed: after the
	// grace the dashboard's state wins.
	keep = localBansToKeep(map[string]bool{"203.0.113.1": true})
	if !reflect.DeepEqual(keep, map[string]bool{"203.0.113.3": true}) {
		t.Fatalf("kept %v", keep)
	}
	*now = now.Add(reportedGrace)
	if keep := localBansToKeep(map[string]bool{}); len(keep) != 0 || outboxLen() != 0 {
		t.Fatalf("kept %v, outbox %d after the grace", keep, outboxLen())
	}
}

// A partial failure stops the flush; the rest is sent at the next sync.
func TestLocalBanOutboxStopsAtFirstFailure(t *testing.T) {
	now, _ := withProtState(t)
	for i, ip := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"} {
		*now = now.Add(time.Duration(i) * time.Second)
		noteLocalBan(ip, "x", 1)
	}
	calls := 0
	reportBan = func(_ *api.Client, req api.BanRequest) error {
		calls++
		if calls == 2 {
			return errors.New("connection reset")
		}
		return nil
	}
	flushLocalBans(nil)
	if calls != 2 {
		t.Fatalf("%d reports, want a stop after the failure", calls)
	}
	prot.Lock()
	pending := 0
	for _, p := range prot.outbox {
		if p.Reported == 0 {
			pending++
		}
	}
	prot.Unlock()
	if pending != 2 {
		t.Fatalf("%d pending, want 2", pending)
	}
}

func TestLocalBanOutboxBounded(t *testing.T) {
	now, _ := withProtState(t)
	for i := 0; i < maxBanOutbox+5; i++ {
		*now = now.Add(time.Second)
		noteLocalBan(fmt.Sprintf("2001:db8::%x", i), "x", 1)
	}
	if n := outboxLen(); n != maxBanOutbox {
		t.Fatalf("outbox %d, want %d", n, maxBanOutbox)
	}
}

func TestEvictionReporterIsRateLimited(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	var events []api.EventRequest
	r := &evictionReporter{
		report: func(e []api.EventRequest) error { events = append(events, e...); return nil },
		now:    func() time.Time { return now },
	}
	r.evicted([]string{"203.0.113.1"}, 500)
	r.evicted([]string{"203.0.113.2", "203.0.113.3"}, 500)
	if len(events) != 1 || events[0].Type != "ban_capacity_reached" || events[0].Severity != "warning" || events[0].Details["evicted"] != "1" {
		t.Fatalf("events %+v", events)
	}
	now = now.Add(evictionReportEvery)
	r.evicted([]string{"203.0.113.4"}, 500)
	if len(events) != 2 || events[1].Details["evicted"] != "3" || events[1].Details["capacity"] != "500" {
		t.Fatalf("second warning %+v, want the 3 evicted since the first", events)
	}
}

func TestBanExpiries(t *testing.T) {
	s1, s2, bad := "2026-10-17T12:00:00Z", "2026-10-17 12:00:00", "tomorrow"
	got := banExpiries([]api.Ban{{IPAddress: "203.0.113.1", ExpiresAt: &s1}, {IPAddress: "203.0.113.2", ExpiresAt: &s2}, {IPAddress: "203.0.113.3"}, {IPAddress: "203.0.113.4", ExpiresAt: &bad}})
	want := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	if !got[0].Expires.Equal(want) || !got[1].Expires.Equal(want) || !got[2].Expires.IsZero() || !got[3].Expires.IsZero() {
		t.Fatalf("%+v", got)
	}
	past := "2026-10-16T11:59:59Z"
	kept := unexpiredBans([]api.Ban{{IPAddress: "203.0.113.1", ExpiresAt: &s1}, {IPAddress: "203.0.113.2", ExpiresAt: &past}, {IPAddress: "203.0.113.3"}}, want.Add(-24*time.Hour))
	if len(kept) != 2 || kept[0].IPAddress != "203.0.113.1" || kept[1].IPAddress != "203.0.113.3" {
		t.Fatalf("unexpired: %+v", kept)
	}
}
