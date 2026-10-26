package main

import (
	"encoding/json"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
)

func TestEventSubject(t *testing.T) {
	ev := func(typ string, d map[string]string) api.EventRequest { return api.EventRequest{Type: typ, Details: d} }
	cases := []struct {
		e       api.EventRequest
		subject string
		problem bool
	}{
		{ev("db_exposed", map[string]string{"port": "3306", "proto": "tcp"}), "port:tcp/3306", true},
		{ev("db_exposed", map[string]string{"warning": "Redis is exposed publicly on port 6379"}), "port:tcp/6379", true},
		{ev("db_exposed", map[string]string{"port": "99999"}), "", true},
		{ev("integrity_change", map[string]string{"file": "/etc/passwd"}), "file:/etc/passwd", true},
		{ev("integrity_change", map[string]string{"file": "relative"}), "", true},
		{ev("php_dropin_changed", map[string]string{"file": "/etc/php.d/99-infrafence.ini"}), "file:/etc/php.d/99-infrafence.ini", true},
		{ev("php_config_risk", map[string]string{"check_id": "PHP_ALLOW_URL_INCLUDE@php8.2-fpm/www"}), "php:PHP_ALLOW_URL_INCLUDE@php8.2-fpm/www", true},
		{ev("php_config_risk", map[string]string{"check_id": "SSH_ROOT"}), "", true},
		{ev("malware_realtime", map[string]string{"file_path": "/home/a/x.php"}), "malware:/home/a/x.php", true},
		{ev("virtual_patch_failed", map[string]string{"cve": "CVE-2021-44228", "action": "apply"}), "cve:CVE-2021-44228", true},
		{ev("virtual_patch_failed", map[string]string{"cve": "CVE-2021-44228", "action": "remove"}), "cve:CVE-2021-44228", false},
		{ev("hardening_fix_failed", map[string]string{"check_id": "SSH_PERMIT_ROOT", "action": "apply"}), "hardening:SSH_PERMIT_ROOT", true},
		{ev("hardening_fix_rolled_back", map[string]string{"check_id": "PHP_EXPOSE_PHP@php8.2", "action": "revert"}), "php:PHP_EXPOSE_PHP@php8.2", false},
		{ev("package_update_failed", map[string]string{"packages": "openssl"}), "package:openssl", true},
		{ev("package_update_failed", map[string]string{"packages": "openssl curl"}), "", true},
		{ev("firewall_action_done", map[string]string{"kind": "close_port", "port": "3306", "proto": "tcp"}), "port:tcp/3306", false},
		{ev("firewall_action_done", map[string]string{"kind": "block_egress", "ip": "192.0.2.3"}), "", false},
		{ev("quarantine_completed", map[string]string{"file": "/home/a/x.php"}), "malware:/home/a/x.php", false},
		{ev("hardening_fix_applied", map[string]string{"check_id": "PHP_DISPLAY_ERRORS@site:a.example"}), "php:PHP_DISPLAY_ERRORS@site:a.example", false},
		{ev("ssh_brute_force", map[string]string{"source": "watcher"}), "", false},
	}
	for _, c := range cases {
		if got := eventSubject(c.e); got != c.subject {
			t.Errorf("%s %v: subject %q, want %q", c.e.Type, c.e.Details, got, c.subject)
		}
		if got := problemEvent(c.e); got != c.problem {
			t.Errorf("%s %v: problem %v, want %v", c.e.Type, c.e.Details, got, c.problem)
		}
	}
}

func TestEnrichAddsSubject(t *testing.T) {
	shared := map[string]string{"file": "/etc/shadow"}
	e := api.EventRequest{Type: "integrity_change", Details: shared}
	enrichEvent(&e, nil)
	if e.Details["subject"] != "file:/etc/shadow" || e.Details["file"] != "/etc/shadow" {
		t.Fatalf("details %v", e.Details)
	}
	if _, ok := shared["subject"]; ok {
		t.Fatal("the caller's map was changed")
	}
	// A subject already set is kept.
	e = api.EventRequest{Type: "integrity_change", Details: map[string]string{"file": "/a", "subject": "file:/b"}}
	enrichEvent(&e, nil)
	if e.Details["subject"] != "file:/b" {
		t.Fatalf("subject replaced: %v", e.Details)
	}
	// No details, no subject: nothing added.
	e = api.EventRequest{Type: "port_scan"}
	enrichEvent(&e, nil)
	if e.Details != nil {
		t.Fatalf("details %v", e.Details)
	}
}

// eventState returns the state fields of the first event of type typ (the
// newest).
func eventState(t *testing.T, typ string) panelEventOut {
	t.Helper()
	r := panelEvents(500, "")
	for _, e := range r["events"].([]panelEventOut) {
		if e.Type == typ {
			return e
		}
	}
	t.Fatalf("no %s event", typ)
	return panelEventOut{}
}

func TestPanelEventResolvedByAgent(t *testing.T) {
	f := withFakePanel(t)
	t.Cleanup(func() { syncedResolutions.Store(nil) })
	at := func(d time.Duration) string { return f.now.Add(d).UTC().Format(time.RFC3339) }
	exposed := api.EventRequest{Type: "db_exposed", Severity: "critical", OccurredAt: at(-time.Hour),
		Details: map[string]string{"warning": "MySQL/MariaDB is exposed publicly on port 3306", "port": "3306", "proto": "tcp"}}
	panelNoteEvent(exposed)
	if e := eventState(t, "db_exposed"); e.State != "open" || e.Subject != "port:tcp/3306" || e.ResolvedAt != nil || e.ResolvedHow != nil {
		t.Fatalf("before: %+v", e)
	}

	// Closed, but still reachable over IPv6: not resolved.
	panelNoteEvent(api.EventRequest{Type: "firewall_action_done", Severity: "info", OccurredAt: at(-50 * time.Minute),
		Details: map[string]string{"kind": "close_port", "port": "3306", "proto": "tcp", "status": "done", "message": ipv6ExposedMessage}})
	if e := eventState(t, "db_exposed"); e.State != "open" {
		t.Fatalf("resolved by an IPv4-only close: %+v", e)
	}
	// A failed or rolled-back close doesn't resolve it either.
	panelNoteEvent(api.EventRequest{Type: "firewall_action_rolled_back", Severity: "warning", OccurredAt: at(-45 * time.Minute),
		Details: map[string]string{"kind": "close_port", "port": "3306", "proto": "tcp", "status": "rolled_back"}})
	if e := eventState(t, "db_exposed"); e.State != "open" {
		t.Fatalf("resolved by a rollback: %+v", e)
	}

	panelNoteEvent(api.EventRequest{Type: "firewall_action_done", Severity: "info", OccurredAt: at(-40 * time.Minute),
		Details: map[string]string{"kind": "close_port", "port": "3306", "proto": "tcp", "status": "done", "message": "port 3306 closed"}})
	e := eventState(t, "db_exposed")
	if e.State != "resolved" || e.ResolvedAt != at(-40*time.Minute) || e.ResolvedHow != "port_closed" {
		t.Fatalf("after the close: %+v", e)
	}
	// The result event has the subject, but no state.
	if r := eventState(t, "firewall_action_done"); r.Subject != "port:tcp/3306" || r.State != nil {
		t.Fatalf("result event: %+v", r)
	}
	// Other events: no subject, no state.
	panelNoteEvent(api.EventRequest{Type: "ssh_brute_force", Severity: "warning", OccurredAt: at(-30 * time.Minute)})
	if r := eventState(t, "ssh_brute_force"); r.Subject != nil || r.State != nil || r.ResolvedAt != nil || r.ResolvedHow != nil {
		t.Fatalf("attack event: %+v", r)
	}

	// Saved (0600) and restored with the panel state.
	data, err := os.ReadFile(panelStatePath)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(panelStatePath); runtime.GOOS == "linux" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	var p panelPersisted
	if err := json.Unmarshal(data, &p); err != nil || len(p.Resolved) != 1 || p.Resolved[0].Subject != "port:tcp/3306" || p.Resolved[0].By != "agent" {
		t.Fatalf("saved %s (%v)", data, err)
	}
	resetPanelState()
	loadPanelState()
	panelNoteEvent(exposed)
	if e := eventState(t, "db_exposed"); e.State != "resolved" || e.ResolvedHow != "port_closed" {
		t.Fatalf("after a restart: %+v", e)
	}

	// Exposed again later: the new event is open, the old one stays resolved.
	again := exposed
	again.OccurredAt = at(-10 * time.Minute)
	panelNoteEvent(again)
	r := panelEvents(500, "")["events"].([]panelEventOut)
	if r[0].Type != "db_exposed" || r[0].State != "open" || r[1].State != "resolved" {
		t.Fatalf("reopened: %+v", r[:2])
	}
}

func TestPanelResolvedByFixes(t *testing.T) {
	f := withFakePanel(t)
	at := func(d time.Duration) string { return f.now.Add(d).UTC().Format(time.RFC3339) }
	check := "PHP_DISPLAY_ERRORS@ea-php82"
	panelNoteEvent(api.EventRequest{Type: "php_config_risk", Severity: "warning", OccurredAt: at(-time.Hour),
		Details: map[string]string{"check_id": check}})
	// Applied, but the verification failed afterwards: not resolved; a revert neither.
	panelNoteEvent(api.EventRequest{Type: "hardening_fix_applied", Severity: "warning", OccurredAt: at(-50 * time.Minute),
		Details: map[string]string{"check_id": check, "action": "apply", "status": "applied"}})
	panelNoteEvent(api.EventRequest{Type: "hardening_fix_applied", Severity: "info", OccurredAt: at(-45 * time.Minute),
		Details: map[string]string{"check_id": check, "action": "revert", "status": "applied"}})
	if e := eventState(t, "php_config_risk"); e.State != "open" {
		t.Fatalf("resolved without a verified fix: %+v", e)
	}
	panelNoteEvent(api.EventRequest{Type: "hardening_fix_applied", Severity: "info", OccurredAt: at(-40 * time.Minute),
		Details: map[string]string{"check_id": check, "action": "apply", "status": "applied"}})
	if e := eventState(t, "php_config_risk"); e.State != "resolved" || e.ResolvedHow != "fix_applied" {
		t.Fatalf("after the fix: %+v", e)
	}

	panelNoteEvent(api.EventRequest{Type: "package_update_failed", Severity: "warning", OccurredAt: at(-30 * time.Minute),
		Details: map[string]string{"packages": "openssl"}})
	panelNoteEvent(api.EventRequest{Type: "package_update_done", Severity: "info", OccurredAt: at(-20 * time.Minute),
		Details: map[string]string{"packages": "openssl curl"}})
	if e := eventState(t, "package_update_failed"); e.State != "resolved" || e.ResolvedHow != "package_updated" {
		t.Fatalf("after the update: %+v", e)
	}

	// Findings: quarantined, then found again.
	path := "/home/alice/public_html/x.php"
	panelNoteEvent(api.EventRequest{Type: "malware_realtime", Severity: "critical", OccurredAt: at(-15 * time.Minute),
		Details: map[string]string{"file_path": path, "name": "Webshell"}})
	finding := func() panelFinding {
		return panelFindings(500)["findings"].([]panelFinding)[0]
	}
	if fd := finding(); fd.Subject != "malware:"+path || fd.State != "open" || fd.ResolvedAt != nil {
		t.Fatalf("finding before: %+v", fd)
	}
	panelNoteEvent(api.EventRequest{Type: "quarantine_completed", Severity: "info", OccurredAt: at(-10 * time.Minute),
		Details: map[string]string{"file": path}})
	if fd := finding(); fd.Status != "quarantined" || fd.State != "resolved" || fd.ResolvedHow != "quarantined" || fd.ResolvedAt != at(-10*time.Minute) {
		t.Fatalf("finding quarantined: %+v", fd)
	}
	panelNoteEvent(api.EventRequest{Type: "malware_realtime", Severity: "critical", OccurredAt: at(-5 * time.Minute),
		Details: map[string]string{"file_path": path, "name": "Webshell"}})
	if fd := finding(); fd.State != "open" {
		t.Fatalf("finding back: %+v", fd)
	}
}

func TestPanelSyncedResolutions(t *testing.T) {
	f := withFakePanel(t)
	t.Cleanup(func() { syncedResolutions.Store(nil) })
	at := func(d time.Duration) string { return f.now.Add(d).UTC().Format(time.RFC3339) }
	panelNoteEvent(api.EventRequest{Type: "integrity_change", Severity: "warning", OccurredAt: at(-time.Hour),
		Details: map[string]string{"file": "/etc/passwd"}})
	panelNoteEvent(api.EventRequest{Type: "db_exposed", Severity: "critical", OccurredAt: at(-time.Hour),
		Details: map[string]string{"port": "5432"}})
	panelNoteResolutions([]api.Resolution{
		{Subject: "file:/etc/passwd", ResolvedAt: f.now.Add(-30 * time.Minute).Format("2006-01-02T15:04:05.000+00:00"), How: "marked_expected", By: "user@example.com"},
		// Before the event: the problem came back after it.
		{Subject: "port:tcp/5432", ResolvedAt: at(-2 * time.Hour), How: "port_closed"},
		// Invalid: dropped.
		{Subject: "port:tcp/5432", ResolvedAt: "yesterday", How: "port_closed"},
		{Subject: "nonsense", ResolvedAt: at(0), How: "port_closed"},
		{Subject: "port:tcp/5432", ResolvedAt: at(0), How: "<b>"},
	})
	if p := syncedResolutions.Load(); len(*p) != 2 || (*p)[0].By != "" {
		t.Fatalf("kept %+v", *p)
	}
	if e := eventState(t, "integrity_change"); e.State != "resolved" || e.ResolvedHow != "marked_expected" || e.ResolvedAt != at(-30*time.Minute) {
		t.Fatalf("integrity_change: %+v", e)
	}
	if e := eventState(t, "db_exposed"); e.State != "open" {
		t.Fatalf("db_exposed: %+v", e)
	}
	// The next sync no longer lists it (reopened in the dashboard).
	panelNoteResolutions(nil)
	if e := eventState(t, "integrity_change"); e.State != "open" {
		t.Fatalf("after the reopen: %+v", e)
	}
	// Panel side off: nothing kept.
	panelOn.Store(false)
	panelNoteResolutions([]api.Resolution{{Subject: "file:/etc/passwd", ResolvedAt: at(0), How: "marked_resolved"}})
	panelOn.Store(true)
	if p := syncedResolutions.Load(); len(*p) != 0 {
		t.Fatalf("kept while off: %+v", *p)
	}
}

func TestLocalResolutionsBounded(t *testing.T) {
	f := withFakePanel(t)
	old := f.now.Add(-resolutionMaxAge - time.Hour).Unix()
	panelState.Lock()
	panelState.p.Resolved = []resolution{{Subject: "port:tcp/6379", At: old, How: "port_closed"}}
	for i := 0; i < maxResolutions; i++ {
		panelState.p.Resolved = append(panelState.p.Resolved, resolution{Subject: "package:p" + string(rune('a'+i%26)) + time.Duration(i).String(), At: f.now.Unix(), How: "package_updated"})
	}
	panelState.Unlock()
	panelNoteEvent(api.EventRequest{Type: "quarantine_completed", Severity: "info", OccurredAt: f.now.Format(time.RFC3339),
		Details: map[string]string{"file": "/home/a/x.php"}})
	panelState.Lock()
	defer panelState.Unlock()
	rs := panelState.p.Resolved
	if len(rs) != maxResolutions || rs[len(rs)-1].Subject != "malware:/home/a/x.php" {
		t.Fatalf("%d kept, last %+v", len(rs), rs[len(rs)-1])
	}
	for _, r := range rs {
		if r.Subject == "port:tcp/6379" {
			t.Fatal("a resolution older than 30 days was kept")
		}
	}
}

func TestResolutionsNotInTheFuture(t *testing.T) {
	f := withFakePanel(t)
	t.Cleanup(func() { syncedResolutions.Store(nil) })
	panelNoteResolutions([]api.Resolution{{Subject: "port:tcp/3306", ResolvedAt: f.now.Add(24 * time.Hour).Format(time.RFC3339), How: "port_closed"}})
	if p := syncedResolutions.Load(); len(*p) != 0 {
		t.Fatalf("future resolution kept: %+v", *p)
	}
	// The agent's own: a future event time counts as now.
	panelNoteEvent(api.EventRequest{Type: "quarantine_completed", Severity: "info", OccurredAt: f.now.Add(time.Hour).Format(time.RFC3339),
		Details: map[string]string{"file": "/home/a/x.php"}})
	panelState.Lock()
	at := panelState.p.Resolved[0].At
	panelState.Unlock()
	if at != f.now.Unix() {
		t.Fatalf("at %d, want %d", at, f.now.Unix())
	}
}

func TestLoadPanelStateBoundsResolutions(t *testing.T) {
	f := withFakePanel(t)
	p := panelPersisted{Resolved: []resolution{
		{Subject: "port:tcp/3306", At: f.now.Add(-time.Hour).Unix(), How: "port_closed"},
		{Subject: "port:tcp/5432", At: f.now.Add(48 * time.Hour).Unix(), How: "port_closed"},
		{Subject: "nonsense", At: f.now.Unix(), How: "port_closed"},
		{Subject: "file:/a", At: f.now.Unix(), How: "<b>"},
		{Subject: "file:/old", At: f.now.Add(-resolutionMaxAge - time.Hour).Unix(), How: "quarantined"},
	}}
	if err := writeFileAtomic(panelStatePath, p); err != nil {
		t.Fatal(err)
	}
	loadPanelState()
	panelState.Lock()
	defer panelState.Unlock()
	if rs := panelState.p.Resolved; len(rs) != 1 || rs[0].Subject != "port:tcp/3306" {
		t.Fatalf("kept %+v", rs)
	}
}

func TestPortClosedByAgentNeedsRulesInForce(t *testing.T) {
	savedInForce, savedPorts6, savedListens6 := fwInForce, fwPorts6, fwListens6
	t.Cleanup(func() { fwInForce, fwPorts6, fwListens6 = savedInForce, savedPorts6, savedListens6 })
	fwPorts6 = func() ([]int, bool) { return nil, false }
	fwListens6 = func(int) bool { return false }
	portInForceTries, portInForceWait = 1, time.Millisecond
	t.Cleanup(func() { portInForceTries, portInForceWait = 30, 2*time.Second })
	fwInForce = func() ([]int, []string) { return nil, nil } // rules not loaded
	if portClosedByAgent(3306) {
		t.Fatal("closed without rules in force")
	}
	fwInForce = func() ([]int, []string) { return []int{3306}, nil }
	if !portClosedByAgent(3306) {
		t.Fatal("not closed with the rule in force")
	}
	fwListens6 = func(int) bool { return true }
	if portClosedByAgent(3306) {
		t.Fatal("closed while still reachable over IPv6")
	}
}
