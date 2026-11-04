package main

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/dbclients"
	"github.com/infrafence/infrafence-agent/internal/loginhistory"
	"github.com/infrafence/infrafence-agent/internal/panel"
)

func withPanelLogins(t *testing.T) *loginhistory.Store {
	t.Helper()
	old, oldCountry := sshLoginStore, panelCountry
	sshLoginStore = loginhistory.NewStore("")
	panelCountry = func(ip string) string {
		if ip == "198.51.100.7" {
			return "it"
		}
		return ""
	}
	t.Cleanup(func() { sshLoginStore, panelCountry = old, oldCountry })
	return sshLoginStore
}

func TestPanelSSHLogins(t *testing.T) {
	withFakePanel(t)
	s := withPanelLogins(t)
	now := time.Now().UTC().Truncate(time.Second)
	scanned := now.Add(-time.Hour)
	s.Apply(loginhistory.Result{Logins: []loginhistory.Login{
		{IP: "198.51.100.7", User: "root", Time: now.Add(-10 * 24 * time.Hour), Source: "auth_log"},
		{IP: "198.51.100.7", User: "deploy", Time: now.Add(-2 * 24 * time.Hour), Source: "auth_log"},
		{IP: "2001:db8::5", User: "root", Time: now.Add(-5 * 24 * time.Hour), Source: "wtmp"},
		{IP: "203.0.113.9", User: "old", Time: now.Add(-40 * 24 * time.Hour), Source: "auth_log"},
	}}, scanned)
	s.Note("203.0.113.20", "alice\x1b[31m", now.Add(-time.Minute))
	panelIsAllowListed = func(ip string) bool { return ip == "2001:db8::5" }

	r := handlePanel(panel.Request{Command: "ssh-logins", Limit: 50})
	if !r.Succeeded() || r["total"] != 3 || r["days"] != 30 || r["scanned_at"] != scanned.Format(time.RFC3339) {
		t.Fatalf("answer: %v", r)
	}
	got := r["logins"].([]panelLoginOut)
	want := []panelLoginOut{
		{IP: "203.0.113.20", Users: []string{"alice[31m"}, Country: nil, FirstAt: now.Add(-time.Minute).Format(time.RFC3339),
			LastAt: now.Add(-time.Minute).Format(time.RFC3339), Logins: 1, Live: true, Protected: true},
		{IP: "198.51.100.7", Users: []string{"root", "deploy"}, Country: "IT", FirstAt: now.Add(-10 * 24 * time.Hour).Format(time.RFC3339),
			LastAt: now.Add(-2 * 24 * time.Hour).Format(time.RFC3339), Logins: 2, Imported: true, Protected: true},
		{IP: "2001:db8::5", Users: []string{"root"}, Country: nil, FirstAt: now.Add(-5 * 24 * time.Hour).Format(time.RFC3339),
			LastAt: now.Add(-5 * 24 * time.Hour).Format(time.RFC3339), Logins: 1, Imported: true, Allowed: true, Protected: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("logins:\n got %+v\nwant %+v", got, want)
	}
	if r := handlePanel(panel.Request{Command: "ssh-logins", Limit: 1}); len(r["logins"].([]panelLoginOut)) != 1 || r["total"] != 3 {
		t.Errorf("limit: %v", r)
	}

	// Nothing known yet: an empty list, never null.
	withPanelLogins(t)
	r = handlePanel(panel.Request{Command: "ssh-logins", Limit: 50})
	if l := r["logins"].([]panelLoginOut); l == nil || len(l) != 0 || r["scanned_at"] != nil {
		t.Errorf("empty: %v", r)
	}
}

func TestPanelSSHLoginsServiceUsers(t *testing.T) {
	withFakePanel(t)
	s := withPanelLogins(t)
	now := time.Now().UTC().Truncate(time.Second)
	// deploy from 11 networks (a CI runner): a service user.
	for i := 1; i <= 11; i++ {
		s.Note(fmt.Sprintf("198.51.%d.10", i), "deploy", now.Add(-time.Duration(i)*time.Hour))
	}
	// root also logged in from one of them: that address stays protected.
	s.Note("198.51.3.10", "root", now.Add(-30*time.Minute))
	// backup is listed in the dashboard's settings.
	s.Note("203.0.113.30", "backup", now.Add(-20*time.Hour))
	s.SetServiceUsers([]string{"backup"})
	// Both kinds on one address.
	s.Note("203.0.113.31", "backup", now.Add(-21*time.Hour))
	s.Note("203.0.113.31", "deploy", now.Add(-21*time.Hour))

	by := map[string]panelLoginOut{}
	for _, l := range handlePanel(panel.Request{Command: "ssh-logins", Limit: 500})["logins"].([]panelLoginOut) {
		by[l.IP] = l
	}
	if l := by["198.51.3.10"]; !l.Protected || l.NotProtected != nil {
		t.Errorf("a person's address: %+v", l)
	}
	l := by["198.51.5.10"]
	if l.Protected || l.NotProtected == nil || l.NotProtected.Reason != "service_user" ||
		!reflect.DeepEqual(l.NotProtected.Users, []panelServiceUserOut{{User: "deploy", Networks: 12}}) {
		t.Errorf("service user: %+v %+v", l, l.NotProtected)
	}
	l = by["203.0.113.30"]
	if l.Protected || l.NotProtected == nil || l.NotProtected.Reason != "listed" ||
		!reflect.DeepEqual(l.NotProtected.Users, []panelServiceUserOut{{User: "backup", Networks: 1, Listed: true}}) {
		t.Errorf("listed: %+v %+v", l, l.NotProtected)
	}
	if l := by["203.0.113.31"]; l.Protected || l.NotProtected == nil || l.NotProtected.Reason != "service_user" || len(l.NotProtected.Users) != 2 {
		t.Errorf("listed and counted: %+v %+v", l, l.NotProtected)
	}
	// The answer is the guard's: the same addresses are unprotected.
	for ip, l := range by {
		if _, ok, _ := s.Protected(ip); ok != l.Protected {
			t.Errorf("%s: panel %v, guard %v", ip, l.Protected, ok)
		}
	}
}

func TestPanelDBClients(t *testing.T) {
	withFakePanel(t)
	allow := map[string]bool{"203.0.113.7": true}
	withDBClients(t, []dbclients.Declared{{Entry: "198.51.100.0/24", Host: "198.51.100.%", Source: "cpanel_access_hosts"}}, allow)

	r := handlePanel(panel.Request{Command: "db-clients"})
	if !r.Succeeded() || r["total"] != 2 || r["min_days"] != dbclients.MinDays || r["window_days"] != dbclients.WindowDays {
		t.Fatalf("answer: %v", r)
	}
	got := r["clients"].([]panelDBClientOut)
	if len(got) != 2 {
		t.Fatalf("clients: %+v", got)
	}
	// 203.0.113.8 was seen on 2 days only: not a regular client.
	o, d := got[0], got[1]
	if o.Port != 3306 || o.IP != "203.0.113.7" || o.Source != "observed" || o.Host != nil || o.Days != 3 || !o.Allowed ||
		o.FirstSeen == nil || o.LastSeen == nil {
		t.Errorf("observed: %+v", o)
	}
	if d.Port != 3306 || d.IP != "198.51.100.0/24" || d.Source != "cpanel_access_hosts" || d.Host != "198.51.100.%" ||
		d.Days != nil || d.FirstSeen != nil || d.LastSeen != nil || d.Allowed {
		t.Errorf("declared: %+v", d)
	}

	// No log yet (the sampler has not started): an empty list.
	dbClientLog.Store(nil)
	dbDeclared.Store(nil)
	if c := handlePanel(panel.Request{Command: "db-clients"})["clients"].([]panelDBClientOut); c == nil || len(c) != 0 {
		t.Errorf("empty: %+v", c)
	}
}

func TestPanelEventDetails(t *testing.T) {
	f := withFakePanel(t)
	at := f.now.Add(-time.Minute).Format(time.RFC3339)
	panelNoteEvent(api.EventRequest{Type: "mail_brute_force", Severity: "warning", SourceIP: "203.0.113.7", OccurredAt: at,
		Details: map[string]string{"target_user": " info@example.com\x07", "protocol": "imap", "auth_method": "plain",
			"attempts": "5", "mta": "dovecot", "line": "the raw log line is not passed on"}})
	panelNoteEvent(api.EventRequest{Type: "modsecurity_block", Severity: "warning", SourceIP: "203.0.113.8", OccurredAt: at,
		Details: map[string]string{"cve": "CVE-2021-44228", "cves": "CVE-2021-44228,CVE-2021-45046", "attack_type": "rce", "waf_ruleset": "comodo"}})
	panelNoteEvent(api.EventRequest{Type: "db_exposed", Severity: "critical", OccurredAt: at,
		Details: map[string]string{"service": "MySQL/MariaDB", "bind_address": "[::]:3306", "warning": "x"}})
	panelNoteEvent(api.EventRequest{Type: "port_scan", Severity: "info", SourceIP: "203.0.113.9", OccurredAt: at})

	ev := handlePanel(panel.Request{Command: "events", Limit: 50})["events"].([]panelEventOut)
	if len(ev) != 4 {
		t.Fatalf("events: %+v", ev)
	}
	want := []map[string]string{
		{},
		{"service": "MySQL/MariaDB", "bind_address": "[::]:3306"},
		{"cve": "CVE-2021-44228", "cves": "CVE-2021-44228,CVE-2021-45046", "attack_type": "rce", "waf_ruleset": "comodo"},
		{"target_user": "info@example.com?", "protocol": "imap", "auth_method": "plain", "attempts": "5", "mta": "dovecot"},
	}
	for i, w := range want {
		if !reflect.DeepEqual(ev[i].Details, w) {
			t.Errorf("%s details: %v, want %v", ev[i].Type, ev[i].Details, w)
		}
	}
	// The answer is a copy: changing it changes nothing kept.
	ev[1].Details["bind_address"] = "changed"
	if again := handlePanel(panel.Request{Command: "events", Limit: 50})["events"].([]panelEventOut); again[1].Details["bind_address"] != "[::]:3306" {
		t.Errorf("kept details changed: %v", again[1].Details)
	}
	// Long values are cut.
	long := make([]byte, 400)
	for i := range long {
		long[i] = 'a'
	}
	panelNoteEvent(api.EventRequest{Type: "mail_relay_scan", Severity: "warning", OccurredAt: at, Details: map[string]string{"recipient": string(long)}})
	if d := handlePanel(panel.Request{Command: "events", Limit: 1})["events"].([]panelEventOut)[0].Details; len(d["recipient"]) != 254 {
		t.Errorf("recipient not cut: %d", len(d["recipient"]))
	}
}
