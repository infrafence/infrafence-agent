package main

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/dbclients"
)

// withDBClients gives the guard a log with 203.0.113.7 seen on port 3306
// on 3 days, 203.0.113.8 on 2 days, and declared hosts.
func withDBClients(t *testing.T, declared []dbclients.Declared, allow map[string]bool) {
	t.Helper()
	l := dbclients.New("")
	now := time.Now().Add(-48 * time.Hour)
	l.Now = func() time.Time { return now }
	for d := 0; d < 3; d++ {
		seen := map[int][]string{3306: {"203.0.113.7"}}
		if d > 0 {
			seen[3306] = append(seen[3306], "203.0.113.8")
		}
		l.Observe(seen)
		now = now.Add(24 * time.Hour)
	}
	now = now.Add(-24 * time.Hour)
	oldLog, oldDecl := dbClientLog.Load(), dbDeclared.Load()
	oldAllow, oldNet := dbAllowListed, dbAllowNet
	dbClientLog.Store(l)
	dbDeclared.Store(&declared)
	dbAllowListed = func(ip string) bool { return allow[ip] }
	dbAllowNet = func(n string) bool { return allow[n] }
	t.Cleanup(func() {
		dbClientLog.Store(oldLog)
		dbDeclared.Store(oldDecl)
		dbAllowListed, dbAllowNet = oldAllow, oldNet
	})
}

func TestCloseRefusedForRegularClients(t *testing.T) {
	f := withFakeFirewall(t)
	allow := map[string]bool{}
	withDBClients(t, []dbclients.Declared{{Entry: "198.51.100.0/24", Host: "198.51.100.%", Source: "cpanel_access_hosts"}}, allow)

	closeA := api.FirewallAction{ID: 30, Kind: "close_port", Port: 3306, Proto: "tcp"}
	applyFirewallState(&api.FirewallState{}, []api.FirewallAction{closeA}, false)
	typ, _, d := runFirewallAction(closeA)
	if typ != "firewall_action_failed" || d["reason"] != "regular_clients" {
		t.Fatalf("got %s %v", typ, d)
	}
	if d["clients"] != "198.51.100.0/24,203.0.113.7" || !strings.Contains(d["message"], "2 regular client(s) of port 3306") {
		t.Fatalf("details: %v", d)
	}
	if len(f.ports) != 0 {
		t.Fatalf("closed: %v", f.ports)
	}

	// The regular client whitelisted, the declared range not yet.
	allow["203.0.113.7"] = true
	closeA.ID = 31
	applyFirewallState(&api.FirewallState{}, []api.FirewallAction{closeA}, false)
	if _, _, d := runFirewallAction(closeA); d["reason"] != "regular_clients" || d["clients"] != "198.51.100.0/24" {
		t.Fatalf("declared range: %v", d)
	}
	// Both whitelisted: the port closes.
	allow["198.51.100.0/24"] = true
	closeA.ID = 32
	applyFirewallState(&api.FirewallState{}, []api.FirewallAction{closeA}, false)
	if typ, _, d := runFirewallAction(closeA); typ != "firewall_action_done" {
		t.Fatalf("whitelisted: %s %v", typ, d)
	}
	if !reflect.DeepEqual(f.ports, []int{3306}) {
		t.Fatalf("in force: %v", f.ports)
	}

	// Once closed, a client no longer whitelisted does not reopen it.
	delete(allow, "203.0.113.7")
	applyFirewallState(&api.FirewallState{ClosedPorts: []api.PortProto{{Port: 3306, Proto: "tcp"}}}, nil, false)
	if !reflect.DeepEqual(f.ports, []int{3306}) {
		t.Fatalf("reopened: %v", f.ports)
	}
}

// A state entry not enforced yet (no request: an older flow, a lost state
// file) is held to the same check.
func TestStateCloseRefusedForRegularClients(t *testing.T) {
	f := withFakeFirewall(t)
	withDBClients(t, nil, map[string]bool{})
	applyFirewallState(&api.FirewallState{ClosedPorts: []api.PortProto{{Port: 3306, Proto: "tcp"}, {Port: 6379, Proto: "tcp"}}}, nil, false)
	if !reflect.DeepEqual(f.ports, []int{6379}) {
		t.Fatalf("in force: %v", f.ports)
	}
	ev := f.refusalsSoon(1)
	if len(ev) != 1 || ev[0].Details["reason"] != "regular_clients" || ev[0].Details["port"] != "3306" {
		t.Fatalf("refusal: %+v", ev)
	}
}

// Declared hosts count for MySQL only; nothing is learned: no refusal.
func TestRegularClientsOtherPorts(t *testing.T) {
	withDBClients(t, []dbclients.Declared{{Entry: "198.51.100.4"}}, map[string]bool{})
	if got := regularClientsNotAllowed(5432); got != nil {
		t.Fatalf("5432: %v", got)
	}
	dbClientLog.Store(nil)
	if got := regularClientsNotAllowed(3306); !reflect.DeepEqual(got, []string{"198.51.100.4"}) {
		t.Fatalf("no log: %v", got)
	}
}

func TestReportDBClients(t *testing.T) {
	withDBClients(t, []dbclients.Declared{{Entry: "198.51.100.0/24", Host: "198.51.100.%", Source: "cpanel_access_hosts"}}, nil)
	old := dbSend
	t.Cleanup(func() { dbSend = old })
	var got []api.DBClientsRequest
	fail := true
	dbSend = func(_ *api.Client, req api.DBClientsRequest) error {
		got = append(got, req)
		if fail {
			return errors.New("404")
		}
		return nil
	}
	l := dbClientLog.Load()
	if err := reportDBClients(nil, l); err == nil {
		t.Fatal("error not returned")
	}
	fail = false
	if err := reportDBClients(nil, l); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || len(got[1].Clients) != 5 || !got[1].DeclaredRead || got[1].Declared[0].Port != 3306 {
		t.Fatalf("got %+v", got)
	}
	// Sent: only the declared list goes again.
	if err := reportDBClients(nil, l); err != nil || len(got[2].Clients) != 0 {
		t.Fatalf("again: %v %+v", err, got[2])
	}
}

func TestRegularClientsMessage(t *testing.T) {
	var ips []string
	for i := 0; i < 12; i++ {
		ips = append(ips, "203.0.113."+string(rune('a'+i)))
	}
	m := regularClientsMessage(3306, ips)
	if !strings.Contains(m, "12 regular client(s) of port 3306") || !strings.HasSuffix(m, "and 2 more") {
		t.Fatalf("got %q", m)
	}
}

// The database watcher's guard: regular clients of a database port and
// declared hosts (addresses and ranges), whitelisted or not.
func TestKnownDBClient(t *testing.T) {
	withDBClients(t, []dbclients.Declared{
		{Entry: "198.51.100.0/24", Host: "198.51.100.%", Source: "cpanel_access_hosts"},
		{Entry: "192.0.2.9", Host: "192.0.2.9", Source: "cpanel_access_hosts"},
	}, map[string]bool{"203.0.113.7": true})
	for ip, want := range map[string]string{
		"203.0.113.7":  "regular_client",
		"203.0.113.8":  "", // seen on 2 days only
		"198.51.100.4": "declared_mysql_host",
		"192.0.2.9":    "declared_mysql_host",
		"192.0.2.10":   "",
		"not-an-ip":    "",
	} {
		if got := knownDBClient(ip); got != want {
			t.Errorf("%s: %q, want %q", ip, got, want)
		}
	}
	// Without a log or declared hosts nothing is known.
	dbClientLog.Store(nil)
	dbDeclared.Store(nil)
	if got := knownDBClient("203.0.113.7"); got != "" {
		t.Errorf("no data: %q", got)
	}
}
