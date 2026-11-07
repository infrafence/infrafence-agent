package main

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/dbclients"
)

// withDBClients gives the guard a log with 203.0.113.7 seen on port 3306
// on 3 days (holding one connection open), 203.0.113.8 on 2 days, and
// declared hosts.
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
		holdConn(l, 3306, "203.0.113.7:40000")
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

// holdConn shows the log one connection held open for HeldSamples samples.
func holdConn(l *dbclients.Log, port int, conn string) {
	for i := 0; i < dbclients.HeldSamples; i++ {
		l.ObserveConns(map[int][]string{port: {conn}})
	}
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
	// As WHM writes them: a range, an address, a MySQL % pattern.
	declared := dbclients.ParseAccessHosts("198.51.100.0/24\n192.0.2.9\n198.18.4.%\n", "cpanel_access_hosts")
	if len(declared) != 3 {
		t.Fatalf("parsed: %+v", declared)
	}
	withDBClients(t, declared, map[string]bool{"203.0.113.7": true})
	for ip, want := range map[string]string{
		"203.0.113.7":        "regular_client",
		"::ffff:203.0.113.7": "regular_client", // IPv4-mapped
		"203.0.113.8":        "",               // seen on 2 days only
		"198.51.100.4":       "declared_mysql_host",
		"198.51.100.255":     "declared_mysql_host",
		"198.51.101.0":       "", // just outside the range
		"198.51.99.255":      "",
		"192.0.2.9":          "declared_mysql_host",
		"192.0.2.10":         "",
		"198.18.4.200":       "declared_mysql_host", // 198.18.4.%
		"198.18.5.1":         "",
		"not-an-ip":          "",
	} {
		if got := knownDBClient(ip, 3306); got != want {
			t.Errorf("%s: %q, want %q", ip, got, want)
		}
	}
	// Without a log or declared hosts nothing is known.
	dbClientLog.Store(nil)
	dbDeclared.Store(nil)
	if got := knownDBClient("203.0.113.7", 3306); got != "" {
		t.Errorf("no data: %q", got)
	}
}

// A server with no hosting panel (no access hosts file): the regular
// clients the sampler learned protect PostgreSQL, MongoDB and the other
// sampled ports on their own.
func TestKnownDBClientNoPanel(t *testing.T) {
	oldFile, oldDecl := dbclients.AccessHostsFile, dbDeclared.Load()
	dbclients.AccessHostsFile = t.TempDir() + "/mysqlaccesshosts"
	withDeclaredSources(t, nil, errors.New("no mysql client"), nil, false)
	t.Cleanup(func() {
		dbclients.AccessHostsFile = oldFile
		dbDeclared.Store(oldDecl)
	})
	readDeclared()
	if d := dbDeclared.Load(); d == nil || len(*d) != 0 {
		t.Fatalf("declared: %v", d)
	}

	l := dbclients.New("")
	now := time.Now().Add(-48 * time.Hour)
	l.Now = func() time.Time { return now }
	for d := 0; d < 3; d++ {
		l.Observe(map[int][]string{5432: {"203.0.113.50"}, 27017: {"203.0.113.51"}})
		holdConn(l, 5432, "203.0.113.50:51000")
		holdConn(l, 27017, "203.0.113.51:52000")
		now = now.Add(24 * time.Hour)
	}
	now = now.Add(-24 * time.Hour)
	oldLog := dbClientLog.Load()
	dbClientLog.Store(l)
	t.Cleanup(func() { dbClientLog.Store(oldLog) })

	for ip, want := range map[string]string{
		"203.0.113.50": "regular_client", // PostgreSQL
		"203.0.113.51": "regular_client", // MongoDB
		"203.0.113.52": "",
	} {
		if got := knownDBClient(ip, 3306); got != want {
			t.Errorf("%s: %q, want %q", ip, got, want)
		}
	}
}

// A host that only opens connections (a new source port every sample, as a
// scanner or a brute force that never logs in) becomes a regular client
// for closing ports, never a known client for the database watcher.
func TestKnownDBClientNeedsHeldConnection(t *testing.T) {
	withDBClients(t, nil, map[string]bool{})
	l := dbclients.New("")
	now := time.Now().Add(-48 * time.Hour)
	l.Now = func() time.Time { return now }
	for d := 0; d < 3; d++ {
		for i := 0; i < 10; i++ {
			l.Observe(map[int][]string{3306: {"203.0.113.90"}})
			l.ObserveConns(map[int][]string{3306: {fmt.Sprintf("203.0.113.90:%d", 40000+d*100+i)}})
		}
		now = now.Add(24 * time.Hour)
	}
	now = now.Add(-24 * time.Hour)
	dbClientLog.Store(l)
	if got := regularClientsNotAllowed(3306); !reflect.DeepEqual(got, []string{"203.0.113.90"}) {
		t.Fatalf("regular for closing: %v", got)
	}
	if got := knownDBClient("203.0.113.90", 3306); got != "" {
		t.Errorf("known without a held connection: %q", got)
	}
}

// withDeclaredSources replaces the MySQL accounts and pg_hba.conf readers.
func withDeclaredSources(t *testing.T, grants []dbclients.Declared, grantsErr error, hba []dbclients.Declared, hbaOK bool) {
	t.Helper()
	oldG, oldH := dbReadGrants, dbReadHBA
	dbReadGrants = func() ([]dbclients.Declared, []string, error) { return grants, nil, grantsErr }
	dbReadHBA = func() ([]dbclients.Declared, bool) { return hba, hbaOK }
	t.Cleanup(func() { dbReadGrants, dbReadHBA = oldG, oldH })
}

// The database itself declares its clients on any server: the hosts of
// MySQL's accounts for 3306, pg_hba.conf for 5432. A client that connects
// for a moment (no held connection, never seen) is protected from the
// first minute, for its own database only; a range wider than a /16 is
// not.
func TestKnownDBClientDeclaredByDatabase(t *testing.T) {
	withDBClients(t, nil, map[string]bool{})
	grants, _ := dbclients.ParseGrantHosts("%\nlocalhost\n203.0.113.20\n198.%.%.%\n")
	hba := dbclients.ParsePGHBA("host all all 198.51.100.30/32 scram-sha-256\n")
	oldCPanel := dbReadCPanel
	dbReadCPanel = func() ([]dbclients.Declared, bool) { return nil, false }
	t.Cleanup(func() { dbReadCPanel = oldCPanel })
	withDeclaredSources(t, grants, nil, hba, true)
	readDeclared()

	for _, c := range []struct {
		ip   string
		port int
		want string
	}{
		{"203.0.113.20", 3306, "mysql_grant"},
		{"203.0.113.20", 5432, ""},
		{"198.51.100.30", 5432, "pg_hba"},
		{"198.51.100.30", 3306, ""},
		{"198.51.100.30", 0, "pg_hba"}, // a log of unknown type
		{"198.18.7.7", 3306, ""},       // 198.%.%.%: wider than a /16
		{"203.0.113.21", 3306, ""},
	} {
		if got := knownDBClient(c.ip, c.port); got != c.want {
			t.Errorf("%s on %d: %q, want %q", c.ip, c.port, got, c.want)
		}
	}
	// Closing 5432 waits for the pg_hba client too.
	if got := regularClientsNotAllowed(5432); !reflect.DeepEqual(got, []string{"198.51.100.30"}) {
		t.Errorf("5432: %v", got)
	}

	// Reported with their port and source.
	var sent api.DBClientsRequest
	oldSend := dbSend
	dbSend = func(_ *api.Client, req api.DBClientsRequest) error { sent = req; return nil }
	t.Cleanup(func() { dbSend = oldSend })
	if err := reportDBClients(nil, dbClientLog.Load()); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, d := range sent.Declared {
		got[d.Entry] = fmt.Sprintf("%d %s", d.Port, d.Source)
	}
	want := map[string]string{"203.0.113.20": "3306 mysql_grants", "198.0.0.0/8": "3306 mysql_grants", "198.51.100.30": "5432 pg_hba"}
	if !reflect.DeepEqual(got, want) || !sent.DeclaredRead {
		t.Errorf("reported: %v", got)
	}
}

// A source that cannot be read leaves the others: the WHM hosts stay when
// MySQL refuses the agent and there is no pg_hba.conf.
func TestReadDeclaredFailures(t *testing.T) {
	oldDecl, oldCPanel := dbDeclared.Load(), dbReadCPanel
	t.Cleanup(func() { dbDeclared.Store(oldDecl); dbReadCPanel = oldCPanel })
	dbReadCPanel = func() ([]dbclients.Declared, bool) {
		return []dbclients.Declared{{Entry: "192.0.2.9", Host: "192.0.2.9", Source: "cpanel_access_hosts"}}, true
	}
	withDeclaredSources(t, nil, errors.New("exit status 1"), nil, false)
	readDeclared()
	if d := dbDeclared.Load(); d == nil || len(*d) != 1 || (*d)[0].Entry != "192.0.2.9" {
		t.Fatalf("declared: %v", d)
	}
	if got := knownDBClient("192.0.2.9", 3306); got != "declared_mysql_host" {
		t.Errorf("cPanel host: %q", got)
	}
}
