package main

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/netstate"
	"github.com/infrafence/infrafence-agent/internal/verify"
)

// fakeFirewall replaces the host: what is "in force" is whatever the last
// apply received, and verification answers verifyOK.
type fakeFirewall struct {
	ports    []int
	egress   []string
	applies  int
	verifyOK bool
	inbound  map[int][]string
	sockets  []netstate.Conn
	sessions []string // logged-in SSH clients
	noSSHD   bool     // no OpenSSH process visible
	flagged  map[string]bool
	logins   map[string]bool
	ports6   bool // ip6tables mirrors the closed ports
	listens6 map[int]bool
	mu       sync.Mutex // refusals and dropped are written in the background
	refusals []api.EventRequest
	dropped  []int
}

func withFakeFirewall(t *testing.T) *fakeFirewall {
	t.Helper()
	f := &fakeFirewall{verifyOK: true, inbound: map[int][]string{}, ports6: true, listens6: map[int]bool{},
		flagged: map[string]bool{"185.1.2.3": true}, logins: map[string]bool{}}
	saved := []any{fwSSHPorts, fwWebPorts, fwPublicInbound, fwSockets, fwEgressRefusal, fwResolvers, fwApply, fwSnapshot, fwCheck, fwInForce, fwReport,
		fwFlagged, fwSSHLoginSeen, fwDashboardIPs, fwPorts6, fwListens6, fwDropConntrack, fwReportRefusal, fwStatePath, fwSSHSessions}
	fwStatePath = filepath.Join(t.TempDir(), "firewall-state.json")
	fwFlagged = func(ip string) bool { return f.flagged[ip] }
	fwSSHLoginSeen = func(ip string) bool { return f.logins[ip] }
	fwDashboardIPs = func() map[string]bool { return map[string]bool{"203.0.113.80": true} }
	fwPorts6 = func() ([]int, bool) {
		if !f.ports6 {
			return nil, false
		}
		return f.ports, true
	}
	fwListens6 = func(p int) bool { return f.listens6[p] }
	fwDropConntrack = func(p []int) { f.mu.Lock(); f.dropped = append(f.dropped, p...); f.mu.Unlock() }
	fwReportRefusal = func(ev api.EventRequest) { f.mu.Lock(); f.refusals = append(f.refusals, ev); f.mu.Unlock() }
	fwSSHPorts = func() []int { return []int{22, 2222} }
	fwWebPorts = func() []int { return []int{80, 443, 8080} }
	fwPublicInbound = func(p int) []string { return f.inbound[p] }
	fwSockets = func() []netstate.Conn { return f.sockets }
	fwSSHSessions = func() ([]string, bool) { return f.sessions, !f.noSSHD }
	fwEgressRefusal = func(ip string) string {
		if p := net.ParseIP(ip); p != nil && p.IsPrivate() {
			return "private_target"
		}
		return ""
	}
	fwResolvers = func() map[string]bool { return map[string]bool{"1.1.1.1": true} }
	fwApply = func(ports []int, egress []string) ([]string, error) {
		f.ports, f.egress = append([]int(nil), ports...), append([]string(nil), egress...)
		f.applies++
		return nil, nil
	}
	fwSnapshot = func() verify.State { return verify.State{} }
	fwCheck = func(verify.State) verify.Result {
		if f.verifyOK {
			return verify.Result{SSHOK: true, SitesOK: true, Details: "ok"}
		}
		return verify.Result{SSHOK: false, SitesOK: true, Details: "ssh port 22 not accepting"}
	}
	fwInForce = func() ([]int, []string) { return f.ports, f.egress }
	t.Cleanup(func() {
		fwSSHPorts = saved[0].(func() []int)
		fwWebPorts = saved[1].(func() []int)
		fwPublicInbound = saved[2].(func(int) []string)
		fwSockets = saved[3].(func() []netstate.Conn)
		fwEgressRefusal = saved[4].(func(string) string)
		fwResolvers = saved[5].(func() map[string]bool)
		fwApply = saved[6].(func([]int, []string) ([]string, error))
		fwSnapshot = saved[7].(func() verify.State)
		fwCheck = saved[8].(func(verify.State) verify.Result)
		fwInForce = saved[9].(func() ([]int, []string))
		fwReport = saved[10].(func(*api.Client, api.EventRequest) error)
		fwFlagged = saved[11].(func(string) bool)
		fwSSHLoginSeen = saved[12].(func(string) bool)
		fwDashboardIPs = saved[13].(func() map[string]bool)
		fwPorts6 = saved[14].(func() ([]int, bool))
		fwListens6 = saved[15].(func(int) bool)
		fwDropConntrack = saved[16].(func([]int))
		fwReportRefusal = saved[17].(func(api.EventRequest))
		fwStatePath = saved[18].(string)
		fwSSHSessions = saved[19].(func() ([]string, bool))
		resetFirewallMemory()
	})
	return f
}

func resetFirewallMemory() {
	fwStateMu.Lock()
	fwBase, fwPending, fwMonitor = nil, nil, false
	fwOverlay = map[int64]api.FirewallAction{}
	fwDone = map[int64]bool{}
	fwUnsent = map[int64]api.EventRequest{}
	fwRefusedSent = map[string]string{}
	fwStateMu.Unlock()
	appliedMu.Lock()
	fwAppliedPorts, fwAppliedEgress = map[int]bool{}, map[string]bool{}
	appliedMu.Unlock()
	memoMu.Lock()
	flagged, sshLogins = map[string]int64{}, map[string]int64{}
	memoMu.Unlock()
}

// refusalsSoon waits for the refusal events sent in the background.
func (f *fakeFirewall) refusalsSoon(n int) []api.EventRequest {
	for i := 0; i < 100; i++ {
		f.mu.Lock()
		got := len(f.refusals)
		f.mu.Unlock()
		if got >= n {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]api.EventRequest(nil), f.refusals...)
}

func TestCloseAndOpenPort(t *testing.T) {
	f := withFakeFirewall(t)
	closeA := api.FirewallAction{ID: 12, Kind: "close_port", Port: 6379, Proto: "tcp"}
	applyFirewallState(&api.FirewallState{}, []api.FirewallAction{closeA}, false)

	typ, _, d := runFirewallAction(closeA)
	if typ != "firewall_action_done" || d["status"] != "done" || d["port"] != "6379" || d["action_id"] != "12" {
		t.Fatalf("close: %s %v", typ, d)
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(d["verify"]), &v); err != nil || v["ssh_ok"] != true {
		t.Fatalf("verify detail: %q", d["verify"])
	}
	if !reflect.DeepEqual(f.ports, []int{6379}) {
		t.Fatalf("in force: %v", f.ports)
	}

	// A sync that still lists the request pending, with a state that does
	// not have the port yet, keeps it closed.
	applyFirewallState(&api.FirewallState{}, []api.FirewallAction{closeA}, false)
	if !reflect.DeepEqual(f.ports, []int{6379}) {
		t.Fatalf("pending request undone by a crossing sync: %v", f.ports)
	}
	// Recorded: the state has it, the request is gone.
	state := &api.FirewallState{ClosedPorts: []api.PortProto{{Port: 6379, Proto: "tcp"}}}
	applyFirewallState(state, nil, false)
	if !reflect.DeepEqual(f.ports, []int{6379}) {
		t.Fatalf("after record: %v", f.ports)
	}

	openA := api.FirewallAction{ID: 13, Kind: "open_port", Port: 6379, Proto: "tcp"}
	applyFirewallState(state, []api.FirewallAction{openA}, false)
	if typ, _, d := runFirewallAction(openA); typ != "firewall_action_done" {
		t.Fatalf("open: %s %v", typ, d)
	}
	if len(f.ports) != 0 {
		t.Fatalf("still closed: %v", f.ports)
	}
}

// A close the dashboard already put in the state is not enforced before
// its request has passed the checks.
func TestPendingCloseWaitsForItsRequest(t *testing.T) {
	f := withFakeFirewall(t)
	closeA := api.FirewallAction{ID: 20, Kind: "close_port", Port: 3306, Proto: "tcp"}
	f.inbound[3306] = []string{"198.51.100.7"}
	state := &api.FirewallState{ClosedPorts: []api.PortProto{{Port: 3306, Proto: "tcp"}}}
	applyFirewallState(state, []api.FirewallAction{closeA}, false)
	if len(f.ports) != 0 {
		t.Fatalf("closed before its request ran: %v", f.ports)
	}
	typ, _, d := runFirewallAction(closeA)
	if typ != "firewall_action_failed" || d["reason"] != "established_connection" {
		t.Fatalf("got %s %v", typ, d)
	}
	applyFirewallState(state, []api.FirewallAction{closeA}, false)
	if len(f.ports) != 0 {
		t.Fatalf("refused close enforced: %v", f.ports)
	}
}

func TestPortRefusals(t *testing.T) {
	f := withFakeFirewall(t)
	for _, c := range []struct {
		a      api.FirewallAction
		reason string
	}{
		{api.FirewallAction{ID: 1, Kind: "close_port", Port: 22}, "ssh_port"},
		{api.FirewallAction{ID: 2, Kind: "close_port", Port: 2222, Proto: "tcp"}, "ssh_port"},
		{api.FirewallAction{ID: 3, Kind: "close_port", Port: 443, Proto: "tcp"}, "web_port"},
		{api.FirewallAction{ID: 4, Kind: "close_port", Port: 0, Proto: "tcp"}, "invalid"},
		{api.FirewallAction{ID: 5, Kind: "close_port", Port: 53, Proto: "udp"}, "unsupported_proto"},
		{api.FirewallAction{ID: 6, Kind: "reboot"}, "unsupported_kind"},
	} {
		typ, _, d := runFirewallAction(c.a)
		if typ != "firewall_action_failed" || d["reason"] != c.reason {
			t.Errorf("%+v: %s %v, want reason %s", c.a, typ, d, c.reason)
		}
	}
	if f.applies != 0 {
		t.Fatalf("a refused request changed the firewall (%d applies)", f.applies)
	}

	// SSH, web and other ports in the dashboard's state are never enforced
	// either, and each refusal is reported once.
	state := &api.FirewallState{ClosedPorts: []api.PortProto{{Port: 22}, {Port: 443}, {Port: 25}, {Port: 9200}}}
	applyFirewallState(state, nil, false)
	if !reflect.DeepEqual(f.ports, []int{9200}) {
		t.Fatalf("state enforced %v", f.ports)
	}
	got := map[string]string{}
	for _, ev := range f.refusalsSoon(3) {
		if ev.Type != "firewall_action_failed" || ev.Details["source"] != "firewall_state" || ev.Details["action_id"] != "" {
			t.Fatalf("refusal event %+v", ev)
		}
		got[ev.Details["port"]] = ev.Details["reason"]
	}
	if want := map[string]string{"22": "ssh_port", "443": "web_port", "25": "not_closable"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("refusals %v, want %v", got, want)
	}
	applyFirewallState(state, nil, false)
	time.Sleep(50 * time.Millisecond)
	if n := len(f.refusalsSoon(0)); n != 3 {
		t.Fatalf("refusals reported again: %d", n)
	}
}

func TestOnlyAllowListedPortsClose(t *testing.T) {
	withFakeFirewall(t)
	for _, port := range []int{8000, 25, 21, 3389, 5000} {
		typ, _, d := runFirewallAction(api.FirewallAction{ID: int64(port), Kind: "close_port", Port: port, Proto: "tcp"})
		if typ != "firewall_action_failed" || d["reason"] != "not_closable" {
			t.Errorf("port %d: %s %v", port, typ, d)
		}
	}
	for _, port := range []int{3306, 5432, 6379, 6380, 27017, 27018, 9200, 9300, 11211, 2375, 2376, 5984, 8086, 15672, 5601, 9042, 7000, 7001, 8529, 28015} {
		if !closablePorts[port] {
			t.Errorf("port %d missing from the list", port)
		}
	}
	if len(closablePorts) != 20 {
		t.Fatalf("%d closable ports, want 20", len(closablePorts))
	}
}

func TestEgress(t *testing.T) {
	f := withFakeFirewall(t)
	// 198.51.100.50 is logged in over SSH (port 2222); 198.51.100.51 is only
	// connected to it, still authenticating.
	f.sockets = []netstate.Conn{
		{LocalPort: 2222, State: 0x0A},
		{LocalPort: 2222, RemoteIP: net.ParseIP("198.51.100.50").To4(), State: 0x01},
		{LocalPort: 2222, RemoteIP: net.ParseIP("198.51.100.51").To4(), State: 0x01},
	}
	f.sessions = []string{"198.51.100.50"}
	f.sockets = append(f.sockets,
		netstate.Conn{LocalPort: 6379, State: 0x0A},
		netstate.Conn{LocalPort: 6379, RemoteIP: net.ParseIP("198.51.100.60").To4(), State: 0x01})
	f.logins["198.51.100.70"] = true
	f.logins["198.51.100.50"] = true // logged in now: the more precise reason wins
	for _, ip := range []string{"198.51.100.50", "198.51.100.51", "198.51.100.60", "198.51.100.70", "203.0.113.80", "1.1.1.1"} {
		f.flagged[ip] = true
	}
	for ip, reason := range map[string]string{
		"10.0.0.8":      "private_target",
		"1.1.1.1":       "dns_resolver",
		"198.51.100.50": "ssh_client",
		"198.51.100.60": "established_connection",
		"198.51.100.70": "ssh_login",
		"203.0.113.80":  "dashboard_api",
		"203.0.113.99":  "not_flagged",
		"2001:db8::1":   "ipv6_unsupported",
		"x":             "invalid",
	} {
		typ, _, d := runFirewallAction(api.FirewallAction{ID: 30, Kind: "block_egress", IP: ip})
		if typ != "firewall_action_failed" || d["reason"] != reason {
			t.Errorf("%s: %s %v, want %s", ip, typ, d, reason)
		}
	}
	// A connection to SSH that has not logged in protects nobody.
	pre := api.FirewallAction{ID: 33, Kind: "block_egress", IP: "198.51.100.51"}
	applyFirewallState(nil, []api.FirewallAction{pre}, false)
	if typ, _, d := runFirewallAction(pre); typ != "firewall_action_done" {
		t.Fatalf("pre-auth connection shielded its address: %s %v", typ, d)
	}
	resetFirewallMemory()
	f.egress = nil
	for _, ip := range []string{"185.1.2.3"} {
		f.flagged[ip] = true
	}
	block := api.FirewallAction{ID: 31, Kind: "block_egress", IP: "185.1.2.3"}
	applyFirewallState(nil, []api.FirewallAction{block}, false)
	if typ, _, d := runFirewallAction(block); typ != "firewall_action_done" || d["ip"] != "185.1.2.3" {
		t.Fatalf("block: %s %v", typ, d)
	}
	if !reflect.DeepEqual(f.egress, []string{"185.1.2.3"}) {
		t.Fatalf("egress in force: %v", f.egress)
	}
	unblock := api.FirewallAction{ID: 32, Kind: "unblock_egress", IP: "185.1.2.3"}
	applyFirewallState(&api.FirewallState{EgressBlocked: []string{"185.1.2.3"}}, []api.FirewallAction{unblock}, false)
	if typ, _, _ := runFirewallAction(unblock); typ != "firewall_action_done" || len(f.egress) != 0 {
		t.Fatalf("unblock: %s %v", typ, f.egress)
	}
}

func TestRollbackOnFailedVerification(t *testing.T) {
	f := withFakeFirewall(t)
	f.verifyOK = false
	a := api.FirewallAction{ID: 40, Kind: "close_port", Port: 6379, Proto: "tcp"}
	applyFirewallState(nil, []api.FirewallAction{a}, false)
	typ, _, d := runFirewallAction(a)
	if typ != "firewall_action_rolled_back" || d["reason"] != "verify_failed" || d["verify"] == "" {
		t.Fatalf("got %s %v", typ, d)
	}
	if len(f.ports) != 0 {
		t.Fatalf("not rolled back: %v", f.ports)
	}
}

func TestMonitorModeChangesNothing(t *testing.T) {
	f := withFakeFirewall(t)
	a := api.FirewallAction{ID: 50, Kind: "close_port", Port: 6379, Proto: "tcp"}
	state := &api.FirewallState{ClosedPorts: []api.PortProto{{Port: 9200}}, EgressBlocked: []string{"185.1.2.3"}}
	applyFirewallState(state, []api.FirewallAction{a}, true)
	typ, _, d := runFirewallAction(a)
	if typ != "firewall_action_failed" || d["status"] != "skipped" || d["reason"] != "monitor_mode" {
		t.Fatalf("got %s %v", typ, d)
	}
	if len(f.ports) != 0 || len(f.egress) != 0 {
		t.Fatalf("monitor mode enforced %v %v", f.ports, f.egress)
	}
}

func TestEnrichEvent(t *testing.T) {
	country := func(ip string) string {
		if ip == "198.51.100.7" {
			return "DE"
		}
		return ""
	}
	shared := map[string]string{"operation": "ssh_login", "ip": "198.51.100.7"}
	e := api.EventRequest{Type: "system_audit", Details: shared}
	enrichEvent(&e, country)
	if e.SourceIP != "198.51.100.7" || e.Details["country"] != "DE" {
		t.Fatalf("got %+v", e)
	}
	if _, ok := shared["country"]; ok {
		t.Fatal("the caller's details map was modified")
	}

	e = api.EventRequest{Type: "ssh_session", Details: map[string]string{"ip": "10.0.0.4"}}
	enrichEvent(&e, country)
	if e.SourceIP != "10.0.0.4" || e.Details["country"] != "" {
		t.Fatalf("private: %+v", e)
	}

	// Other events keep their source; no database, no country.
	e = api.EventRequest{Type: "sql_injection", SourceIP: "198.51.100.7", Details: map[string]string{"ip": "203.0.113.1"}}
	enrichEvent(&e, nil)
	if e.SourceIP != "198.51.100.7" || e.Details["country"] != "" {
		t.Fatalf("got %+v", e)
	}
}

// A result that could not be delivered is sent again, the request is not
// run a second time.
func TestUndeliveredResultIsResent(t *testing.T) {
	f := withFakeFirewall(t)
	var sent []api.EventRequest
	fail := true
	fwReport = func(_ *api.Client, ev api.EventRequest) error {
		if fail {
			return errors.New("offline")
		}
		sent = append(sent, ev)
		return nil
	}
	a := api.FirewallAction{ID: 60, Kind: "close_port", Port: 6379, Proto: "tcp"}
	applyFirewallState(&api.FirewallState{}, []api.FirewallAction{a}, false)
	applyFirewallActions(nil, []api.FirewallAction{a})
	applies := f.applies
	fail = false
	applyFirewallActions(nil, []api.FirewallAction{a})
	if len(sent) != 1 || sent[0].Type != "firewall_action_done" || sent[0].Details["action_id"] != "60" {
		t.Fatalf("sent %v", sent)
	}
	if f.applies != applies {
		t.Fatal("the request ran again")
	}
	applyFirewallActions(nil, []api.FirewallAction{a})
	if len(sent) != 1 {
		t.Fatalf("delivered result sent twice: %d", len(sent))
	}
}

// A sync without firewall_state (older dashboard) changes nothing.
func TestMissingStateKeepsState(t *testing.T) {
	f := withFakeFirewall(t)
	applyFirewallState(&api.FirewallState{ClosedPorts: []api.PortProto{{Port: 9200}}}, nil, false)
	applyFirewallState(nil, nil, false)
	if !reflect.DeepEqual(f.ports, []int{9200}) {
		t.Fatalf("got %v", f.ports)
	}
}

// Egress state entries: one not enforced yet must have been flagged; one
// already enforced stays when the flag expires; one the allow list now
// covers is lifted.
func TestEgressStateRefusals(t *testing.T) {
	f := withFakeFirewall(t)
	state := &api.FirewallState{EgressBlocked: []string{"185.1.2.3", "203.0.113.99"}}
	applyFirewallState(state, nil, false)
	if !reflect.DeepEqual(f.egress, []string{"185.1.2.3"}) {
		t.Fatalf("egress %v", f.egress)
	}
	ev := f.refusalsSoon(1)
	if len(ev) != 1 || ev[0].Details["ip"] != "203.0.113.99" || ev[0].Details["reason"] != "not_flagged" {
		t.Fatalf("refusals %+v", ev)
	}
	delete(f.flagged, "185.1.2.3")
	applyFirewallState(state, nil, false)
	if !reflect.DeepEqual(f.egress, []string{"185.1.2.3"}) {
		t.Fatalf("enforced block lifted when its flag expired: %v", f.egress)
	}
	fwEgressRefusal = func(ip string) string {
		if ip == "185.1.2.3" {
			return "allowlisted_target"
		}
		return ""
	}
	applyFirewallState(state, nil, false)
	if len(f.egress) != 0 {
		t.Fatalf("allow-listed address still blocked: %v", f.egress)
	}
}

// The live-connection check is for new requests: a port already closed
// stays closed when someone is connected (through the DROP, or before it).
func TestLiveCheckOnlyForNewRequests(t *testing.T) {
	f := withFakeFirewall(t)
	a := api.FirewallAction{ID: 70, Kind: "close_port", Port: 6379, Proto: "tcp"}
	applyFirewallState(nil, []api.FirewallAction{a}, false)
	if typ, _, d := runFirewallAction(a); typ != "firewall_action_done" {
		t.Fatalf("close: %s %v", typ, d)
	}
	f.inbound[6379] = []string{"198.51.100.7"}
	applyFirewallState(&api.FirewallState{ClosedPorts: []api.PortProto{{Port: 6379}}}, nil, false)
	if !reflect.DeepEqual(f.ports, []int{6379}) {
		t.Fatalf("closed port reopened: %v", f.ports)
	}
	f.mu.Lock()
	dropped := append([]int(nil), f.dropped...)
	f.mu.Unlock()
	for i := 0; i < 100 && len(dropped) == 0; i++ {
		time.Sleep(10 * time.Millisecond)
		f.mu.Lock()
		dropped = append([]int(nil), f.dropped...)
		f.mu.Unlock()
	}
	if !reflect.DeepEqual(dropped, []int{6379}) {
		t.Fatalf("conntrack entries dropped for %v, want [6379] once", dropped)
	}
}

// What is enforced is saved (0600) and restored before the first firewall
// setup, re-checked by the same refusals.
func TestStatePersistsAcrossRestart(t *testing.T) {
	f := withFakeFirewall(t)
	f.inbound[6379] = nil
	a := api.FirewallAction{ID: 80, Kind: "close_port", Port: 6379, Proto: "tcp"}
	b := api.FirewallAction{ID: 81, Kind: "block_egress", IP: "185.1.2.3"}
	applyFirewallState(nil, []api.FirewallAction{a, b}, false)
	runFirewallAction(a)
	runFirewallAction(b)
	noteEgressEvent(api.EventRequest{Type: "system_audit", Details: map[string]string{"operation": "ssh_login", "ip": "198.51.100.9"}})

	info, err := os.Stat(fwStatePath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("state file: %v %v", info, err)
	}
	data, _ := os.ReadFile(fwStatePath)
	var st fwPersisted
	if err := json.Unmarshal(data, &st); err != nil || !reflect.DeepEqual(st.ClosedPorts, []int{6379}) ||
		!reflect.DeepEqual(st.EgressBlocked, []string{"185.1.2.3"}) || st.SSHLogins["198.51.100.9"] == 0 {
		t.Fatalf("saved %s (%v)", data, err)
	}

	// "Restart": memory gone, someone connected to 6379 now, the flag gone.
	resetFirewallMemory()
	delete(f.flagged, "185.1.2.3")
	f.inbound[6379] = []string{"198.51.100.7"}
	// A saved port that is a web port now is dropped on load.
	st.ClosedPorts = append(st.ClosedPorts, 8080)
	b2, _ := json.Marshal(st)
	_ = os.WriteFile(fwStatePath, b2, 0600)
	loadFirewallState()
	appliedMu.Lock()
	gotPorts, gotEgress := fwAppliedPorts, fwAppliedEgress
	appliedMu.Unlock()
	if !reflect.DeepEqual(gotPorts, map[int]bool{6379: true}) || !reflect.DeepEqual(gotEgress, map[string]bool{"185.1.2.3": true}) {
		t.Fatalf("restored %v %v", gotPorts, gotEgress)
	}
	if !seenWithin(sshLogins, "198.51.100.9", sshLoginFor) {
		t.Fatal("SSH login addresses not restored")
	}
}

func TestActionsCappedPerSync(t *testing.T) {
	withFakeFirewall(t)
	var sent []string
	fwReport = func(_ *api.Client, ev api.EventRequest) error {
		sent = append(sent, ev.Details["action_id"])
		return nil
	}
	var actions []api.FirewallAction
	for i := 1; i <= 13; i++ {
		actions = append(actions, api.FirewallAction{ID: int64(i), Kind: "close_port", Port: 25, Proto: "tcp"})
	}
	applyFirewallActions(nil, actions)
	if len(sent) != maxActionsPerSync {
		t.Fatalf("first sync handled %d", len(sent))
	}
	applyFirewallActions(nil, actions)
	if len(sent) != 13 || sent[12] != "13" {
		t.Fatalf("second sync: %v", sent)
	}
}

func TestIPv6Exposure(t *testing.T) {
	f := withFakeFirewall(t)
	f.ports6 = false
	f.listens6[6379] = true
	a := api.FirewallAction{ID: 90, Kind: "close_port", Port: 6379, Proto: "tcp"}
	applyFirewallState(nil, []api.FirewallAction{a}, false)
	typ, _, d := runFirewallAction(a)
	if typ != "firewall_action_done" || d["message"] != ipv6ExposedMessage || !strings.Contains(d["verify"], `"ipv6_exposed":true`) {
		t.Fatalf("got %s %v", typ, d)
	}
	// Mirrored into ip6tables: a plain done.
	f.ports6 = true
	b := api.FirewallAction{ID: 91, Kind: "close_port", Port: 3306, Proto: "tcp"}
	f.listens6[3306] = true
	applyFirewallState(nil, []api.FirewallAction{a, b}, false)
	if typ, _, d := runFirewallAction(b); typ != "firewall_action_done" || strings.Contains(d["verify"], "ipv6_exposed") {
		t.Fatalf("mirrored: %s %v", typ, d)
	}
}

func TestNoteEgressEvent(t *testing.T) {
	resetFirewallMemory()
	t.Cleanup(resetFirewallMemory)
	old := fwStatePath
	fwStatePath = filepath.Join(t.TempDir(), "s.json")
	t.Cleanup(func() { fwStatePath = old })
	noteEgressEvent(api.EventRequest{Type: "egress_threat_match", SourceIP: "185.1.2.3"})
	noteEgressEvent(api.EventRequest{Type: "dns_threat_answer", SourceIP: "2001:db8::5"})
	noteEgressEvent(api.EventRequest{Type: "port_scan", SourceIP: "185.9.9.9"})
	if !seenWithin(flagged, "185.1.2.3", flaggedFor) || seenWithin(flagged, "185.9.9.9", flaggedFor) || len(flagged) != 1 {
		t.Fatalf("flagged %v", flagged)
	}
	now := fwNow
	fwNow = func() time.Time { return now().Add(25 * time.Hour) }
	defer func() { fwNow = now }()
	if seenWithin(flagged, "185.1.2.3", flaggedFor) {
		t.Fatal("flag older than 24 h still counts")
	}
}

func TestParseResolvectl(t *testing.T) {
	out := "Global: 9.9.9.9#dns.quad9.net\nLink 2 (eth0): 192.0.2.53 2001:db8::53%eth0\nLink 3 (docker0):\n"
	got := parseResolvectl(out)
	for _, ip := range []string{"9.9.9.9", "192.0.2.53", "2001:db8::53"} {
		if !got[ip] {
			t.Errorf("%s missing from %v", ip, got)
		}
	}
	if len(got) != 3 {
		t.Fatalf("got %v", got)
	}
}

func TestParseLastIPs(t *testing.T) {
	out := "root     pts/0        198.51.100.7     Mon Oct 12 10:00   still logged in\n" +
		"admin    pts/1        2001:db8::7      Sun Oct 11 09:00 - 10:00  (01:00)\n" +
		"reboot   system boot  0.0.0.0          Sun Oct 11 08:00   still running\n" +
		"root     tty1         0.0.0.0          Sun Oct 11 08:01 - 08:02  (00:01)\n" +
		"\nwtmp begins Sun Oct  1 00:00:00 2026\n"
	if got := parseLastIPs(out); !reflect.DeepEqual(got, []string{"198.51.100.7", "2001:db8::7"}) {
		t.Fatalf("got %v", got)
	}
}

// A block in force is lifted when its address logs in over SSH, never for a
// connection to SSH that has not logged in.
func TestEnforcedEgressAndSSHSessions(t *testing.T) {
	f := withFakeFirewall(t)
	block := api.FirewallAction{ID: 80, Kind: "block_egress", IP: "185.1.2.3"}
	applyFirewallState(nil, []api.FirewallAction{block}, false)
	if typ, _, d := runFirewallAction(block); typ != "firewall_action_done" {
		t.Fatalf("block: %s %v", typ, d)
	}
	state := &api.FirewallState{EgressBlocked: []string{"185.1.2.3"}}
	f.sockets = []netstate.Conn{
		{LocalPort: 22, State: 0x0A},
		{LocalPort: 22, RemoteIP: net.ParseIP("185.1.2.3").To4(), State: 0x01},
	}
	applyFirewallState(state, nil, false)
	if !reflect.DeepEqual(f.egress, []string{"185.1.2.3"}) {
		t.Fatalf("pre-auth connection lifted the block: %v", f.egress)
	}
	f.sessions = []string{"185.1.2.3"}
	applyFirewallState(state, nil, false)
	if len(f.egress) != 0 {
		t.Fatalf("logged-in address still blocked: %v", f.egress)
	}
	ev := f.refusalsSoon(1)
	if len(ev) != 1 || ev[0].Details["reason"] != "ssh_client" {
		t.Fatalf("refusals %+v", ev)
	}
}

// A destination this server talks to regularly is blocked only on a
// request a person asked for or approved; an enforced block stays.
func TestEgressRegularDestinationNeedsApproval(t *testing.T) {
	f := withFakeFirewall(t)
	saved := fwRegularDestination
	t.Cleanup(func() { fwRegularDestination = saved })
	fwRegularDestination = func(ip string) (bool, int, int) { return ip == "185.1.2.3", 40, 5 }

	auto := api.FirewallAction{ID: 90, Kind: "block_egress", IP: "185.1.2.3"}
	applyFirewallState(nil, []api.FirewallAction{auto}, false)
	typ, _, d := runFirewallAction(auto)
	if typ != "firewall_action_failed" || d["reason"] != "regular_destination" || !strings.Contains(d["message"], "40 times on 5 of the last 7 days") {
		t.Fatalf("automatic block: %s %v", typ, d)
	}
	if len(f.egress) != 0 {
		t.Fatalf("blocked: %v", f.egress)
	}
	// The dashboard state alone (no approved request) is refused too.
	applyFirewallState(&api.FirewallState{EgressBlocked: []string{"185.1.2.3"}}, nil, false)
	if len(f.egress) != 0 {
		t.Fatalf("state entry blocked a regular destination: %v", f.egress)
	}
	if ev := f.refusalsSoon(1); len(ev) != 1 || ev[0].Details["reason"] != "regular_destination" {
		t.Fatalf("refusals %+v", ev)
	}
	approved := api.FirewallAction{ID: 91, Kind: "block_egress", IP: "185.1.2.3", Approved: true}
	applyFirewallState(&api.FirewallState{}, []api.FirewallAction{approved}, false)
	if typ, _, d := runFirewallAction(approved); typ != "firewall_action_done" {
		t.Fatalf("approved block: %s %v", typ, d)
	}
	applyFirewallState(&api.FirewallState{EgressBlocked: []string{"185.1.2.3"}}, nil, false)
	if !reflect.DeepEqual(f.egress, []string{"185.1.2.3"}) {
		t.Fatalf("approved block lifted: %v", f.egress)
	}
}

// Without an OpenSSH process to inspect (dropbear, sshd in a container of
// its own), any connection to an SSH port still shields its address.
func TestEgressSSHServerNotInspectable(t *testing.T) {
	f := withFakeFirewall(t)
	f.noSSHD = true
	f.sockets = []netstate.Conn{
		{LocalPort: 22, State: 0x0A},
		{LocalPort: 22, RemoteIP: net.ParseIP("185.1.2.3").To4(), State: 0x01},
	}
	a := api.FirewallAction{ID: 95, Kind: "block_egress", IP: "185.1.2.3"}
	applyFirewallState(nil, []api.FirewallAction{a}, false)
	if typ, _, d := runFirewallAction(a); typ != "firewall_action_failed" || d["reason"] != "ssh_client" {
		t.Fatalf("%s %v", typ, d)
	}
}
