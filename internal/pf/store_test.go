package pf_test

import (
	"net"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/infrafence/infrafence-agent/internal/pf"
	"github.com/infrafence/infrafence-agent/internal/pf/pftest"
)

type guard struct{ nets []string }

func (g guard) Why(ip net.IP) string {
	for _, c := range g.nets {
		if _, n, err := net.ParseCIDR(c); err == nil && n.Contains(ip) {
			return "protected " + c
		}
	}
	return ""
}
func (g guard) Nets() []string { return g.nets }
func (g guard) Overlaps(n *net.IPNet) string {
	for _, c := range g.nets {
		if _, p, err := net.ParseCIDR(c); err == nil && (p.Contains(n.IP) || n.Contains(p.IP)) {
			return "protected " + c
		}
	}
	return ""
}

// neg is the table content: the always-negated private ranges, the
// guard's network, then entries.
func neg(entries ...string) []string {
	out := []string{"!10.0.0.0/8", "!100.64.0.0/10", "!127.0.0.0/8", "!169.254.0.0/16", "!172.16.0.0/12", "!192.168.0.0/16",
		"!::1", "!fc00::/7", "!fe80::/10", "!85.1.2.0/29"}
	out = append(out, entries...)
	sort.Strings(out)
	return out
}

func positive(list []string) []string {
	var out []string
	for _, e := range list {
		if !strings.HasPrefix(e, "!") {
			out = append(out, e)
		}
	}
	return out
}

func newStore(t *testing.T) (*pf.Store, *pftest.Fake, string) {
	t.Helper()
	f := pftest.NewFake()
	state := filepath.Join(t.TempDir(), "pf-state.json")
	s := pf.NewStore(pf.NewCtl(f.Run), guard{nets: []string{"85.1.2.0/29"}}, state)
	if _, err := s.Ensure(); err != nil {
		t.Fatal(err)
	}
	return s, f, state
}

func TestBanUnbanWritesTable(t *testing.T) {
	s, f, _ := newStore(t)
	added, why, err := s.Ban("45.155.205.233", time.Now().Add(time.Hour), "brute_force_ssh", "local")
	if !added || why != "" || err != nil {
		t.Fatalf("ban: %v %q %v", added, why, err)
	}
	if got := f.Entries(pf.TableBans); !reflect.DeepEqual(got, neg("45.155.205.233")) {
		t.Fatalf("table %v", got)
	}
	if len(f.Killed) != 1 || f.Killed[0] != "45.155.205.233" {
		t.Fatalf("states of the banned host not killed: %v", f.Killed)
	}
	// Second ban of the same address: not added again.
	if added, _, _ := s.Ban("45.155.205.233", time.Time{}, "x", "local"); added {
		t.Fatal("added twice")
	}
	if ok, err := s.Unban("45.155.205.233"); !ok || err != nil {
		t.Fatalf("unban %v %v", ok, err)
	}
	if got := f.Entries(pf.TableBans); !reflect.DeepEqual(got, neg()) {
		t.Fatalf("table after unban %v", got)
	}
}

func TestIPv6SharesTable(t *testing.T) {
	s, f, _ := newStore(t)
	if added, _, _ := s.Ban("2a03:2880:f12f:83:face:b00c:0:25de", time.Time{}, "x", "local"); !added {
		t.Fatal("v6 not banned")
	}
	if !strings.Contains(strings.Join(f.Entries(pf.TableBans), " "), "2a03:2880:f12f:83:face:b00c:0:25de") {
		t.Fatal("v6 not in table")
	}
}

func TestNeverBans(t *testing.T) {
	s, f, _ := newStore(t)
	s.SetAllowList([]string{"91.200.12.0/24", "8.8.8.8"})
	for ip, want := range map[string]string{
		"192.168.1.50":  "private (internal) address",
		"10.0.0.1":      "private (internal) address",
		"127.0.0.1":     "loopback or unspecified address",
		"fe80::1":       "link-local or multicast address",
		"100.64.3.3":    "reserved address range",
		"85.1.2.3":      "protected 85.1.2.0/29",
		"91.200.12.77":  "allow-listed",
		"8.8.8.8":       "allow-listed",
		"not-an-ip":     "invalid address",
		"1.0.0.0/8":     "network too large to ban",
		"91.200.0.0/16": "overlaps the allow list",
	} {
		added, why, _ := s.Ban(ip, time.Time{}, "x", "local")
		if added || why != want {
			t.Errorf("%s: added=%v why=%q, want %q", ip, added, why, want)
		}
	}
	for _, e := range f.Entries(pf.TableBans) {
		if !strings.HasPrefix(e, "!") {
			t.Fatalf("a refused address reached the table: %v", f.Entries(pf.TableBans))
		}
	}
	// Allow-listed and protected networks are negated in every table.
	for _, tb := range pf.Tables {
		got := strings.Join(f.Entries(tb), " ")
		for _, n := range neg("!91.200.12.0/24", "!8.8.8.8") {
			if !strings.Contains(got, n) {
				t.Errorf("%s lacks %s: %s", tb, n, got)
			}
		}
	}
}

func TestAllowListRemovesBan(t *testing.T) {
	s, f, _ := newStore(t)
	s.Ban("37.19.221.10", time.Time{}, "x", "local")
	s.SetAllowList([]string{"37.19.221.0/24"})
	if s.IsBanned("37.19.221.10") {
		t.Fatal("allow-listed address still banned")
	}
	if strings.Contains(strings.Join(f.Entries(pf.TableBans), " "), " 37.19.221.10") {
		t.Fatal("still in table")
	}
}

func TestFilterReloadAndReboot(t *testing.T) {
	s, f, state := newStore(t)
	s.Ban("45.155.205.233", time.Now().Add(time.Hour), "x", "local")
	s.SetSet(pf.TableThreat, []string{"185.220.101.0/24", "10.0.0.0/8", "185.220.101.0/24"})
	// A filter reload keeps external tables: nothing to repair.
	if rep, err := s.Ensure(); err != nil || len(rep) != 0 {
		t.Fatalf("after reload: %v %v", rep, err)
	}
	// A reboot empties them: a new agent restores from the state file.
	f.Reboot()
	s2 := pf.NewStore(pf.NewCtl(f.Run), guard{nets: []string{"85.1.2.0/29"}}, state)
	if n := s2.Load(); n != 1 {
		t.Fatalf("restored %d bans", n)
	}
	s2.SetSet(pf.TableThreat, []string{"185.220.101.0/24"})
	rep, err := s2.Ensure()
	if err != nil || len(rep) != 3 {
		t.Fatalf("after reboot: %v %v", rep, err)
	}
	if got := f.Entries(pf.TableBans); !reflect.DeepEqual(got, neg("45.155.205.233")) {
		t.Fatalf("bans after reboot %v", got)
	}
	if got := f.Entries(pf.TableThreat); !reflect.DeepEqual(got, neg("185.220.101.0/24")) {
		t.Fatalf("threat after reboot %v (private net must be dropped)", got)
	}
	// Someone flushes a table by hand: the guard refills it.
	f.Run("", "-t", pf.TableBans, "-T", "flush")
	if rep, _ := s2.Ensure(); len(rep) != 1 || rep[0] != pf.TableBans {
		t.Fatalf("flush not repaired: %v", rep)
	}
}

func TestDetectOnlyWithoutTables(t *testing.T) {
	s, f, _ := newStore(t)
	f.Declare(pf.TableGeo, false) // plugin removed / aliases not loaded
	if _, err := s.Ensure(); err != pf.ErrNoTables {
		t.Fatalf("err %v", err)
	}
	before := len(f.Calls)
	if added, _, err := s.Ban("45.155.205.233", time.Time{}, "x", "local"); !added || err != nil {
		t.Fatalf("ban is still recorded: %v %v", added, err)
	}
	for _, c := range f.Calls[before:] {
		if strings.Contains(c, "-T") {
			t.Fatalf("pf written while detect-only: %s", c)
		}
	}
	if st := s.Status(); st.Ready {
		t.Fatal("ready while tables missing")
	}
	// Plugin back: the guard fills everything.
	f.Declare(pf.TableGeo, true)
	if _, err := s.Ensure(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(f.Entries(pf.TableBans), " "), "45.155.205.233") {
		t.Fatal("ban not applied once tables are back")
	}
}

func TestLearningEmptiesTables(t *testing.T) {
	s, f, _ := newStore(t)
	s.Ban("45.155.205.233", time.Time{}, "x", "local")
	s.SetSet(pf.TableGeo, []string{"5.8.0.0/16"})
	s.SetMonitor(true)
	for _, tb := range pf.Tables {
		for _, e := range f.Entries(tb) {
			if !strings.HasPrefix(e, "!") {
				t.Fatalf("Learning mode: %s still blocks %s", tb, e)
			}
		}
	}
	if added, why, _ := s.Ban("45.155.205.234", time.Time{}, "x", "local"); added || why != "learning" {
		t.Fatalf("learning ban: %v %q", added, why)
	}
	s.SetMonitor(false)
	if !strings.Contains(strings.Join(f.Entries(pf.TableGeo), " "), "5.8.0.0/16") {
		t.Fatal("geo not restored after Learning")
	}
}

func TestSyncBansAndExpiry(t *testing.T) {
	s, f, _ := newStore(t)
	now := time.Now()
	s.Ban("45.155.205.233", now.Add(time.Hour), "local", "local")
	added, removed := s.SyncBans([]pf.Ban{{IP: "80.94.95.1"}, {IP: "80.94.95.2", Expires: now.Add(time.Minute)}, {IP: "192.168.1.9"}, {IP: "80.94.95.3", Expires: now.Add(-time.Minute)}})
	if added != 2 || removed != 0 {
		t.Fatalf("added %d removed %d", added, removed)
	}
	// Dashboard drops 80.94.95.1: removed; the local ban stays.
	_, removed = s.SyncBans([]pf.Ban{{IP: "80.94.95.2", Expires: now.Add(time.Minute)}})
	if removed != 1 || s.IsBanned("80.94.95.1") || !s.IsBanned("45.155.205.233") {
		t.Fatalf("removed %d, bans %v", removed, s.Bans())
	}
	gone := s.Expire(now.Add(2 * time.Minute))
	if !reflect.DeepEqual(gone, []string{"80.94.95.2"}) {
		t.Fatalf("expired %v", gone)
	}
	if got := f.Entries(pf.TableBans); !reflect.DeepEqual(got, neg("45.155.205.233")) {
		t.Fatalf("table %v", got)
	}
}

func TestOnlyOwnTables(t *testing.T) {
	ctl := pf.NewCtl(pftest.NewFake().Run)
	if err := ctl.Replace("sshlockout", nil); err == nil {
		t.Fatal("wrote a table that is not ours")
	}
	if err := ctl.Add("bogons", "1.2.3.4"); err == nil {
		t.Fatal("wrote a table that is not ours")
	}
}

func TestCapacity(t *testing.T) {
	f := pftest.NewFake()
	f.Limit = 10
	s := pf.NewStore(pf.NewCtl(f.Run), nil, "")
	s.Ensure()
	var err error
	for i := 1; i <= 12 && err == nil; i++ {
		_, _, err = s.Ban(net.IPv4(45, 155, 205, byte(i)).String(), time.Time{}, "x", "local")
	}
	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("no capacity error: %v", err)
	}
}

func TestCtlParsing(t *testing.T) {
	f := pftest.NewFake()
	ctl := pf.NewCtl(f.Run)
	if on, err := ctl.Enabled(); !on || err != nil {
		t.Fatalf("enabled %v %v", on, err)
	}
	f.Enabled = false
	if on, _ := ctl.Enabled(); on {
		t.Fatal("disabled pf reported enabled")
	}
	if n := ctl.TableLimit(); n != 1000000 {
		t.Fatalf("limit %d", n)
	}
	f.Fail = "replace"
	if err := ctl.Replace(pf.TableBans, []string{"1.2.3.4"}); err == nil || !strings.Contains(err.Error(), "fake failure") {
		t.Fatalf("error not surfaced: %v", err)
	}
}

func TestFeedCannotCoverPrivateOrProtected(t *testing.T) {
	s, f, _ := newStore(t)
	s.SetSet(pf.TableThreat, []string{"128.0.0.0/1", "8.0.0.0/5", "172.0.0.0/8", "8000::/1", "85.1.0.0/16", "85.1.2.3", "185.220.101.0/24", "2001:db8:1::/48"})
	if got := positive(f.Entries(pf.TableThreat)); !reflect.DeepEqual(got, []string{"185.220.101.0/24", "2001:db8:1::/48"}) {
		t.Fatalf("threat table %v", got)
	}
	for _, ip := range []string{"10.0.0.0/9", "85.1.0.0/16", "128.0.0.0/1"} {
		if added, why, _ := s.Ban(ip, time.Time{}, "x", "dashboard"); added || why == "" {
			t.Errorf("network ban %s accepted", ip)
		}
	}
}

func TestSetCappedToLimit(t *testing.T) {
	f := pftest.NewFake()
	f.Limit = 400
	s := pf.NewStore(pf.NewCtl(f.Run), nil, "")
	s.Ensure()
	var list []string
	for i := 0; i < 300; i++ {
		list = append(list, net.IPv4(45, 155, byte(i/250), byte(i%250+1)).String())
	}
	s.SetSet(pf.TableGeo, list)
	if n := len(positive(f.Entries(pf.TableGeo))); n != 100 {
		t.Fatalf("%d entries for a limit of 400", n)
	}
}

func TestUnreferencedTableIsDetectOnly(t *testing.T) {
	s, f, _ := newStore(t)
	f.Unreference(pf.TableBans, true)
	if _, err := s.Ensure(); err != pf.ErrNoTables {
		t.Fatalf("persist table without rules: %v", err)
	}
	f.Unreference(pf.TableBans, false)
	if _, err := s.Ensure(); err != nil {
		t.Fatal(err)
	}
}

func TestPresentParsesRealOutput(t *testing.T) {
	out := "-pa-r--\tinfrafence_bans\n-pa----\tinfrafence_geo\n--a-r--\tbogons\n"
	ctl := pf.NewCtl(func(string, ...string) (string, error) { return out, nil })
	m, err := ctl.Present()
	if err != nil || !m["infrafence_bans"] || m["infrafence_geo"] || !m["bogons"] {
		t.Fatalf("%v %v", m, err)
	}
}
