package opnsense

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func load(t *testing.T, name string) *Config {
	t.Helper()
	c, err := LoadConfig(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func ids(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.ID+":"+f.Severity)
	}
	sort.Strings(out)
	return out
}

func lines(t *testing.T, name string) []string {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

func TestFactoryConfig(t *testing.T) {
	c := load(t, "config-factory.xml")
	if got := c.ExternalNames(); !reflect.DeepEqual(got, []string{"wan"}) {
		t.Fatalf("external %v", got)
	}
	if got := c.InternalNets(); !reflect.DeepEqual(got, []string{"192.168.1.0/24"}) {
		t.Fatalf("internal %v", got)
	}
	if len(c.Rules) != 2 || c.Rules[0].Interface[0] != "lan" || c.Rules[0].Src != "lan" {
		t.Fatalf("rules %+v", c.Rules)
	}
	got := ids(Check(c, nil))
	want := []string{"default_root_password:critical", "gui_2fa_off:medium", "no_offbox_backup:low"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("findings %v, want %v", got, want)
	}
}

func TestExposedConfig(t *testing.T) {
	c := load(t, "config-exposed.xml")
	if !c.IDSEnabled || !c.IPSMode || !c.CARP || c.Hostname != "fw1" {
		t.Fatalf("flags %+v", c)
	}
	if got := c.InternalNets(); !reflect.DeepEqual(got, []string{"192.168.10.0/24", "fd00:10::/64", "172.16.5.0/24"}) {
		t.Fatalf("internal %v (disabled opt2 must not count)", got)
	}
	if !reflect.DeepEqual(c.Gateways, []string{"85.1.2.1"}) || !reflect.DeepEqual(c.Peers, []string{"91.198.174.192"}) || len(c.DNSServers) != 2 {
		t.Fatalf("gw %v peers %v dns %v", c.Gateways, c.Peers, c.DNSServers)
	}
	if !reflect.DeepEqual(c.Plugin.Interfaces, []string{"wan", "opt1"}) || c.Aliases["infrafence_bans"] != "external" {
		t.Fatalf("plugin %+v aliases %v", c.Plugin, c.Aliases)
	}
	if !reflect.DeepEqual(c.Backups, []string{"Nextcloud"}) {
		t.Fatalf("backups %v", c.Backups)
	}
	fwData, _ := os.ReadFile("testdata/firmware-updates.json")
	fw, err := ParseFirmware(fwData)
	if err != nil {
		t.Fatal(err)
	}
	got := ids(Check(c, &fw))
	want := []string{"admin_without_2fa:medium", "firmware_updates_pending:medium", "gui_wan_exposed:high", "ssh_wan_exposed:high", "wan_any_any_pass:critical"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("findings %v, want %v", got, want)
	}
	for _, f := range Check(c, &fw) {
		if f.ID == "admin_without_2fa" && f.Detail != "No OTP seed for: alice." {
			t.Fatalf("2fa detail %q (disabled bob must not count)", f.Detail)
		}
		if strings.Contains(f.Detail, "$2y$") {
			t.Fatal("a password hash leaked into a finding")
		}
	}
}

func TestGUIExposureNeedsRule(t *testing.T) {
	c := load(t, "config-exposed.xml")
	c.Rules = nil
	for _, f := range Check(c, nil) {
		if f.ID == "gui_wan_exposed" || f.ID == "wan_any_any_pass" || f.ID == "ssh_wan_exposed" {
			t.Fatalf("%s without a WAN rule", f.ID)
		}
	}
	// GUI on LAN only: a WAN rule to 8443 does not expose it.
	c = load(t, "config-exposed.xml")
	c.WebGUI.Interfaces = []string{"lan"}
	for _, f := range Check(c, nil) {
		if f.ID == "gui_wan_exposed" {
			t.Fatal("GUI bound to LAN reported exposed")
		}
	}
}

func TestPortMatches(t *testing.T) {
	for spec, want := range map[string]bool{"": true, "any": true, "443": true, "80,443": true, "400:500": true, "https": true, "22": false, "MyPorts": false, "1000-2000": false} {
		if portMatches(spec, "443") != want {
			t.Errorf("%q: want %v", spec, want)
		}
	}
}

func TestFirmware(t *testing.T) {
	data, _ := os.ReadFile("testdata/firmware-updates.json")
	fw, _ := ParseFirmware(data)
	if !fw.Checked || fw.Updates != 2 || fw.Version != "26.7.1" || fw.Latest != "26.7.3" {
		t.Fatalf("%+v", fw)
	}
	data, _ = os.ReadFile("testdata/firmware-unchecked.json")
	fw, _ = ParseFirmware(data)
	if fw.Checked {
		t.Fatal("null product_check reported as checked")
	}
	if got := ids(Check(&Config{Backups: []string{"x"}}, &fw)); !reflect.DeepEqual(got, []string{"firmware_not_checked:low"}) {
		t.Fatalf("%v", got)
	}
	if _, err := ParseFirmware([]byte("Execute error")); err == nil {
		t.Fatal("configd error text parsed")
	}
}

func TestParseFilterLog(t *testing.T) {
	var got []FilterRecord
	for _, l := range lines(t, "filter.log") {
		if r, ok := ParseFilterLog(l); ok {
			got = append(got, r)
		}
	}
	if len(got) != 6 {
		t.Fatalf("parsed %d records: %+v", len(got), got)
	}
	want := []FilterRecord{
		{Proto: "tcp", Src: "45.155.205.233", Dst: "85.1.2.3", SrcPort: 51234, DstPort: 3389, Action: "block", Dir: "in", IPVersion: 4, Interface: "vtnet1"},
		{Proto: "udp", Src: "80.94.95.10", Dst: "85.1.2.3", SrcPort: 40000, DstPort: 5060, Action: "block", Dir: "in", IPVersion: 4, Interface: "vtnet1"},
		{Proto: "icmp", Src: "193.32.162.5", Dst: "85.1.2.3", Action: "block", Dir: "in", IPVersion: 4, Interface: "vtnet1"},
		{Proto: "tcp", Src: "2a03:b0c0:3:d0::1a4:1", Dst: "2a01:4f8:1:2::3", SrcPort: 44321, DstPort: 22, Action: "block", Dir: "in", IPVersion: 6, Interface: "vtnet1"},
		{Proto: "tcp", Src: "192.168.10.20", Dst: "93.184.216.34", SrcPort: 50000, DstPort: 443, Action: "pass", Dir: "in", IPVersion: 4, Interface: "vtnet0"},
		{Proto: "tcp", Src: "45.155.205.233", Dst: "85.1.2.3", SrcPort: 51234, DstPort: 23, Action: "block", Dir: "in", IPVersion: 4, Interface: "vtnet1"},
	}
	for i, w := range want {
		g := got[i]
		if g.Proto != w.Proto || g.Src != w.Src || g.Dst != w.Dst || g.SrcPort != w.SrcPort || g.DstPort != w.DstPort || g.Action != w.Action || g.Dir != w.Dir || g.IPVersion != w.IPVersion || g.Interface != w.Interface {
			t.Errorf("record %d: got %+v, want %+v", i, g, w)
		}
	}
}

func TestParseAuth(t *testing.T) {
	var got []string
	for _, f := range []string{"audit.log", "openvpn.log"} {
		for _, l := range lines(t, f) {
			if e, ok := ParseAuth(l); ok {
				got = append(got, e.Service+" "+e.Result+" "+e.IP+" "+e.User)
			}
		}
	}
	want := []string{
		"ssh failure 45.155.205.233 admin",
		"ssh failure 45.155.205.233 admin",
		"ssh failure 2a03:b0c0:3:d0::1a4:1 root",
		"ssh failure 45.155.205.233 oracle",
		"ssh success 192.168.10.20 root",
		"opnsense-gui failure 80.94.95.10 root",
		"opnsense-gui failure 80.94.95.10 admin",
		"opnsense-gui success 192.168.10.20 root",
		"opnsense-gui success 192.168.10.20 root",
		// Real OPNsense 26.7 lines (VM): only the legacy line has the address.
		"opnsense-gui failure 127.0.0.1 root",
		"ssh failure 45.155.205.233 root",
		"openvpn failure 80.94.95.11 ",
		"openvpn failure 80.94.95.11 ",
		"openvpn failure 2001:67c:2e8:22::c100:68b ",
		"openvpn failure 80.94.95.12 ",
		"wireguard failure 80.94.95.13 ",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestParseEve(t *testing.T) {
	var got []IDSAlert
	for _, l := range lines(t, "eve.json") {
		if a, ok := ParseEve(l); ok {
			got = append(got, a)
		}
	}
	if len(got) != 2 {
		t.Fatalf("%d alerts", len(got))
	}
	a := got[0]
	if a.SrcIP != "45.155.205.233" || a.DestPort != 443 || a.Alert.SID != 2024897 || a.Alert.Action != "blocked" || a.SeverityName() != "critical" || a.Interface != "vtnet1" {
		t.Fatalf("%+v", a)
	}
	if got[1].SeverityName() != "info" {
		t.Fatal(got[1].SeverityName())
	}
}

func TestParseSyslogVariants(t *testing.T) {
	sl, ok := ParseSyslog(`<13>1 2026-11-15T10:00:00+01:00 h prog 1 - - hello world`)
	if !ok || sl.Program != "prog" || sl.Msg != "- hello world" && sl.Msg != "hello world" {
		t.Fatalf("%+v", sl)
	}
	sl, ok = ParseSyslog(`<13>1 2026-11-15T10:00:00+01:00 h prog 1 - [meta a="x]y" b="\"q\""][x y="1"] msg`)
	if !ok || sl.Msg != "msg" {
		t.Fatalf("%+v %v", sl, ok)
	}
	if _, ok := ParseSyslog(`<13>1 2026-11-15T10:00:00+01:00 h prog 1 - [unterminated msg`); ok {
		t.Fatal("unterminated SD accepted")
	}
}

func TestTailFollowsLatestSymlink(t *testing.T) {
	dir := t.TempDir()
	day1 := filepath.Join(dir, "filter_20261114.log")
	day2 := filepath.Join(dir, "filter_20261115.log")
	latest := filepath.Join(dir, "latest.log")
	os.WriteFile(day1, []byte("old line before start\n"), 0o644)
	os.Symlink(day1, latest)
	var mu sync.Mutex
	var got []string
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		Tail(ctx, latest, 20*time.Millisecond, func(l string) {
			mu.Lock()
			got = append(got, l)
			mu.Unlock()
		})
		close(done)
	}()
	time.Sleep(60 * time.Millisecond)
	f, _ := os.OpenFile(day1, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("a\nb-partial")
	time.Sleep(60 * time.Millisecond)
	f.WriteString("-done\n")
	f.Close()
	time.Sleep(60 * time.Millisecond)
	// Midnight: a new file and the symlink switched.
	os.WriteFile(day2, []byte("c\n"), 0o644)
	os.Remove(latest)
	os.Symlink(day2, latest)
	time.Sleep(100 * time.Millisecond)
	f, _ = os.OpenFile(day2, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("d\n")
	f.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n >= 4 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	if want := []string{"a", "b-partial-done", "c", "d"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestAggregator(t *testing.T) {
	now := time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)
	a := NewAggregator([]string{"vtnet1"}, now)
	n := 0
	for _, l := range lines(t, "filter.log") {
		if r, ok := ParseFilterLog(l); ok && a.Add(r) {
			n++
		}
	}
	if n != 5 {
		t.Fatalf("counted %d (the LAN pass must not count)", n)
	}
	s, ok := a.Take(now.Add(time.Minute))
	if !ok || s.Blocked != 5 || s.DistinctSources != 4 || s.TopSources[0] != (KeyCount{"45.155.205.233", 2}) {
		t.Fatalf("%+v", s)
	}
	if s2, ok := a.Take(now.Add(2 * time.Minute)); ok || s2.Blocked != 0 {
		t.Fatal("window not reset")
	}
	// Bounded under a flood of distinct sources.
	for i := 0; i < maxKeys+500; i++ {
		a.Add(FilterRecord{Action: "block", Dir: "in", Interface: "vtnet1", Proto: "tcp", Src: strconv.Itoa(i), DstPort: 1})
	}
	if s, _ := a.Take(now); !s.Truncated || s.DistinctSources != maxKeys || s.Blocked != maxKeys+500 {
		t.Fatalf("flood: %d sources, truncated %v", s.DistinctSources, s.Truncated)
	}
}

func TestCounter(t *testing.T) {
	now := time.Now()
	c := NewCounter(3, time.Minute)
	if c.Fail("a", now) != 0 || c.Fail("a", now.Add(time.Second)) != 0 {
		t.Fatal("fired early")
	}
	if n := c.Fail("a", now.Add(2*time.Second)); n != 3 {
		t.Fatalf("fired %d", n)
	}
	if c.Fail("a", now.Add(3*time.Second)) != 0 {
		t.Fatal("fired twice in a window")
	}
	// Spread over more than the window: never fires.
	for i := 0; i < 10; i++ {
		if c.Fail("b", now.Add(time.Duration(i)*40*time.Second)) != 0 {
			t.Fatal("slow failures fired")
		}
	}
}

func TestGuard(t *testing.T) {
	c := load(t, "config-exposed.xml")
	g := NewGuard()
	g.Set(append(GuardEntries(c, []string{"203.0.113.77"}), GuardEntry{"104.18.0.0/20", "the InfraFence dashboard"}))
	for ip, want := range map[string]string{
		"85.1.2.3":       "an address of this firewall",
		"85.1.2.1":       "a gateway of this firewall",
		"85.1.2.5":       "", // same WAN subnet: not protected
		"9.9.9.9":        "a DNS server of this firewall",
		"91.198.174.192": "a VPN peer of this firewall",
		"192.168.10.77":  "an internal network of this firewall",
		"172.16.5.9":     "an internal network of this firewall",
		"203.0.113.77":   "an address of this firewall",
		"104.18.3.4":     "the InfraFence dashboard",
		"45.155.205.233": "",
	} {
		if got := g.Why(net.ParseIP(ip)); got != want {
			t.Errorf("%s: %q, want %q", ip, got, want)
		}
	}
	for _, n := range g.Nets() {
		if strings.HasPrefix(n, "192.168.") || strings.HasPrefix(n, "172.16.") || strings.HasPrefix(n, "fd00") {
			t.Errorf("private network %s in the negations", n)
		}
	}
}

func TestCounterBounded(t *testing.T) {
	now := time.Now()
	c := NewCounter(5, time.Minute)
	for i := 0; i < maxKeys+1000; i++ {
		c.Fail(strconv.Itoa(i), now)
	}
	if len(c.seen) > maxKeys {
		t.Fatalf("%d keys", len(c.seen))
	}
}

func TestAuthSpoofedUsernames(t *testing.T) {
	// The user name is attacker text: the real source is the last address.
	for _, l := range []string{
		`<38>1 2026-11-15T09:20:01+01:00 fw sshd 1 - - Invalid user x from 8.8.4.4 port 1 from 45.155.205.233 port 4444`,
		`<38>1 2026-11-15T09:20:01+01:00 fw sshd 1 - - Failed password for invalid user x from 8.8.4.4 port 1 ssh2 from 45.155.205.233 port 4444 ssh2`,
		`<36>1 2026-11-15T09:21:01+01:00 fw audit 1 - - user x could not authenticate for WebGui. [using a + b] at 8.8.4.4 could not authenticate for WebGui. [using OPNsense\Auth\Services\WebGui + OPNsense\Auth\Local] at 45.155.205.233`,
		`<36>1 2026-11-15T09:21:02+01:00 fw audit 1 - - /index.php: Web GUI authentication error for 'x' from 8.8.4.4' from 45.155.205.233`,
	} {
		e, ok := ParseAuth(l)
		if !ok || e.IP != "45.155.205.233" {
			t.Errorf("%q: %+v %v", l, e, ok)
		}
	}
	// A WireGuard-looking user name in an sshd line is not a WireGuard event.
	l := `<38>1 2026-11-15T09:20:01+01:00 fw sshd 1 - - Connection closed by invalid user wg0: Invalid handshake initiation from 8.8.4.4:1 45.155.205.233 port 4 [preauth]`
	if e, ok := ParseAuth(l); ok {
		t.Errorf("spoofed WireGuard line parsed: %+v", e)
	}
	// Pre-authentication UDP failures are marked spoofable.
	e, ok := ParseAuth(`<28>1 2026-11-15T09:30:02+01:00 fw openvpn_server1 7001 - - 80.94.95.11:41235 TLS Error: TLS handshake failed`)
	if !ok || !e.Spoofable {
		t.Fatalf("%+v", e)
	}
	e, ok = ParseAuth(`<28>1 2026-11-15T09:30:01+01:00 fw openvpn_server1 7001 - - 80.94.95.11:41234 TLS Auth Error: Auth Username/Password verification failed for peer`)
	if !ok || e.Spoofable {
		t.Fatalf("%+v", e)
	}
}
