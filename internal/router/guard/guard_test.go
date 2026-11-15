package guard

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestParse(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.7":        "203.0.113.7/32",
		"198.51.100.9/24":    "198.51.100.0/24",
		"::ffff:203.0.113.7": "203.0.113.7/32",
		"2001:db8::1":        "2001:db8::1/128",
		" 2001:db8::/32 ":    "2001:db8::/32",
	} {
		p, err := Parse(in)
		if err != nil || p.String() != want {
			t.Errorf("Parse(%q) = %v, %v; want %s", in, p, err, want)
		}
	}
	for _, bad := range []string{"", "x", "1.2.3.4/33", "::ffff:1.2.3.4/90"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q): no error", bad)
		}
	}
}

func TestCheck(t *testing.T) {
	g := New()
	g.SetProtected([]netip.Prefix{netip.MustParsePrefix("198.51.100.1/32")})
	g.SetAllow([]netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")})
	ok := []string{"203.0.113.7", "203.0.113.0/24", "8.0.0.0/8", "2a00:1450::/32"}
	refused := []string{
		"10.1.2.3", "192.168.1.5", "172.16.0.1", "100.64.1.1", "127.0.0.1", "169.254.1.1", "224.0.0.1", "0.0.0.0",
		"fe80::1", "fd00::1", "::1", "ff02::1",
		"0.0.0.0/4",       // too wide
		"2000::/16",       // too wide
		"198.51.100.1",    // protected
		"198.51.100.0/24", // contains a protected address
		"192.0.2.77",      // whitelisted
		"192.0.0.0/16",    // contains the whitelist
		"8.0.0.0/7",       // too wide
	}
	for _, s := range ok {
		if err := g.Check(mustParse(t, s)); err != nil {
			t.Errorf("Check(%s): %v", s, err)
		}
	}
	for _, s := range refused {
		if err := g.Check(mustParse(t, s)); err == nil {
			t.Errorf("Check(%s): allowed", s)
		}
	}
}

func mustParse(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestProcFiles(t *testing.T) {
	dir := t.TempDir()
	route := filepath.Join(dir, "route")
	// 10.0.2.2 as the kernel prints it on a little-endian host.
	os.WriteFile(route, []byte("Iface\tDestination\tGateway \tFlags\nbr-wan\t00000000\t0202000A\t0003\nbr-lan\t0002000A\t00000000\t0001\n"), 0o644)
	got := gateways4(route)
	if len(got) != 1 {
		t.Fatalf("gateways4 = %v", got)
	}
	r6 := filepath.Join(dir, "ipv6_route")
	os.WriteFile(r6, []byte("00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 wan\n"), 0o644)
	if g := gateways6(r6); len(g) != 1 || g[0].Addr().String() != "fe80::1" {
		t.Errorf("gateways6 = %v", g)
	}
	rc := filepath.Join(dir, "resolv")
	os.WriteFile(rc, []byte("# Interface wan\nnameserver 9.9.9.9\nnameserver 2620:fe::fe\nsearch lan\n"), 0o644)
	if r := resolvers(rc); len(r) != 2 {
		t.Errorf("resolvers = %v", r)
	}
}

func TestPeers(t *testing.T) {
	dump := []byte(`{"interface":[{"interface":"wan","route":[{"target":"0.0.0.0","mask":0,"nexthop":"0.0.0.0"},{"target":"0.0.0.0","mask":0,"nexthop":"198.51.100.1"}],
		"dns-server":["9.9.9.9","2620:fe::fe"],"ipv4-address":[{"address":"203.0.113.5","mask":32,"ptpaddress":"203.0.113.1"}]}]}`)
	got := ubusPeers(dump)
	want := map[string]bool{"198.51.100.1/32": true, "9.9.9.9/32": true, "2620:fe::fe/128": true, "203.0.113.1/32": true}
	if len(got) != len(want) {
		t.Fatalf("peers = %v", got)
	}
	for _, p := range got {
		if !want[p.String()] {
			t.Errorf("unexpected %s", p)
		}
	}
	s := dnsmasqServers("8.8.8.8 1.1.1.1#53 /lan.example/192.0.2.53 /onion/ 9.9.9.9@wan")
	if len(s) != 4 {
		t.Errorf("servers = %v", s)
	}
}
