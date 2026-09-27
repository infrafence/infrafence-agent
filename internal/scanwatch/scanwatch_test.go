package scanwatch

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"golang.org/x/net/bpf"
)

func ipv4SYN(src string, dport uint16, flags byte) []byte {
	b := make([]byte, 40)
	b[0] = 0x45
	b[9] = 6
	copy(b[12:16], net.ParseIP(src).To4())
	copy(b[16:20], net.ParseIP("203.0.113.1").To4())
	binary.BigEndian.PutUint16(b[20:22], 40000)
	binary.BigEndian.PutUint16(b[22:24], dport)
	b[20+13] = flags
	return b
}

func ipv6SYN(src string, dport uint16) []byte {
	b := make([]byte, 60)
	b[0] = 0x60
	b[6] = 6
	copy(b[8:24], net.ParseIP(src).To16())
	binary.BigEndian.PutUint16(b[42:44], dport)
	b[40+13] = 0x02
	return b
}

func TestParseSYN(t *testing.T) {
	src, port, ok := ParseSYN(ipv4SYN("198.51.100.9", 3306, 0x02))
	if !ok || src.String() != "198.51.100.9" || port != 3306 {
		t.Fatalf("got %v %d %v", src, port, ok)
	}
	if _, _, ok := ParseSYN(ipv4SYN("198.51.100.9", 3306, 0x12)); ok {
		t.Fatal("SYN-ACK is not a connection attempt")
	}
	if _, _, ok := ParseSYN(ipv4SYN("198.51.100.9", 80, 0x10)); ok {
		t.Fatal("ACK is not a connection attempt")
	}
	src, port, ok = ParseSYN(ipv6SYN("2001:db8::7", 22))
	if !ok || src.String() != "2001:db8::7" || port != 22 {
		t.Fatalf("ipv6: %v %d %v", src, port, ok)
	}
	if _, _, ok := ParseSYN([]byte{0x45, 0}); ok {
		t.Fatal("short packet accepted")
	}
}

func only(scans []Scan, scope string) (Scan, bool) {
	for _, s := range scans {
		if s.Scope == scope {
			return s, true
		}
	}
	return Scan{}, false
}

func TestAddressScanAtThreshold(t *testing.T) {
	a := NewAnalyzer(nil)
	now := time.Now()
	src := net.ParseIP("198.51.100.9")
	for p := 0; p < Threshold-1; p++ {
		if _, ok := only(a.Observe(src, uint16(1000+p), now), "address"); ok {
			t.Fatalf("reported after %d ports", p+1)
		}
	}
	// Repeating a port doesn't count twice.
	if _, ok := only(a.Observe(src, 1000, now), "address"); ok {
		t.Fatal("a repeated port counted")
	}
	s, ok := only(a.Observe(src, 2000, now), "address")
	if !ok || s.Ports != Threshold || s.IP != "198.51.100.9" || len(s.Sample) != Threshold {
		t.Fatalf("scan = %+v ok=%v", s, ok)
	}
	if d := s.Details(); d["ports_scanned"] != "15" || d["scope"] != "address" || d["window"] != "10m" {
		t.Fatalf("details = %v", d)
	}
	// Cooldown: not reported again right away.
	for p := 0; p < 50; p++ {
		if _, ok := only(a.Observe(src, uint16(3000+p), now.Add(time.Minute)), "address"); ok {
			t.Fatal("reported again within the cooldown")
		}
	}
	// After the cooldown it is.
	later := now.Add(Cooldown + Window + time.Minute)
	var again bool
	for p := 0; p < Threshold; p++ {
		if _, ok := only(a.Observe(src, uint16(5000+p), later), "address"); ok {
			again = true
		}
	}
	if !again {
		t.Fatal("not reported after the cooldown")
	}
}

func TestSlowScannerWithinTenMinutes(t *testing.T) {
	a := NewAnalyzer(nil)
	start := time.Now()
	src := net.ParseIP("198.51.100.13")
	// One port every 30 s: 15 ports in 7 minutes.
	var found bool
	for p := 0; p < 15; p++ {
		if _, ok := only(a.Observe(src, uint16(p+1), start.Add(time.Duration(p)*30*time.Second)), "address"); ok {
			found = true
		}
	}
	if !found {
		t.Fatal("slow scanner within 10 minutes not reported")
	}
}

func TestVerySlowProbingIsNotAScan(t *testing.T) {
	a := NewAnalyzer(nil)
	start := time.Now()
	src := net.ParseIP("198.51.100.10")
	// One port a minute: at most 10 within any 10 minutes.
	for p := 0; p < 60; p++ {
		if _, ok := only(a.Observe(src, uint16(p+1), start.Add(time.Duration(p)*time.Minute)), "address"); ok {
			t.Fatalf("very slow probing reported at port %d", p+1)
		}
	}
}

func TestNormalClientIsNotAScan(t *testing.T) {
	a := NewAnalyzer(nil)
	now := time.Now()
	src := net.ParseIP("198.51.100.11")
	for i := 0; i < 1000; i++ {
		port := uint16(443)
		if i%2 == 0 {
			port = 80
		}
		if got := a.Observe(src, port, now); len(got) > 0 {
			t.Fatal("a busy web client is not a scan")
		}
	}
}

// Real traffic seen on the demo server: addresses of one /24 each trying a
// few random ports.
func TestDistributedScanFromOneNetwork(t *testing.T) {
	demo := map[string][]uint16{
		"85.217.140.39": {17176, 41249, 42956, 46803, 55279, 62676},
		"85.217.140.38": {34712, 44048, 52644, 58370, 6756},
		"85.217.140.9":  {22165, 39114, 48974, 51669},
		"85.217.140.51": {20158, 22389, 26572, 32877},
		"85.217.140.50": {16548, 451, 46975, 48578},
		"85.217.140.13": {12018, 29718, 8927},
		"85.217.140.77": {1111, 2222, 3333, 4444, 5555},
	}
	a := NewAnalyzer(nil)
	now := time.Now()
	var net24 Scan
	var found bool
	addrs := []string{"85.217.140.39", "85.217.140.38", "85.217.140.9", "85.217.140.51", "85.217.140.50", "85.217.140.13", "85.217.140.77"}
	for i, ad := range addrs {
		for _, p := range demo[ad] {
			got := a.Observe(net.ParseIP(ad), p, now.Add(time.Duration(i)*10*time.Second))
			if _, ok := only(got, "address"); ok {
				t.Fatalf("%s alone is not an address scan", ad)
			}
			if s, ok := only(got, "network"); ok {
				net24, found = s, true
			}
		}
	}
	if !found {
		t.Fatal("distributed scan not reported")
	}
	if net24.Network != "85.217.140.0/24" || net24.Addresses < NetworkAddresses || net24.Ports < NetworkThreshold {
		t.Fatalf("scan = %+v", net24)
	}
	d := net24.Details()
	if d["scope"] != "network" || d["network"] != "85.217.140.0/24" {
		t.Fatalf("details = %v", d)
	}
}

func TestBusyNetworkOfClientsIsNotAScan(t *testing.T) {
	a := NewAnalyzer(nil)
	now := time.Now()
	for i := 1; i <= 50; i++ {
		ip := net.IPv4(198, 51, 100, byte(i))
		for _, p := range []uint16{80, 443, 443, 80} {
			if got := a.Observe(ip, p, now); len(got) > 0 {
				t.Fatalf("clients of one network browsing reported: %+v", got)
			}
		}
	}
}

func TestTwoAddressesAreNotANetworkScan(t *testing.T) {
	a := NewAnalyzer(nil)
	now := time.Now()
	var scopes []string
	for p := 0; p < 20; p++ {
		for _, ip := range []string{"203.0.113.5", "203.0.113.6"} {
			for _, s := range a.Observe(net.ParseIP(ip), uint16(100+p), now) {
				scopes = append(scopes, s.Scope)
			}
		}
	}
	for _, sc := range scopes {
		if sc == "network" {
			t.Fatal("two addresses reported as a network scan")
		}
	}
	if len(scopes) != 2 {
		t.Fatalf("want 2 address scans, got %v", scopes)
	}
}

func TestIPv6NetworkIsSlash64(t *testing.T) {
	if got := networkOf(net.ParseIP("2001:db8:1:2:aaaa::1")); got != "2001:db8:1:2::/64" {
		t.Fatalf("got %s", got)
	}
	if got := networkOf(net.ParseIP("85.217.140.39")); got != "85.217.140.0/24" {
		t.Fatalf("got %s", got)
	}
}

func TestSkippedAddresses(t *testing.T) {
	a := NewAnalyzer(func(ip net.IP) bool { return ip.IsPrivate() })
	now := time.Now()
	for p := 0; p < 100; p++ {
		for i := 1; i < 5; i++ {
			if got := a.Observe(net.IPv4(10, 0, 0, byte(i)), uint16(p), now); len(got) > 0 {
				t.Fatal("skipped address reported")
			}
		}
	}
}

func TestPruneBoundsMemory(t *testing.T) {
	a := NewAnalyzer(nil)
	now := time.Now()
	for i := 0; i < 1000; i++ {
		a.Observe(net.IPv4(198, 51, byte(i/256), byte(i%256)), 22, now)
	}
	a.Prune(now.Add(2 * Window))
	if len(a.sources) != 0 || len(a.networks) != 0 {
		t.Fatalf("%d sources, %d networks left after prune", len(a.sources), len(a.networks))
	}
}

func TestKernelFilter(t *testing.T) {
	vm, err := bpf.NewVM(SYNFilter())
	if err != nil {
		t.Fatal(err)
	}
	udp := ipv4SYN("198.51.100.9", 53, 0x02)
	udp[9] = 17
	frag := ipv4SYN("198.51.100.9", 22, 0x02)
	frag[6], frag[7] = 0x00, 0x10 // fragment offset
	withOptions := append(append([]byte{}, ipv4SYN("198.51.100.9", 22, 0)[:20]...), make([]byte, 8)...)
	withOptions[0] = 0x47 // 28-byte header
	withOptions = append(withOptions, make([]byte, 20)...)
	withOptions[28+13] = 0x02
	cases := []struct {
		name   string
		pkt    []byte
		accept bool
	}{
		{"ipv4 SYN", ipv4SYN("198.51.100.9", 22, 0x02), true},
		{"ipv4 SYN with IP options", withOptions, true},
		{"ipv4 SYN-ACK", ipv4SYN("198.51.100.9", 22, 0x12), false},
		{"ipv4 ACK", ipv4SYN("198.51.100.9", 22, 0x10), false},
		{"ipv4 RST", ipv4SYN("198.51.100.9", 22, 0x04), false},
		{"ipv4 UDP", udp, false},
		{"ipv4 fragment", frag, false},
		{"ipv6 SYN", ipv6SYN("2001:db8::7", 443), true},
	}
	for _, c := range cases {
		n, err := vm.Run(c.pkt)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if (n > 0) != c.accept {
			t.Errorf("%s: accepted=%v, want %v", c.name, n > 0, c.accept)
		}
	}
}
