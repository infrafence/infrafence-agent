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

func TestScanDetectedAtThreshold(t *testing.T) {
	a := NewAnalyzer(nil)
	now := time.Now()
	src := net.ParseIP("198.51.100.9")
	for p := 0; p < Threshold-1; p++ {
		if _, ok := a.Observe(src, uint16(1000+p), now); ok {
			t.Fatalf("reported after %d ports", p+1)
		}
	}
	// Repeating a port doesn't count twice.
	if _, ok := a.Observe(src, 1000, now); ok {
		t.Fatal("a repeated port counted")
	}
	s, ok := a.Observe(src, 2000, now)
	if !ok || s.Ports != Threshold || s.IP != "198.51.100.9" || len(s.Sample) != Threshold {
		t.Fatalf("scan = %+v ok=%v", s, ok)
	}
	if d := s.Details(); d["ports_scanned"] != "15" || d["detection"] != "syn" {
		t.Fatalf("details = %v", d)
	}
	// Cooldown: the same source isn't reported again right away.
	for p := 0; p < 50; p++ {
		if _, ok := a.Observe(src, uint16(3000+p), now.Add(time.Minute)); ok {
			t.Fatal("reported again within the cooldown")
		}
	}
	// After the cooldown it is.
	later := now.Add(Cooldown + time.Minute)
	var again bool
	for p := 0; p < Threshold; p++ {
		if _, ok := a.Observe(src, uint16(5000+p), later); ok {
			again = true
		}
	}
	if !again {
		t.Fatal("not reported after the cooldown")
	}
}

func TestSlowProbingIsNotAScan(t *testing.T) {
	a := NewAnalyzer(nil)
	start := time.Now()
	src := net.ParseIP("198.51.100.10")
	// One port every 10 s: never 15 within 60 s.
	for p := 0; p < 40; p++ {
		if _, ok := a.Observe(src, uint16(p+1), start.Add(time.Duration(p)*10*time.Second)); ok {
			t.Fatalf("slow probing reported at port %d", p+1)
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
		if _, ok := a.Observe(src, port, now); ok {
			t.Fatal("a busy web client is not a scan")
		}
	}
}

func TestSkippedAddresses(t *testing.T) {
	a := NewAnalyzer(func(ip net.IP) bool { return ip.IsPrivate() })
	now := time.Now()
	for p := 0; p < 100; p++ {
		if _, ok := a.Observe(net.ParseIP("10.0.0.5"), uint16(p), now); ok {
			t.Fatal("skipped address reported")
		}
	}
}

func TestBurstReportedAtThreshold(t *testing.T) {
	a := NewAnalyzer(nil)
	now := time.Now()
	src := net.ParseIP("198.51.100.12")
	var s Scan
	// Arrives all at once in one burst larger than the threshold: the first
	// report happens at the threshold.
	for p := 0; p < 200; p++ {
		if got, ok := a.Observe(src, uint16(p+1), now); ok {
			s = got
		}
	}
	if s.Ports != Threshold {
		t.Fatalf("scan = %+v", s)
	}
}

func TestPruneBoundsMemory(t *testing.T) {
	a := NewAnalyzer(nil)
	now := time.Now()
	for i := 0; i < 1000; i++ {
		a.Observe(net.IPv4(198, 51, byte(i/256), byte(i%256)), 22, now)
	}
	a.Prune(now.Add(2 * Window))
	if len(a.sources) != 0 {
		t.Fatalf("%d sources left after prune", len(a.sources))
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
