package lan

import (
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestInventory(t *testing.T) {
	dir := t.TempDir()
	inv := NewInventory([]byte("0123456789abcdef0123456789abcdef"))
	inv.Leases = filepath.Join(dir, "leases")
	inv.ARP = filepath.Join(dir, "arp")
	inv.ODHCPD = filepath.Join(dir, "odhcpd")
	inv.Now = func() time.Time { return time.Unix(1_000_000, 0) }
	os.WriteFile(inv.Leases, []byte("1731700000 a4:83:e7:11:22:33 192.168.1.23 Lauras-iPhone 01:a4:83:e7:11:22:33\n1731700000 da:a1:19:00:00:01 192.168.1.24 * *\n"), 0o644)
	os.WriteFile(inv.ARP, []byte("IP address       HW type     Flags       HW address            Mask     Device\n192.168.1.50     0x1         0x2         00:11:32:aa:bb:cc     *        br-lan\n192.168.1.51     0x1         0x0         00:00:00:00:00:00     *        br-lan\n"), 0o644)
	os.WriteFile(inv.ODHCPD, []byte("# br-lan 0001 1 Lauras-iPhone 1731700000 ab 128 fd00::23/128\n"), 0o644)
	inv.Refresh()
	if inv.Len() != 3 {
		t.Fatalf("devices = %d: %+v", inv.Len(), inv.List())
	}
	d, ok := inv.Lookup(netip.MustParseAddr("192.168.1.23"))
	if !ok || d.Name != "Lauras-iPhone" || d.OUI != "A4:83:E7" || d.Random || len(d.Key) != 16 || strings.Contains(d.Key, "a4") && d.Key == "a483e7112233" {
		t.Errorf("device = %+v", d)
	}
	if d.Key != inv.KeyFor("A4:83:E7:11:22:33") {
		t.Error("key depends on MAC case")
	}
	if d6, ok := inv.Lookup(netip.MustParseAddr("fd00::23")); !ok || d6.Key != d.Key {
		t.Errorf("ipv6 lookup = %+v %v", d6, ok)
	}
	r, _ := inv.Lookup(netip.MustParseAddr("192.168.1.24"))
	if !r.Random || r.OUI != "" {
		t.Errorf("randomized = %+v", r)
	}
	u, ok := inv.Lookup(netip.MustParseAddr("192.168.1.99"))
	if ok || u.Key == "" || u.Key != inv.KeyForIP(netip.MustParseAddr("192.168.1.99")) {
		t.Errorf("unknown = %+v %v", u, ok)
	}
	other := NewInventory([]byte("another secret, another router.."))
	if other.KeyFor("a4:83:e7:11:22:33") == d.Key {
		t.Error("key does not depend on the secret")
	}
}

func TestLoadSecret(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "device-key")
	a, err := LoadSecret(p)
	if err != nil || len(a) != 32 {
		t.Fatal(a, err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode())
	}
	b, _ := LoadSecret(p)
	if string(a) != string(b) {
		t.Error("secret changed")
	}
}

func TestConntrack(t *testing.T) {
	var b strings.Builder
	line := func(src, dst string, dport int) {
		b.WriteString("ipv4     2 tcp      6 431999 ESTABLISHED src=" + src + " dst=" + dst + " sport=50000 dport=" + itoa(dport) + " packets=3 bytes=180 src=" + dst + " dst=" + src + " sport=" + itoa(dport) + " dport=50000 [ASSURED] mark=0 zone=0 use=2\n")
	}
	line("192.168.1.10", "203.0.113.9", 3333)
	line("192.168.1.10", "203.0.113.9", 443)
	for i := 0; i < 130; i++ {
		line("192.168.1.11", "198.51.100."+itoa(i), 23)
	}
	for i := 0; i < 25; i++ {
		line("192.168.1.12", "198.51.100."+itoa(i), 25)
	}
	for i := 0; i < 200; i++ {
		line("192.168.1.13", "198.51.100."+itoa(i), 443)
	}
	line("192.168.1.14", "192.168.1.1", 3333) // to the LAN: ignored
	b.WriteString("garbage\n")
	isLAN := func(a netip.Addr) bool { return netip.MustParsePrefix("192.168.1.0/24").Contains(a) }
	fs, total, err := scanConntrack(strings.NewReader(b.String()), isLAN)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2+130+25+200+1+1 {
		t.Errorf("total = %d", total)
	}
	got := map[string]Finding{}
	for _, f := range fs {
		got[f.Kind+"@"+f.Device.String()] = f
	}
	if len(got) != 3 {
		t.Fatalf("findings = %+v", fs)
	}
	if f := got[FindMinerPort+"@192.168.1.10"]; f.Port != 3333 || f.Example.String() != "203.0.113.9" {
		t.Errorf("miner = %+v", f)
	}
	if f := got[FindFanOut+"@192.168.1.11"]; f.Count != 130 || f.Port != 23 {
		t.Errorf("fan-out = %+v", f)
	}
	if f := got[FindSMTP+"@192.168.1.12"]; f.Count != 25 {
		t.Errorf("smtp = %+v", f)
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

func TestParseIPPacket(t *testing.T) {
	// A response for evil.example.com A 203.0.113.5 from 192.168.1.1:53 to 192.168.1.23:40000.
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, Response: true, RCode: dnsmessage.RCodeSuccess})
	b.StartQuestions()
	name := dnsmessage.MustNewName("Evil.Example.com.")
	b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	b.StartAnswers()
	b.AResource(dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: [4]byte{203, 0, 113, 5}})
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	pkt := ipv4UDP([4]byte{192, 168, 1, 1}, [4]byte{192, 168, 1, 23}, 53, 40000, msg)
	p, ok := ParseIPPacket(pkt)
	if !ok || !p.Response || p.Name != "evil.example.com" || len(p.Answers) != 1 || p.Answers[0].String() != "203.0.113.5" || p.SrcPort != 53 || p.Dst.String() != "192.168.1.23" {
		t.Errorf("packet = %+v ok=%v", p, ok)
	}
	if _, ok := ParseIPPacket(pkt[:30]); ok {
		t.Error("truncated accepted")
	}
	if _, ok := ParseIPPacket([]byte{0x45}); ok {
		t.Error("garbage accepted")
	}
}

func ipv4UDP(src, dst [4]byte, sport, dport uint16, payload []byte) []byte {
	l := 20 + 8 + len(payload)
	b := make([]byte, l)
	b[0] = 0x45
	b[2], b[3] = byte(l>>8), byte(l)
	b[8] = 64
	b[9] = 17
	copy(b[12:16], src[:])
	copy(b[16:20], dst[:])
	u := b[20:]
	u[0], u[1] = byte(sport>>8), byte(sport)
	u[2], u[3] = byte(dport>>8), byte(dport)
	ul := 8 + len(payload)
	u[4], u[5] = byte(ul>>8), byte(ul)
	copy(u[8:], payload)
	return b
}

func TestRandomLooking(t *testing.T) {
	for _, n := range []string{"xkqjzvbwpfhd.com", "a.qwxzkjvbnmpl.net"} {
		if !RandomLooking(n) {
			t.Errorf("%s not random", n)
		}
	}
	for _, n := range []string{"weatherforecast.com", "short.com", "xkqjzvbwpfhd.amazonaws.com", "printer.lan"} {
		if RandomLooking(n) {
			t.Errorf("%s random", n)
		}
	}
	if BaseDomain("a.b.evil.co.uk") != "evil.co.uk" || BaseDomain("x.example.com") != "example.com" {
		t.Error("BaseDomain")
	}
}
