package dnswatch

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/monitor"
)

// ── test helpers ─────────────────────────────────────────────────────

func encName(name string) []byte {
	var b []byte
	for _, l := range strings.Split(name, ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0)
}

// dnsQuery builds a query for name/qtype.
func dnsQuery(name string, qtype uint16) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[0:2], 0x1234)
	binary.BigEndian.PutUint16(b[2:4], 0x0100) // RD
	binary.BigEndian.PutUint16(b[4:6], 1)
	b = append(b, encName(name)...)
	return binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(b, qtype), 1)
}

// dnsResponse answers name with A records (compressed name pointers) or
// NXDOMAIN when ips is empty and nx is true.
func dnsResponse(name string, nx bool, ips ...string) []byte {
	b := make([]byte, 12)
	flags := uint16(0x8180)
	if nx {
		flags |= rcodeNX
	}
	binary.BigEndian.PutUint16(b[2:4], flags)
	binary.BigEndian.PutUint16(b[4:6], 1)
	binary.BigEndian.PutUint16(b[6:8], uint16(len(ips)))
	b = append(b, encName(name)...)
	b = binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(b, typeA), 1)
	for _, ip := range ips {
		b = append(b, 0xc0, 12) // pointer to the question name
		b = binary.BigEndian.AppendUint16(b, typeA)
		b = binary.BigEndian.AppendUint16(b, 1)
		b = binary.BigEndian.AppendUint32(b, 60)
		b = binary.BigEndian.AppendUint16(b, 4)
		b = append(b, net.ParseIP(ip).To4()...)
	}
	return b
}

func query(src string, sport uint16, dst, name string) Packet {
	return Packet{Src: net.ParseIP(src), Dst: net.ParseIP(dst), SrcPort: sport, DstPort: 53, Payload: dnsQuery(name, typeA), Outgoing: true}
}

func answer(resolver, host string, dport uint16, payload []byte) Packet {
	return Packet{Src: net.ParseIP(resolver), Dst: net.ParseIP(host), SrcPort: 53, DstPort: dport, Payload: payload}
}

// randomLabel makes a DGA-like label of n random lower-case letters.
func randomLabel(seed uint64, n int) string {
	b := make([]byte, n)
	x := seed*0x9e3779b97f4a7c15 + 1
	for i := range b {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		b[i] = byte('a' + x%26)
	}
	return string(b)
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

var (
	appProc      = &monitor.ProcInfo{PID: 4242, Name: "curl", Exe: "/usr/bin/curl", User: "www-data"}
	unboundProc  = &monitor.ProcInfo{PID: 700, Name: "unbound", Exe: "/usr/sbin/unbound", User: "unbound"}
	resolvedProc = &monitor.ProcInfo{PID: 500, Name: "systemd-resolve", Exe: "/usr/lib/systemd/systemd-resolved", User: "systemd-resolve"}
)

func newTestAnalyzer(owners map[uint16]*monitor.ProcInfo, threats ...string) (*Analyzer, *fakeClock) {
	clock := &fakeClock{t: time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)}
	bad := map[string]bool{}
	for _, t := range threats {
		bad[t] = true
	}
	return NewAnalyzer(Sources{
		Configured: func() map[string]bool { return map[string]bool{"127.0.0.53": true, "209.126.15.53": true} },
		Threat: func(ip net.IP) (bool, string) {
			if bad[ip.String()] {
				return true, "test-feed"
			}
			return false, ""
		},
		Owner: func(port uint16, v6 bool) *monitor.ProcInfo { return owners[port] },
		Now:   clock.now,
	}), clock
}

func types(ev []api.EventRequest) []string {
	var t []string
	for _, e := range ev {
		t = append(t, e.Type)
	}
	return t
}

// ── parsing ──────────────────────────────────────────────────────────

func TestParseMessage(t *testing.T) {
	m, ok := parseMessage(dnsQuery("Example.COM", typeTXT))
	if !ok || m.Response || m.Name != "example.com" || m.QType != typeTXT {
		t.Errorf("query: %+v %v", m, ok)
	}
	m, ok = parseMessage(dnsResponse("example.org", false, "93.184.216.34", "93.184.216.35"))
	if !ok || !m.Response || m.Name != "example.org" || len(m.Answers) != 2 || m.Answers[1].String() != "93.184.216.35" {
		t.Errorf("response: %+v %v", m, ok)
	}
	m, _ = parseMessage(dnsResponse("nope.example", true))
	if m.RCode != rcodeNX {
		t.Errorf("nxdomain rcode = %d", m.RCode)
	}
}

func TestParseMessageRejectsMalformed(t *testing.T) {
	full := dnsResponse("example.org", false, "1.2.3.4")
	for i := 0; i < len(full); i++ { // every truncation
		parseMessage(full[:i]) // must not panic
	}
	loop := dnsQuery("a.b", typeA)
	loop[12] = 0xc0 // name is a pointer to itself
	loop[13] = 12
	if _, ok := parseMessage(loop); ok {
		t.Error("pointer loop accepted")
	}
	long := dnsQuery(strings.Repeat("a", 63)+"."+strings.Repeat("b", 63)+"."+strings.Repeat("c", 63)+"."+strings.Repeat("d", 63)+".com", typeA)
	if _, ok := parseMessage(long); ok {
		t.Error("name over 255 bytes accepted")
	}
}

func TestParseIP(t *testing.T) {
	payload := dnsQuery("example.com", typeA)
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], 40000)
	binary.BigEndian.PutUint16(udp[2:4], 53)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	udp = append(udp, payload...)

	v4 := make([]byte, 20)
	v4[0], v4[9] = 0x45, 17
	copy(v4[12:16], net.ParseIP("10.0.0.5").To4())
	copy(v4[16:20], net.ParseIP("1.1.1.1").To4())
	p, ok := parseIP(append(v4, udp...))
	if !ok || p.Src.String() != "10.0.0.5" || p.Dst.String() != "1.1.1.1" || p.SrcPort != 40000 || p.DstPort != 53 || len(p.Payload) != len(payload) {
		t.Errorf("v4: %+v %v", p, ok)
	}
	frag := append([]byte(nil), v4...)
	frag[6] = 0x20 // more fragments
	if _, ok := parseIP(append(frag, udp...)); ok {
		t.Error("fragment accepted")
	}

	v6 := make([]byte, 40)
	v6[0], v6[6] = 0x60, 17
	copy(v6[8:24], net.ParseIP("2001:db8::5"))
	copy(v6[24:40], net.ParseIP("2606:4700::1111"))
	if p, ok := parseIP(append(v6, udp...)); !ok || p.Dst.String() != "2606:4700::1111" {
		t.Errorf("v6: %+v %v", p, ok)
	}
}

func TestSplitBase(t *testing.T) {
	for name, want := range map[string][2]string{
		"www.example.com":    {"example.com", "www"},
		"a1b2.c3.evil.co.uk": {"evil.co.uk", "a1b2.c3"},
		"example.com":        {"example.com", ""},
		"x.y.example.com.br": {"example.com.br", "x.y"},
		"deep.sub.domain.io": {"domain.io", "deep.sub"},
	} {
		b, s := splitBase(name)
		if b != want[0] || s != want[1] {
			t.Errorf("splitBase(%q) = %q, %q", name, b, s)
		}
	}
}

// ── analysis ─────────────────────────────────────────────────────────

func TestConfiguredResolverIsQuiet(t *testing.T) {
	a, _ := newTestAnalyzer(map[uint16]*monitor.ProcInfo{40000: resolvedProc})
	if ev := a.Handle(query("10.0.0.5", 40000, "209.126.15.53", "example.com")); len(ev) != 0 {
		t.Errorf("configured resolver reported: %v", types(ev))
	}
}

func TestUnlistedResolverWithProcess(t *testing.T) {
	a, _ := newTestAnalyzer(map[uint16]*monitor.ProcInfo{40001: appProc})
	ev := a.Handle(query("10.0.0.5", 40001, "1.1.1.1", "example.org"))
	if len(ev) != 1 || ev[0].Type != "dns_unlisted_resolver" {
		t.Fatalf("got %v", types(ev))
	}
	d := ev[0].Details
	if d["process"] != "curl" || d["exe"] != "/usr/bin/curl" || d["user"] != "www-data" || d["domain"] != "example.org" || d["resolver"] != "1.1.1.1" {
		t.Errorf("details: %+v", d)
	}
	if ev := a.Handle(query("10.0.0.5", 40001, "1.1.1.1", "example.net")); len(ev) != 0 {
		t.Error("same process and resolver reported again within the cooldown")
	}
}

func TestSystemResolverRecursionIsQuiet(t *testing.T) {
	a, _ := newTestAnalyzer(map[uint16]*monitor.ProcInfo{40002: unboundProc})
	for _, root := range []string{"198.41.0.4", "199.9.14.201", "192.33.4.12"} {
		if ev := a.Handle(query("10.0.0.5", 40002, root, "example.com")); len(ev) != 0 {
			t.Errorf("unbound's recursion reported: %v", types(ev))
		}
	}
}

func TestThreatResolverAndAnswer(t *testing.T) {
	a, _ := newTestAnalyzer(map[uint16]*monitor.ProcInfo{40003: resolvedProc, 40004: appProc}, "203.0.113.66", "198.51.100.9")
	ev := a.Handle(query("10.0.0.5", 40003, "203.0.113.66", "example.com"))
	if len(ev) != 1 || ev[0].Type != "dns_threat_resolver" || ev[0].Severity != "critical" {
		t.Fatalf("threat resolver: %v", types(ev))
	}
	ev = a.Handle(answer("209.126.15.53", "10.0.0.5", 40004, dnsResponse("bad.example", false, "198.51.100.9")))
	if len(ev) != 1 || ev[0].Type != "dns_threat_answer" || ev[0].Details["resolved_ip"] != "198.51.100.9" || ev[0].Details["process"] != "curl" {
		t.Fatalf("threat answer: %+v", ev)
	}
}

func TestTunneling(t *testing.T) {
	a, clock := newTestAnalyzer(map[uint16]*monitor.ProcInfo{40005: appProc})
	var got []api.EventRequest
	for i := 0; i < 80; i++ {
		clock.t = clock.t.Add(time.Second)
		label := fmt.Sprintf("%x", uint64(i)*0x9e3779b97f4a7c15) + fmt.Sprintf("%x", uint64(i+7)*0xbf58476d1ce4e5b9)
		got = append(got, a.Handle(query("10.0.0.5", 40005, "209.126.15.53", label+".t.exfil-example.net"))...)
	}
	if len(got) != 1 || got[0].Type != "dns_tunneling" || got[0].Details["base_domain"] != "exfil-example.net" {
		t.Fatalf("tunneling: %+v", got)
	}
	// Antivirus hash lookups look the same but are legitimate.
	b, _ := newTestAnalyzer(nil)
	for i := 0; i < 80; i++ {
		if ev := b.Handle(query("10.0.0.5", 40006, "209.126.15.53", fmt.Sprintf("%032x.v1.sophosxl.net", i*7919))); len(ev) != 0 {
			t.Fatalf("allowlisted service reported: %v", types(ev))
		}
	}
	// Ordinary browsing: many subdomains, short.
	c, _ := newTestAnalyzer(nil)
	for i := 0; i < 200; i++ {
		if ev := c.Handle(query("10.0.0.5", 40007, "209.126.15.53", fmt.Sprintf("img%d.cdn.example.com", i))); len(ev) != 0 {
			t.Fatalf("short subdomains reported: %v", types(ev))
		}
	}
}

func TestDGA(t *testing.T) {
	a, _ := newTestAnalyzer(map[uint16]*monitor.ProcInfo{40008: appProc})
	var got []api.EventRequest
	for i := 0; i < 40; i++ {
		name := randomLabel(uint64(i+1), 15) + ".com"
		got = append(got, a.Handle(answer("209.126.15.53", "10.0.0.5", 40008, dnsResponse(name, true)))...)
	}
	if len(got) != 1 || got[0].Type != "dns_dga" || got[0].Details["process"] != "curl" {
		t.Fatalf("dga: %+v", got)
	}
	// Long real words that don't exist as domains: not random-looking.
	w, _ := newTestAnalyzer(nil)
	for _, n := range []string{"stackoverflowx", "microsoftonlinex", "exampledomainx", "cloudflaretestx", "wikipediaarchive", "facebookmessenger", "internationalbank", "photographystudio", "restaurantguide", "universityportal", "developmentserver", "productioncluster", "accountingoffice", "weatherforecastx", "marketingagencyx", "insurancebrokers", "constructionsite", "hospitalnetwork", "architecturefirm", "entertainmentnews", "educationcenter", "technologyblog"} {
		if ev := w.Handle(answer("209.126.15.53", "10.0.0.5", 40011, dnsResponse(n+".com", true))); len(ev) != 0 {
			t.Fatalf("real words reported as DGA: %v", types(ev))
		}
	}
	// Typos and dead links: a few short non-existent names.
	b, _ := newTestAnalyzer(nil)
	for _, n := range []string{"gogle.com", "exampel.org", "old-site.net", "wwww.example.com"} {
		if ev := b.Handle(answer("209.126.15.53", "10.0.0.5", 40009, dnsResponse(n, true))); len(ev) != 0 {
			t.Fatalf("typo reported: %v", types(ev))
		}
	}
}

func TestInboundQueriesToOurDNSServerAreIgnored(t *testing.T) {
	a, _ := newTestAnalyzer(nil)
	p := query("203.0.113.7", 5555, "10.0.0.5", strings.Repeat("a", 30)+".example.com")
	p.Outgoing = false // someone asking this server
	if ev := a.Handle(p); len(ev) != 0 {
		t.Errorf("inbound query analyzed: %v", types(ev))
	}
}

func TestStubQueryAttributedToTheApp(t *testing.T) {
	// The app asks systemd-resolved (127.0.0.53); the resolver forwards
	// upstream from its own port. Events are attributed to the app.
	a, _ := newTestAnalyzer(map[uint16]*monitor.ProcInfo{41000: appProc, 42000: resolvedProc}, "198.51.100.9")
	a.Handle(query("127.0.0.1", 41000, "127.0.0.53", "bad.example"))
	ev := a.Handle(answer("209.126.15.53", "10.0.0.5", 42000, dnsResponse("bad.example", false, "198.51.100.9")))
	if len(ev) != 1 || ev[0].Details["process"] != "curl" {
		t.Fatalf("attribution: %+v", ev)
	}
}

func TestUnknownProcessIsSaid(t *testing.T) {
	a, _ := newTestAnalyzer(nil)
	ev := a.Handle(query("10.0.0.5", 40010, "1.1.1.1", "example.org"))
	if len(ev) != 1 || ev[0].Details["process"] != "unknown" || ev[0].Details["process_note"] == "" {
		t.Fatalf("got %+v", ev)
	}
}
