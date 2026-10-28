package scanwatch

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const tcpHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

// procV4 formats an IPv4 address and port as /proc/net/tcp does.
func procV4(ip string, port uint16) string {
	b := net.ParseIP(ip).To4()
	return fmt.Sprintf("%02X%02X%02X%02X:%04X", b[3], b[2], b[1], b[0], port)
}

func procV6(ip string, port uint16) string {
	b := net.ParseIP(ip).To16()
	var s strings.Builder
	for w := 0; w < 4; w++ {
		o := w * 4
		fmt.Fprintf(&s, "%02X%02X%02X%02X", b[o+3], b[o+2], b[o+1], b[o])
	}
	return fmt.Sprintf("%s:%04X", s.String(), port)
}

type sock struct {
	local, remote string // "ip:port" in /proc form
	state         byte
}

func writeTable(t *testing.T, root, name string, socks []sock) {
	t.Helper()
	var b strings.Builder
	b.WriteString(tcpHeader)
	for i, s := range socks {
		fmt.Fprintf(&b, "%4d: %s %s %02X 00000000:00000000 00:00000000 00000000     0        0 %d 1 0000000000000000 100 0 0 10 0\n",
			i, s.local, s.remote, s.state, 1000+i)
	}
	write(t, root, "proc/net/"+name, b.String())
}

func write(t *testing.T, root, path, content string) {
	t.Helper()
	p := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

const (
	server = "203.0.113.1"
	client = "198.51.100.20"
)

// A cPanel server: Pure-FTPd on 21 with cPanel's passive range, SSH, the web
// server, and a Redis bound to loopback only.
func ftpServer(t *testing.T, extra ...sock) string {
	t.Helper()
	root := t.TempDir()
	write(t, root, "var/cpanel/conf/pureftpd/main", "---\nAnonymousCantUpload: 'yes'\nPassivePortRange: 49152 65534\nMaxClientsNumber: 50\n")
	socks := []sock{
		{procV4("0.0.0.0", 21), procV4("0.0.0.0", 0), tcpListen},
		{procV4("0.0.0.0", 22), procV4("0.0.0.0", 0), tcpListen},
		{procV4("0.0.0.0", 443), procV4("0.0.0.0", 0), tcpListen},
		{procV4("127.0.0.1", 6379), procV4("0.0.0.0", 0), tcpListen},
	}
	writeTable(t, root, "tcp", append(socks, extra...))
	writeTable(t, root, "tcp6", []sock{{procV6("::", 80), procV6("::", 0), tcpListen}})
	return root
}

// session feeds the attempts of src to ports through Local and the analyzer,
// as the watcher does, and returns the address scans reported.
func session(l *Local, src string, ports []uint16, start time.Time) []Scan {
	a := NewAnalyzer(nil)
	addr := netip.MustParseAddr(src)
	var out []Scan
	now := start
	for _, p := range ports {
		now = now.Add(3 * time.Second)
		l.Add(addr, p, now)
		for _, at := range l.Due(now.Add(2 * time.Second)) {
			for _, s := range a.Observe(net.IP(at.src.AsSlice()), at.port, at.at) {
				if s.Scope == "address" {
					out = append(out, s)
				}
			}
		}
	}
	return out
}

// The ports of the event that banned a FileZilla user on a cPanel server.
var filezilla = []uint16{21, 49535, 51508, 51572, 54587, 54988, 58066, 59087, 61318, 61321, 61894,
	62373, 63959, 64528, 64726, 50001, 50002, 50003, 50004, 50005, 50006, 50007, 50008, 50009, 50010}

func TestPassiveFTPSessionIsNotAScan(t *testing.T) {
	// The control connection is open; every passive listener is gone by
	// the time the table is read (uploads end before it).
	root := ftpServer(t, sock{procV4(server, 21), procV4(client, 51000), 0x01})
	if got := session(NewLocal(root), client, filezilla, time.Now()); len(got) > 0 {
		t.Fatalf("passive FTP session reported: %+v", got)
	}
}

func TestPassiveFTPAfterControlClosed(t *testing.T) {
	// The control connection is seen once, then closes: its data
	// connections within the window still don't count.
	root := ftpServer(t, sock{procV4(server, 21), procV4(client, 51000), 0x01})
	l := NewLocal(root)
	start := time.Now()
	if got := session(l, client, filezilla[:3], start); len(got) > 0 {
		t.Fatal(got)
	}
	writeTable(t, root, "tcp", []sock{{procV4("0.0.0.0", 21), procV4("0.0.0.0", 0), tcpListen}})
	if got := session(l, client, filezilla[3:], start.Add(10*time.Second)); len(got) > 0 {
		t.Fatalf("reported after the control connection closed: %+v", got)
	}
}

func TestFTPClientSweepingOtherPortsIsAScan(t *testing.T) {
	// Logged in on 21, then trying 20 low ports: those are not data ports.
	root := ftpServer(t, sock{procV4(server, 21), procV4(client, 51000), 0x01})
	ports := []uint16{21}
	for p := uint16(1000); p < 1020; p++ {
		ports = append(ports, p)
	}
	got := session(NewLocal(root), client, ports, time.Now())
	if len(got) != 1 || got[0].Ports != Threshold {
		t.Fatalf("scan from an FTP client not reported: %+v", got)
	}
	for _, p := range got[0].Sample {
		if p == 21 {
			t.Fatal("the open FTP port counted")
		}
	}
}

func TestFTPHalfOpenControlIsNotAnFTPClient(t *testing.T) {
	// A SYN scan of 21 leaves only a half-open connection: the passive
	// range then counts like any other port.
	root := ftpServer(t, sock{procV4(server, 21), procV4(client, 51000), tcpSynRecv})
	if got := session(NewLocal(root), client, filezilla, time.Now()); len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
}

func TestPassivePortsWithoutControlConnectionCount(t *testing.T) {
	root := ftpServer(t)
	got := session(NewLocal(root), client, filezilla[1:], time.Now())
	if len(got) != 1 || got[0].Ports != Threshold {
		t.Fatalf("passive-range sweep without an FTP connection not reported: %+v", got)
	}
}

func TestOpenPortsNeverCount(t *testing.T) {
	// Open services (and a closed loopback-only one): 22, 80 (IPv6
	// wildcard), 443 and 21 never count; 6379 listens on loopback only, so
	// from outside it is closed and counts.
	root := ftpServer(t)
	l := NewLocal(root)
	a := NewAnalyzer(nil)
	src := netip.MustParseAddr(client)
	now := time.Now()
	var counted []uint16
	for i := 0; i < 50; i++ {
		for _, p := range []uint16{21, 22, 80, 443, 6379} {
			l.Add(src, p, now)
		}
		now = now.Add(2 * time.Second)
		for _, at := range l.Due(now) {
			counted = append(counted, at.port)
			a.Observe(net.IP(at.src.AsSlice()), at.port, at.at)
		}
	}
	for _, p := range counted {
		if p != 6379 {
			t.Fatalf("open port %d counted", p)
		}
	}
	if len(counted) == 0 {
		t.Fatal("loopback-only port not counted")
	}
}

func TestAcceptedConnectionMeansOpenPort(t *testing.T) {
	// No FTP configured, but each port the client tried has a connection
	// from it in the table (a listener that accepted and closed): open.
	root := t.TempDir()
	var socks []sock
	var ports []uint16
	for p := uint16(40000); p < 40030; p++ {
		ports = append(ports, p)
		socks = append(socks, sock{procV4(server, p), procV4(client, 50000+p%1000), 0x06}) // TIME_WAIT
	}
	writeTable(t, root, "tcp", socks)
	if got := session(NewLocal(root), client, ports, time.Now()); len(got) > 0 {
		t.Fatalf("accepted connections counted: %+v", got)
	}
	// Another address trying the same ports was not answered.
	if got := session(NewLocal(root), "198.51.100.77", ports, time.Now()); len(got) != 1 {
		t.Fatalf("other address: %+v", got)
	}
}

func TestOutgoingConnectionIsNotAccepted(t *testing.T) {
	root := t.TempDir()
	var socks []sock
	var ports []uint16
	for p := uint16(40000); p < 40020; p++ {
		ports = append(ports, p)
		socks = append(socks, sock{procV4(server, p), procV4(client, 443), tcpSynSent})
	}
	writeTable(t, root, "tcp", socks)
	if got := session(NewLocal(root), client, ports, time.Now()); len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
}

func TestIPv6FTPClient(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/vsftpd.conf", "listen_ipv6=YES\npasv_min_port=40000\npasv_max_port=40100\n")
	writeTable(t, root, "tcp", nil)
	writeTable(t, root, "tcp6", []sock{
		{procV6("::", 21), procV6("::", 0), tcpListen},
		{procV6("2001:db8::1", 21), procV6("2001:db8:5::9", 50123), 0x01},
	})
	var ports []uint16
	for p := uint16(40000); p < 40040; p++ {
		ports = append(ports, p)
	}
	if got := session(NewLocal(root), "2001:db8:5::9", ports, time.Now()); len(got) > 0 {
		t.Fatalf("IPv6 FTP client reported: %+v", got)
	}
}

func TestIPv4MappedFTPClient(t *testing.T) {
	// A dual-stack FTP server shows IPv4 clients as ::ffff:a.b.c.d.
	root := ftpServer(t)
	writeTable(t, root, "tcp6", []sock{
		{procV6("::", 21), procV6("::", 0), tcpListen},
		{procV6("::ffff:"+server, 21), procV6("::ffff:"+client, 50123), 0x01},
	})
	if got := session(NewLocal(root), client, filezilla, time.Now()); len(got) > 0 {
		t.Fatalf("IPv4-mapped FTP client reported: %+v", got)
	}
}

func TestNoTableCountsEverything(t *testing.T) {
	got := session(NewLocal(t.TempDir()), client, filezilla, time.Now())
	if len(got) != 1 {
		t.Fatalf("without /proc every attempt counts: %+v", got)
	}
}

func TestParseProcAddr(t *testing.T) {
	cases := map[string]string{
		procV4("203.0.113.7", 22):          "203.0.113.7:22",
		procV6("2001:db8::7", 443):         "[2001:db8::7]:443",
		procV6("::ffff:198.51.100.2", 990): "198.51.100.2:990",
	}
	for in, want := range cases {
		a, p, ok := parseProcAddr([]byte(in))
		if !ok || netip.AddrPortFrom(a, p).String() != want {
			t.Errorf("%s: got %v %d %v, want %s", in, a, p, ok, want)
		}
	}
	for _, bad := range []string{"", "0100007F", "0100007F:", "0100007G:0016", "0100007F-0016"} {
		if _, _, ok := parseProcAddr([]byte(bad)); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestFTPConfigPureFTPd(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/pure-ftpd.conf", "# comment\nChrootEveryone yes\nPassivePortRange   30000 35000   # data ports\nBind 0.0.0.0,2121\n")
	c := LoadFTPConfig(root)
	if len(c.Passive) != 1 || c.Passive[0] != (portRange{30000, 35000}) {
		t.Fatalf("passive = %v", c.Passive)
	}
	if !c.Control[21] || !c.Control[990] || !c.Control[2121] {
		t.Fatalf("control = %v", c.Control)
	}
}

func TestFTPConfigCPanel(t *testing.T) {
	root := t.TempDir()
	write(t, root, "var/cpanel/conf/pureftpd/main", "---\nPassivePortRange: '49152 65534'\n")
	c := LoadFTPConfig(root)
	if len(c.Passive) != 1 || c.Passive[0] != (portRange{49152, 65534}) || c.Sources[0] != "/var/cpanel/conf/pureftpd/main" {
		t.Fatalf("cPanel: %+v", c)
	}
}

func TestFTPConfigDebianPureFTPd(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/pure-ftpd/conf/PassivePortRange", "40000 40100\n")
	write(t, root, "etc/pure-ftpd/conf/Bind", ",2100\n")
	c := LoadFTPConfig(root)
	if len(c.Passive) != 1 || c.Passive[0] != (portRange{40000, 40100}) || !c.Control[2100] {
		t.Fatalf("debian: %+v", c)
	}
}

func TestFTPConfigProFTPD(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/proftpd/proftpd.conf", "ServerName \"x\"\nPort 2221\nInclude /etc/proftpd/conf.d/\n# PassivePorts 1 2\n")
	write(t, root, "etc/proftpd/conf.d/passive.conf", "<Global>\n  PassivePorts 50000 51000\n</Global>\n")
	c := LoadFTPConfig(root)
	if len(c.Passive) != 1 || c.Passive[0] != (portRange{50000, 51000}) || !c.Control[2221] {
		t.Fatalf("proftpd: %+v", c)
	}
	if c.Sources[0] != "/etc/proftpd/conf.d/passive.conf" {
		t.Fatalf("source = %v", c.Sources)
	}
}

func TestFTPConfigVsftpd(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/vsftpd/vsftpd.conf", "listen=YES\npasv_enable=YES\npasv_min_port=10000\npasv_max_port=10100\nlisten_port=2021\n")
	c := LoadFTPConfig(root)
	if len(c.Passive) != 1 || c.Passive[0] != (portRange{10000, 10100}) || !c.Control[2021] {
		t.Fatalf("vsftpd: %+v", c)
	}
	// Only one end set: no configured range.
	write(t, root, "etc/vsftpd/vsftpd.conf", "pasv_min_port=10000\n")
	if c := LoadFTPConfig(root); len(c.Passive) != 0 {
		t.Fatalf("half range: %v", c.Passive)
	}
}

func TestFTPConfigRangeLimits(t *testing.T) {
	root := t.TempDir()
	// A range down to port 1 would hide scans of the well-known ports.
	write(t, root, "etc/pure-ftpd.conf", "PassivePortRange 1 65535\n")
	write(t, root, "etc/vsftpd.conf", "pasv_min_port=6000\npasv_max_port=5000\n")
	c := LoadFTPConfig(root)
	if len(c.Passive) != 1 || c.Passive[0] != (portRange{minPassivePort, 65535}) {
		t.Fatalf("limits: %v", c.Passive)
	}
}

func TestFTPFallbackRange(t *testing.T) {
	root := t.TempDir()
	c := LoadFTPConfig(root)
	if r := c.passiveRanges(false); r != nil {
		t.Fatalf("no FTP server listening, no range: %v", r)
	}
	if r := c.passiveRanges(true); len(r) != 1 || r[0] != (portRange{49152, 65534}) {
		t.Fatalf("fallback: %v", r)
	}
	write(t, root, "proc/sys/net/ipv4/ip_local_port_range", "32768\t60999\n")
	c = LoadFTPConfig(root)
	if r := c.passiveRanges(true); len(r) != 1 || r[0] != (portRange{32768, 65534}) {
		t.Fatalf("fallback with the ephemeral range: %v", r)
	}
	// A configured range replaces the fallback.
	write(t, root, "etc/vsftpd.conf", "pasv_min_port=40000\npasv_max_port=40100\n")
	if r := LoadFTPConfig(root).passiveRanges(true); len(r) != 1 || r[0] != (portRange{40000, 40100}) {
		t.Fatalf("configured: %v", r)
	}
}

func TestFTPFallbackOnlyWithFTPServer(t *testing.T) {
	// No FTP configuration and nothing on 21: a client holding some
	// connection on 990 does not make 49152+ data ports.
	root := t.TempDir()
	socks := []sock{{procV4(server, 990), procV4(client, 50000), 0x01}}
	var ports []uint16
	for p := uint16(50000); p < 50020; p++ {
		ports = append(ports, p)
	}
	writeTable(t, root, "tcp", socks)
	if got := session(NewLocal(root), client, ports, time.Now()); len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
	// With an FTP server listening on 21, the default range applies.
	writeTable(t, root, "tcp", append(socks, sock{procV4("0.0.0.0", 21), procV4("0.0.0.0", 0), tcpListen}))
	if got := session(NewLocal(root), client, ports, time.Now()); len(got) > 0 {
		t.Fatalf("fallback range: %+v", got)
	}
}

func TestFTPConfigIgnoresSFTPPort(t *testing.T) {
	// mod_sftp's Port is SSH, not an FTP control port; nor is 22 anywhere.
	root := t.TempDir()
	write(t, root, "etc/proftpd.conf", "Port 21\n<IfModule mod_sftp.c>\n  <IfModule mod_ban.c>\n  </IfModule>\n  Port 2222\n</IfModule>\nPassivePorts 50000 51000\n")
	write(t, root, "etc/vsftpd.conf", "listen_port=22\n")
	c := LoadFTPConfig(root)
	if c.Control[2222] || c.Control[22] || len(c.Passive) != 1 {
		t.Fatalf("control = %v passive = %v", c.Control, c.Passive)
	}
}

func TestFTPConfigNotARegularFile(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc/vsftpd.conf"), 0o755); err != nil {
		t.Fatal(err)
	}
	if c := LoadFTPConfig(root); len(c.Passive) != 0 {
		t.Fatal(c.Passive)
	}
}

func TestBrokenTableFailsTheRead(t *testing.T) {
	// A line too long for the reader: the whole read fails, so nothing is
	// taken as closed by mistake.
	root := ftpServer(t)
	write(t, root, "proc/net/tcp6", tcpHeader+strings.Repeat("x", 70<<10)+"\n")
	if _, err := readSockets(root, nil, nil); err == nil {
		t.Fatal("partial read accepted")
	}
}
