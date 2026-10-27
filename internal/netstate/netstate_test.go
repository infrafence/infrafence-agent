package netstate

import (
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/infrafence/infrafence-agent/internal/monitor"
)

// Lines as the kernel prints them: listener on 0.0.0.0:6379, a public client
// 198.51.100.7 connected to it, a LAN client 10.0.0.5 connected to it, and an
// outbound connection from local port 6379 to 203.0.113.9:443.
const procTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:18EB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0
   1: 0100000A:18EB 076433C6:D431 01 00000000:00000000 00:00000000 00000000     0        0 2 1 0000000000000000 20 4 30 10 -1
   2: 0100000A:18EB 0500000A:D432 01 00000000:00000000 00:00000000 00000000     0        0 3 1 0000000000000000 20 4 30 10 -1
`

// IPv6: listener on [::]:8443 and an IPv4-mapped public client.
const procTCP6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:20FB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4 1 0000000000000000 100 0 0 10 0
   1: 0000000000000000FFFF00000100000A:20FB 0000000000000000FFFF0000096433C6:C350 01 00000000:00000000 00:00000000 00000000     0        0 5 1 0000000000000000 20 4 30 10 -1
`

func fakeProc(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "net/tcp"), []byte(procTCP), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "net/tcp6"), []byte(procTCP6), 0o644)
	old, oldCT := procRoot, conntrackTable
	procRoot = dir
	conntrackTable = func() string { return "" }
	t.Cleanup(func() { procRoot, conntrackTable = old, oldCT })
}

func TestParseAddr(t *testing.T) {
	ip, port, ok := parseAddr("076433C6:D431")
	if !ok || ip.String() != "198.51.100.7" || port != 0xD431 {
		t.Fatalf("got %v %d %v", ip, port, ok)
	}
	ip, _, ok = parseAddr("0000000000000000FFFF0000096433C6:C350")
	if !ok || ip.String() != "198.51.100.9" {
		t.Fatalf("mapped IPv6: got %v %v", ip, ok)
	}
	ip, _, ok = parseAddr("B80D0120000000000000000001000000:0016")
	if !ok || ip.String() != "2001:db8::1" {
		t.Fatalf("IPv6: got %v %v", ip, ok)
	}
}

func TestPublicInbound(t *testing.T) {
	fakeProc(t)
	if got := PublicInbound(6379); !reflect.DeepEqual(got, []string{"198.51.100.7"}) {
		t.Fatalf("6379: %v", got)
	}
	if got := PublicInbound(8443); !reflect.DeepEqual(got, []string{"198.51.100.9"}) {
		t.Fatalf("8443: %v", got)
	}
	if got := PublicInbound(5432); got != nil {
		t.Fatalf("nothing listens on 5432: %v", got)
	}
	if !Listening(6379) || Listening(5432) {
		t.Fatal("Listening")
	}
}

func TestIsPublic(t *testing.T) {
	for ip, want := range map[string]bool{
		"198.51.100.7": true, "8.8.8.8": true, "10.1.2.3": false, "100.64.0.1": false,
		"127.0.0.1": false, "169.254.1.1": false, "0.0.0.0": false, "::1": false, "fd00::1": false,
		"2001:4860:4860::8888": true,
	} {
		if got := IsPublic(net.ParseIP(ip)); got != want {
			t.Errorf("%s: %v, want %v", ip, got, want)
		}
	}
}

func TestSSHPorts(t *testing.T) {
	oldT, oldL, oldS, oldP := sshdT, listeners, sshSocketListen, sshSessionPorts
	sshSocketListen = func() string { return "" }
	sshSessionPorts = func() []int { return nil }
	t.Cleanup(func() {
		sshdT, listeners, sshSocketListen, sshSessionPorts = oldT, oldL, oldS, oldP
		sshMu.Lock()
		sshPorts = nil
		sshMu.Unlock()
	})
	reset := func() { sshMu.Lock(); sshPorts = nil; sshChecked = time.Time{}; sshMu.Unlock() }

	sshdT = func() string { return "port 22\nport 2222\nlistenaddress 0.0.0.0:22\n" }
	listeners = func() []monitor.ListeningService {
		return []monitor.ListeningService{{Port: 2200, Process: "sshd"}, {Port: 80, Process: "nginx"}}
	}
	reset()
	if got := SSHPorts(); !reflect.DeepEqual(got, []int{22, 2200, 2222}) {
		t.Fatalf("got %v", got)
	}

	// Nothing readable: 22 is assumed, never "no SSH port".
	sshdT = func() string { return "" }
	listeners = func() []monitor.ListeningService { return nil }
	reset()
	if got := SSHPorts(); !reflect.DeepEqual(got, []int{22}) {
		t.Fatalf("fallback: got %v", got)
	}
}

func TestWebPorts(t *testing.T) {
	got := WebPortsFrom([]monitor.ListeningService{
		{Port: 443, Process: "docker-proxy"}, {Port: 8080, Process: "httpd"},
		{Port: 6379, Process: "redis-server"}, {Port: 22, Process: "sshd"},
	})
	if !reflect.DeepEqual(got, []int{443, 8080}) {
		t.Fatalf("got %v", got)
	}
}

func TestSSHPortsFromSocketUnitsAndSessions(t *testing.T) {
	oldT, oldL, oldS, oldP := sshdT, listeners, sshSocketListen, sshSessionPorts
	t.Cleanup(func() {
		sshdT, listeners, sshSocketListen, sshSessionPorts = oldT, oldL, oldS, oldP
		sshMu.Lock()
		sshPorts = nil
		sshMu.Unlock()
	})
	sshdT = func() string { return "port 22\n" }
	listeners = func() []monitor.ListeningService { return nil }
	// Socket activation: systemd listens on 2222, sshd -T still says 22.
	sshSocketListen = func() string { return "Listen=[::]:2222 (Stream)\n\nListen=\n" }
	sshSessionPorts = func() []int { return []int{2022} }
	sshMu.Lock()
	sshPorts = nil
	sshMu.Unlock()
	if got := SSHPorts(); !reflect.DeepEqual(got, []int{22, 2022, 2222}) {
		t.Fatalf("got %v", got)
	}
}

func TestParseSocketListen(t *testing.T) {
	out := "Listen=0.0.0.0:2222 (Stream)\nListen=[::]:2223 (Stream)\nListen=22 (Stream)\nListen=\n"
	if got := parseSocketListen(out); !reflect.DeepEqual(got, []int{2222, 2223, 22}) {
		t.Fatalf("got %v", got)
	}
}

// An sshd process holding the established socket of inode 2 (local port
// 6379 in procTCP), and a shell whose SSH_CONNECTION names server port 2022.
func TestSessionPorts(t *testing.T) {
	fakeProc(t)
	root := procRoot
	mk := func(pid, comm, environ string) string {
		dir := filepath.Join(root, pid)
		_ = os.MkdirAll(filepath.Join(dir, "fd"), 0o755)
		_ = os.WriteFile(filepath.Join(dir, "comm"), []byte(comm+"\n"), 0o644)
		_ = os.WriteFile(filepath.Join(dir, "environ"), []byte(environ), 0o644)
		return dir
	}
	d := mk("100", "sshd-session", "")
	if err := os.Symlink("socket:[2]", filepath.Join(d, "fd", "3")); err != nil {
		t.Fatal(err)
	}
	mk("200", "bash", "HOME=/root\x00SSH_CONNECTION=198.51.100.7 51000 192.0.2.1 2022\x00TERM=xterm\x00")
	mk("300", "nginx", "PATH=/usr/bin\x00")
	if got := sessionPorts(root, Sockets()); !reflect.DeepEqual(got, []int{2022, 6379}) {
		t.Fatalf("got %v", got)
	}
}

// Logged-in sessions: SSH_CONNECTION of a shell, whose client still has an
// established connection to that port. A pre-authentication connection
// (no process with SSH_CONNECTION) and a stale environment are left out.
func TestSessionAddrs(t *testing.T) {
	root := t.TempDir()
	mk := func(pid, environ string) {
		dir := filepath.Join(root, pid)
		_ = os.MkdirAll(dir, 0o755)
		_ = os.WriteFile(filepath.Join(dir, "environ"), []byte(environ), 0o644)
	}
	mk("200", "HOME=/root\x00SSH_CONNECTION=203.0.113.7 51000 192.0.2.1 22\x00")
	mk("201", "SSH_CONNECTION=203.0.113.8 51001 192.0.2.1 22\x00")   // session ended
	mk("202", "SSH_CONNECTION=10.0.0.5 51002 192.0.2.1 22\x00")      // private
	mk("203", "SSH_CONNECTION=203.0.113.9 51003 192.0.2.1 2222\x00") // other port
	mk("300", "PATH=/usr/bin\x00")
	inbound := func(port int) []string {
		switch port {
		case 22:
			return []string{"203.0.113.7", "198.51.100.66", "10.0.0.5"} // 198.51.100.66: pre-auth
		case 2222:
			return []string{"203.0.113.9"}
		}
		return nil
	}
	if got := sessionAddrs(root, inbound); !reflect.DeepEqual(got, []string{"203.0.113.7", "203.0.113.9"}) {
		t.Fatalf("got %v", got)
	}
}

// A published container port: no listener on the host, the flow is only in
// the conntrack table.
func TestPublicInboundConntrack(t *testing.T) {
	fakeProc(t)
	oldT, oldL := conntrackTable, localAddrs
	t.Cleanup(func() { conntrackTable, localAddrs = oldT, oldL })
	conntrackTable = func() string {
		return "ipv4     2 tcp      6 431999 ESTABLISHED src=198.51.100.20 dst=192.0.2.1 sport=40000 dport=27017 src=172.17.0.2 dst=198.51.100.20 sport=27017 dport=40000 [ASSURED] mark=0 use=1\n" +
			"ipv4     2 tcp      6 431999 ESTABLISHED src=10.0.0.9 dst=192.0.2.1 sport=40001 dport=27017 src=172.17.0.2 dst=10.0.0.9 sport=27017 dport=40001 [ASSURED] mark=0 use=1\n" +
			"ipv4     2 tcp      6 100 TIME_WAIT src=198.51.100.21 dst=192.0.2.1 sport=40002 dport=27017 src=172.17.0.2 dst=198.51.100.21 sport=27017 dport=40002 mark=0 use=1\n" +
			// The host's own outbound connection to a remote 27017.
			"ipv4     2 tcp      6 431999 ESTABLISHED src=203.0.113.50 dst=198.51.100.99 sport=40003 dport=27017 src=198.51.100.99 dst=203.0.113.50 sport=27017 dport=40003 [ASSURED] mark=0 use=1\n"
	}
	localAddrs = func() map[string]bool { return map[string]bool{"203.0.113.50": true} }
	if got := PublicInbound(27017); !reflect.DeepEqual(got, []string{"198.51.100.20"}) {
		t.Fatalf("got %v", got)
	}
}

func TestListensPublicIPv6(t *testing.T) {
	fakeProc(t)
	if !ListensPublicIPv6(8443) {
		t.Fatal("[::]:8443 not seen")
	}
	if ListensPublicIPv6(6379) {
		t.Fatal("IPv4-only listener reported on IPv6")
	}
}

func TestHasPublicIPv6(t *testing.T) {
	cidr := func(s string) net.Addr {
		ip, n, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatal(err)
		}
		n.IP = ip
		return n
	}
	if hasPublicIPv6([]net.Addr{cidr("127.0.0.1/8"), cidr("203.0.113.5/24"), cidr("::1/128"), cidr("fe80::1/64"), cidr("fd00::5/64")}) {
		t.Fatal("loopback, link-local, ULA and IPv4 are not public IPv6")
	}
	if !hasPublicIPv6([]net.Addr{cidr("fe80::1/64"), cidr("2a01:4f8::5/64")}) {
		t.Fatal("global IPv6 not found")
	}
}

func TestLoggedInTitle(t *testing.T) {
	for title, want := range map[string]bool{
		"sshd: alice@pts/0":               true,
		"sshd: root@notty":                true,
		"sshd-session: root@pts/1":        true,
		"sshd: alice":                     true, // ssh -N
		"sshd: root [priv]":               false,
		"sshd: unknown [net]":             false,
		"sshd: root [net]":                false,
		"sshd: [accepted]":                false,
		"sshd-session: root [priv]":       false,
		"sshd-session: unknown [preauth]": false,
		"sshd-auth: root [net]":           false,
		"sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups": false,
		"/usr/sbin/sshd -D": false,
		"sshd: ":            false,
		"":                  false,
	} {
		if got := loggedInTitle(title); got != want {
			t.Errorf("%q: %v, want %v", title, got, want)
		}
	}
}

// Sockets of procTCP: inode 2 is 198.51.100.7 connected to 6379, inode 3 the
// LAN client 10.0.0.5. Only a logged-in sshd process (not [priv] or [net])
// makes its client a session.
func TestLoggedInSockAddrs(t *testing.T) {
	fakeProc(t)
	root := procRoot
	mk := func(pid, comm, cmdline string, inodes ...string) {
		dir := filepath.Join(root, pid)
		_ = os.MkdirAll(filepath.Join(dir, "fd"), 0o755)
		_ = os.WriteFile(filepath.Join(dir, "comm"), []byte(comm+"\n"), 0o644)
		_ = os.WriteFile(filepath.Join(dir, "cmdline"), []byte(cmdline), 0o644)
		for i, ino := range inodes {
			if err := os.Symlink("socket:["+ino+"]", filepath.Join(dir, "fd", string(rune('3'+i)))); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Pre-authentication: the monitor and the network child hold the socket.
	mk("100", "sshd", "sshd: root [priv]\x00\x00\x00", "2")
	mk("101", "sshd", "sshd: root [net]\x00", "2")
	if got := loggedInSockAddrs(root, Sockets()); len(got) != 0 {
		t.Fatalf("pre-auth connection counted as a session: %v", got)
	}
	// Logged in: the session process holds it too. The LAN client is not public.
	mk("102", "sshd-session", "sshd-session: root@notty\x00", "2", "3")
	if got := loggedInSockAddrs(root, Sockets()); !reflect.DeepEqual(got, []string{"198.51.100.7"}) {
		t.Fatalf("got %v", got)
	}
	// A process that is not sshd, whatever its title, does not count.
	_ = os.RemoveAll(filepath.Join(root, "102"))
	mk("103", "bash", "sshd: root@pts/0\x00", "2")
	if got := loggedInSockAddrs(root, Sockets()); len(got) != 0 {
		t.Fatalf("non-sshd process counted: %v", got)
	}
}
