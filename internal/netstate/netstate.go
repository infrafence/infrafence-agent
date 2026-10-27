// Package netstate reads what the host's network looks like right now:
// listening TCP ports, established connections, the ports sshd uses and the
// ports web servers listen on. Read only; used to refuse firewall changes
// that would cut the owner off or take a site down.
package netstate

import (
	"context"
	"encoding/hex"
	"io"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/infrafence/infrafence-agent/internal/monitor"
)

const (
	stateEstablished = 0x01
	stateListen      = 0x0A
)

// Conn is one TCP socket from /proc/net/tcp{,6}.
type Conn struct {
	LocalIP    net.IP
	LocalPort  int
	RemoteIP   net.IP
	RemotePort int
	State      int
	Inode      uint64
}

// procRoot is replaced in tests.
var procRoot = "/proc"

// Sockets returns every IPv4 and IPv6 TCP socket of the host.
func Sockets() []Conn {
	var out []Conn
	for _, f := range []string{"net/tcp", "net/tcp6"} {
		data, err := os.ReadFile(procRoot + "/" + f)
		if err != nil {
			continue
		}
		out = append(out, parseProcNet(string(data))...)
	}
	return out
}

func parseProcNet(data string) []Conn {
	var out []Conn
	for i, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 4 {
			continue
		}
		lip, lport, ok1 := parseAddr(f[1])
		rip, rport, ok2 := parseAddr(f[2])
		st, err := strconv.ParseUint(f[3], 16, 8)
		if !ok1 || !ok2 || err != nil {
			continue
		}
		var inode uint64
		if len(f) > 9 {
			inode, _ = strconv.ParseUint(f[9], 10, 64)
		}
		out = append(out, Conn{LocalIP: lip, LocalPort: lport, RemoteIP: rip, RemotePort: rport, State: int(st), Inode: inode})
	}
	return out
}

// parseAddr decodes "0100007F:0050": the address is stored as 32-bit words
// in host byte order (little endian on every platform the agent ships for).
func parseAddr(s string) (net.IP, int, bool) {
	host, port, ok := strings.Cut(s, ":")
	if !ok {
		return nil, 0, false
	}
	raw, err := hex.DecodeString(host)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return nil, 0, false
	}
	ip := make(net.IP, len(raw))
	for w := 0; w < len(raw); w += 4 {
		ip[w], ip[w+1], ip[w+2], ip[w+3] = raw[w+3], raw[w+2], raw[w+1], raw[w]
	}
	p, err := strconv.ParseUint(port, 16, 16)
	if err != nil {
		return nil, 0, false
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip, int(p), true
}

// IsPublic reports whether ip is a routable public address (IPv4-mapped
// IPv6 is read as IPv4).
func IsPublic(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		// Shared address space (carrier-grade NAT) and "this network".
		if v4[0] == 100 && v4[1]&0xC0 == 64 || v4[0] == 0 {
			return false
		}
	}
	return true
}

// Listening reports whether anything listens on TCP port.
func Listening(port int) bool {
	for _, c := range Sockets() {
		if c.State == stateListen && c.LocalPort == port {
			return true
		}
	}
	return false
}

// PublicInbound returns the public addresses with an established connection
// to port: to a port the host listens on (/proc/net/tcp), or tracked by
// conntrack with port as the original destination, which also covers a
// published container port (Docker DNAT, no listener on the host).
func PublicInbound(port int) []string {
	out := publicInbound(Sockets(), port)
	seen := map[string]bool{}
	for _, ip := range out {
		seen[ip] = true
	}
	for _, ip := range conntrackInbound(port) {
		if !seen[ip] {
			seen[ip] = true
			out = append(out, ip)
		}
	}
	sort.Strings(out)
	return out
}

// conntrackTable is replaced in tests: the established TCP entries as
// /proc/net/nf_conntrack or `conntrack -L` prints them ("" when neither is
// available).
var conntrackTable = func() string {
	if b, err := os.ReadFile(procRoot + "/net/nf_conntrack"); err == nil {
		return string(b)
	}
	if _, err := exec.LookPath("conntrack"); err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "conntrack", "-L", "-p", "tcp", "--state", "ESTABLISHED").Output()
	return string(out)
}

// conntrackInbound returns the public sources of established TCP flows whose
// original destination port is port. Flows the host started itself (source
// is one of its addresses) are not inbound.
func conntrackInbound(port int) []string {
	return parseConntrackInbound(conntrackTable(), port, localAddrs())
}

func parseConntrackInbound(table string, port int, local map[string]bool) []string {
	seen := map[string]bool{}
	var out []string
	for _, line := range strings.Split(table, "\n") {
		f := strings.Fields(line)
		established := false
		var src, dport string
		for _, w := range f {
			switch {
			case w == "ESTABLISHED":
				established = true
			case strings.HasPrefix(w, "src=") && src == "":
				src = w[4:]
			case strings.HasPrefix(w, "dport=") && dport == "":
				dport = w[6:]
			}
		}
		if !established || !containsField(f, "tcp") || dport != strconv.Itoa(port) {
			continue
		}
		ip := net.ParseIP(src)
		if ip == nil || !IsPublic(ip) || local[ip.String()] || seen[ip.String()] {
			continue
		}
		seen[ip.String()] = true
		out = append(out, ip.String())
	}
	return out
}

func containsField(f []string, v string) bool {
	for _, x := range f {
		if x == v {
			return true
		}
	}
	return false
}

// localAddrs is replaced in tests.
var localAddrs = func() map[string]bool {
	out := map[string]bool{}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			out[n.IP.String()] = true
		}
	}
	return out
}

// ListensPublicIPv6 reports whether something listens on TCP port on an
// IPv6 address other than loopback ([::] included).
func ListensPublicIPv6(port int) bool {
	for _, c := range Sockets() {
		if c.State == stateListen && c.LocalPort == port && len(c.LocalIP) == net.IPv6len &&
			c.LocalIP.To4() == nil && !c.LocalIP.IsLoopback() {
			return true
		}
	}
	return false
}

// HasPublicIPv6 reports whether an interface of this host has a public IPv6
// address. Without one nothing reaches the host over IPv6 from the
// internet, whatever listens on [::].
func HasPublicIPv6() bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return true // unknown: assume it has one
	}
	return hasPublicIPv6(addrs)
}

func hasPublicIPv6(addrs []net.Addr) bool {
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if ok && n.IP.To4() == nil && len(n.IP) == net.IPv6len && IsPublic(n.IP) {
			return true
		}
	}
	return false
}

func publicInbound(socks []Conn, port int) []string {
	listening := false
	for _, c := range socks {
		if c.State == stateListen && c.LocalPort == port {
			listening = true
			break
		}
	}
	if !listening {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, c := range socks {
		if c.State == stateEstablished && c.LocalPort == port && IsPublic(c.RemoteIP) && !seen[c.RemoteIP.String()] {
			seen[c.RemoteIP.String()] = true
			out = append(out, c.RemoteIP.String())
		}
	}
	sort.Strings(out)
	return out
}

var (
	sshMu      sync.Mutex
	sshPorts   []int
	sshChecked time.Time
)

// sshdT is replaced in tests.
var sshdT = func() string {
	for _, bin := range []string{"sshd", "/usr/sbin/sshd"} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		out, err := exec.CommandContext(ctx, bin, "-T").Output()
		cancel()
		if err == nil && len(out) > 0 {
			return string(out)
		}
	}
	return ""
}

// listeners is replaced in tests.
var listeners = monitor.DetectListeningServices

// SSHPorts returns every port sshd uses: each "port" line of `sshd -T`, any
// port an sshd process listens on, the Listen addresses of the ssh.socket /
// sshd.socket units (socket activation: sshd itself does not listen), and the
// local port of every SSH session open right now (the sockets of sshd
// processes, and SSH_CONNECTION in the environment of the session's
// processes). When none can be read it returns 22, so callers never treat
// the default SSH port as free. Cached for a minute (sshd -T is a process
// start).
func SSHPorts() []int {
	sshMu.Lock()
	defer sshMu.Unlock()
	if sshPorts != nil && time.Since(sshChecked) < time.Minute {
		return append([]int(nil), sshPorts...)
	}
	set := map[int]bool{}
	for _, line := range strings.Split(sshdT(), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && strings.EqualFold(f[0], "port") {
			if p, err := strconv.Atoi(f[1]); err == nil && p > 0 && p < 65536 {
				set[p] = true
			}
		}
	}
	for _, s := range listeners() {
		if s.Process == "sshd" || strings.HasPrefix(s.Process, "sshd") {
			set[s.Port] = true
		}
	}
	for _, p := range parseSocketListen(sshSocketListen()) {
		set[p] = true
	}
	for _, p := range sshSessionPorts() {
		set[p] = true
	}
	if len(set) == 0 {
		// Not cached: the next call reads sshd again.
		return []int{22}
	}
	sshPorts = sortedKeys(set)
	sshChecked = time.Now()
	return append([]int(nil), sshPorts...)
}

// sshSocketListen is replaced in tests: the Listen= lines of the SSH
// socket units.
var sshSocketListen = func() string {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "systemctl", "show", "ssh.socket", "sshd.socket", "-p", "Listen").Output()
	return string(out)
}

// parseSocketListen reads "Listen=[::]:2222 (Stream)" lines (one per
// address; "Listen=" for a unit that does not exist).
func parseSocketListen(out string) []int {
	var ports []int
	for _, line := range strings.Split(out, "\n") {
		v, ok := strings.CutPrefix(strings.TrimSpace(line), "Listen=")
		if !ok {
			continue
		}
		for _, item := range strings.Fields(v) {
			if strings.HasPrefix(item, "(") {
				continue
			}
			if i := strings.LastIndex(item, ":"); i >= 0 {
				item = item[i+1:]
			}
			if p, err := strconv.Atoi(item); err == nil && p > 0 && p < 65536 {
				ports = append(ports, p)
			}
		}
	}
	return ports
}

// maxProcs bounds the /proc walk for SSH sessions.
const maxProcs = 20000

// sshSessionPorts is replaced in tests.
var sshSessionPorts = func() []int { return sessionPorts(procRoot, Sockets()) }

// sessionPorts returns the local ports of the SSH sessions open right now:
// established sockets held by an sshd process (sshd, sshd-session), and the
// server port of SSH_CONNECTION in the environment of any process.
func sessionPorts(root string, socks []Conn) []int {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	inodes := map[uint64]bool{}
	set := map[int]bool{}
	n := 0
	for _, e := range entries {
		pid := e.Name()
		if pid == "" || pid[0] < '0' || pid[0] > '9' {
			continue
		}
		if n++; n > maxProcs {
			break
		}
		dir := root + "/" + pid
		if comm, err := os.ReadFile(dir + "/comm"); err == nil && strings.HasPrefix(strings.TrimSpace(string(comm)), "sshd") {
			fds, _ := os.ReadDir(dir + "/fd")
			for _, fd := range fds {
				link, err := os.Readlink(dir + "/fd/" + fd.Name())
				if err != nil {
					continue
				}
				if v, ok := strings.CutPrefix(link, "socket:["); ok {
					if i, err := strconv.ParseUint(strings.TrimSuffix(v, "]"), 10, 64); err == nil {
						inodes[i] = true
					}
				}
			}
		}
		if p := sshConnectionPort(dir + "/environ"); p > 0 {
			set[p] = true
		}
	}
	for _, c := range socks {
		if c.State == stateEstablished && c.Inode != 0 && inodes[c.Inode] {
			set[c.LocalPort] = true
		}
	}
	return sortedKeys(set)
}

// sshConnectionPort returns the server port of SSH_CONNECTION
// ("client_ip client_port server_ip server_port") in an environ file, or 0.
func sshConnectionPort(path string) int {
	_, port := sshConnection(path)
	return port
}

// sshConnection returns the client address and the server port of
// SSH_CONNECTION in an environ file (nil, 0 without one).
func sshConnection(path string) (net.IP, int) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0
	}
	defer f.Close()
	buf := make([]byte, 64*1024)
	n, _ := io.ReadFull(f, buf)
	for _, kv := range strings.Split(string(buf[:n]), "\x00") {
		if v, ok := strings.CutPrefix(kv, "SSH_CONNECTION="); ok {
			if f := strings.Fields(v); len(f) == 4 {
				if p, err := strconv.Atoi(f[3]); err == nil && p > 0 && p < 65536 {
					return net.ParseIP(f[0]), p
				}
			}
		}
	}
	return nil, 0
}

// SSHSessionAddrs returns the public client addresses of the SSH sessions
// logged in right now. Only authenticated sessions count, never a
// connection still authenticating (a brute force holds many of those):
//
//   - SSH_CONNECTION in the environment of a process (sshd sets it only for
//     the session's processes, after authentication) whose address still
//     has an established connection to that server port;
//   - the client of an established socket held by a logged-in sshd process
//     (loggedInTitle), which also covers a session without a shell
//     (ssh -N, port forwarding).
func SSHSessionAddrs() []string {
	set := map[string]bool{}
	for _, a := range sessionAddrs(procRoot, PublicInbound) {
		set[a] = true
	}
	for _, a := range loggedInSockAddrs(procRoot, Sockets()) {
		set[a] = true
	}
	out := make([]string, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// loggedInTitle reports whether an sshd process title (the start of
// /proc/<pid>/cmdline) is one sshd gives a process after authentication:
// "sshd: alice@pts/0", "sshd-session: root@notty", "sshd: alice" (no
// session channel). Before authentication every sshd process carries a
// bracketed role: "sshd: root [priv]", "sshd: unknown [net]",
// "sshd: [accepted]", "sshd-session: root [preauth]", the listener
// "sshd: /usr/sbin/sshd -D [listener] ..."; the monitor keeps "[priv]" for
// the whole session, so it is never the one counted.
func loggedInTitle(title string) bool {
	var rest string
	switch {
	case strings.HasPrefix(title, "sshd: "):
		rest = title[len("sshd: "):]
	case strings.HasPrefix(title, "sshd-session: "):
		rest = title[len("sshd-session: "):]
	default:
		return false
	}
	rest = strings.TrimSpace(rest)
	return rest != "" && !strings.ContainsAny(rest, "[]") && !strings.HasPrefix(rest, "/")
}

// procTitle returns the process title: /proc/<pid>/cmdline up to the first
// NUL (setproctitle writes it over argv).
func procTitle(dir string) string {
	f, err := os.Open(dir + "/cmdline")
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, 512)
	n, _ := io.ReadFull(f, buf)
	t, _, _ := strings.Cut(string(buf[:n]), "\x00")
	return strings.TrimSpace(t)
}

// loggedInSockAddrs returns the public clients of the established sockets
// held by logged-in sshd processes.
func loggedInSockAddrs(root string, socks []Conn) []string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	inodes := map[uint64]bool{}
	n := 0
	for _, e := range entries {
		pid := e.Name()
		if pid == "" || pid[0] < '0' || pid[0] > '9' {
			continue
		}
		if n++; n > maxProcs {
			break
		}
		dir := root + "/" + pid
		comm, err := os.ReadFile(dir + "/comm")
		if err != nil || !strings.HasPrefix(strings.TrimSpace(string(comm)), "sshd") || !loggedInTitle(procTitle(dir)) {
			continue
		}
		fds, _ := os.ReadDir(dir + "/fd")
		for _, fd := range fds {
			link, err := os.Readlink(dir + "/fd/" + fd.Name())
			if err != nil {
				continue
			}
			if v, ok := strings.CutPrefix(link, "socket:["); ok {
				if i, err := strconv.ParseUint(strings.TrimSuffix(v, "]"), 10, 64); err == nil {
					inodes[i] = true
				}
			}
		}
	}
	set := map[string]bool{}
	for _, c := range socks {
		if c.State == stateEstablished && c.Inode != 0 && inodes[c.Inode] && IsPublic(c.RemoteIP) {
			set[c.RemoteIP.String()] = true
		}
	}
	out := make([]string, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

func sessionAddrs(root string, inbound func(port int) []string) []string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	clients := map[int]map[string]bool{} // server port -> client addresses
	n := 0
	for _, e := range entries {
		pid := e.Name()
		if pid == "" || pid[0] < '0' || pid[0] > '9' {
			continue
		}
		if n++; n > maxProcs {
			break
		}
		if ip, port := sshConnection(root + "/" + pid + "/environ"); ip != nil && IsPublic(ip) {
			if clients[port] == nil {
				clients[port] = map[string]bool{}
			}
			clients[port][ip.String()] = true
		}
	}
	set := map[string]bool{}
	for port, ips := range clients {
		for _, a := range inbound(port) {
			if p := net.ParseIP(a); p != nil && ips[p.String()] {
				set[p.String()] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// webProcesses are the process names (/proc/<pid>/comm) of web servers and
// the proxies that front them.
var webProcesses = map[string]bool{
	"nginx": true, "apache2": true, "httpd": true, "lshttpd": true, "litespeed": true,
	"openlitespeed": true, "lsws": true, "caddy": true, "traefik": true, "haproxy": true,
	"envoy": true, "varnishd": true, "h2o": true, "lighttpd": true, "openresty": true,
	"cpsrvd": true, "sw-cp-serverd": true, "directadmin": true, "miniserv.pl": true,
}

// panelPorts are 80, 443 and the ports of hosting control panels (cPanel/WHM,
// Plesk, DirectAdmin, HestiaCP/VestaCP, Webmin) and common web alternates,
// protected whenever anything listens on them.
var panelPorts = map[int]bool{
	80: true, 443: true, 2082: true, 2083: true, 2086: true, 2087: true, 2095: true, 2096: true,
	2222: true, 8443: true, 8880: true, 8083: true, 10000: true, 8080: true, 8081: true,
}

// WebPorts returns the ports a web server or panel listens on, plus the
// panelPorts whenever anything listens on them (a container's proxy).
func WebPorts() []int { return WebPortsFrom(listeners()) }

// WebPortsFrom is WebPorts for an already collected list of listeners.
func WebPortsFrom(list []monitor.ListeningService) []int {
	set := map[int]bool{}
	for _, s := range list {
		if webProcesses[s.Process] || panelPorts[s.Port] {
			set[s.Port] = true
		}
	}
	return sortedKeys(set)
}

func sortedKeys(m map[int]bool) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}
