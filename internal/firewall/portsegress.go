package firewall

import (
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

// Ports closed to the public and addresses the host may not reach, both
// requested from the dashboard:
//
//	INFRAFENCE-PORTS   jumped to from INFRAFENCE right after the allow-list
//	                   RETURN, so it sees INPUT and DOCKER-USER traffic and
//	                   never applies to allow-listed sources. Loopback and
//	                   private sources RETURN (the LAN and containers keep
//	                   their access); new connections to a closed port are
//	                   dropped. --ctorigdstport is the port the client asked
//	                   for, also for a published container port after DNAT.
//	INFRAFENCE-EGRESS  jumped to from OUTPUT (the host's own connections) and
//	                   from INFRAFENCE (containers' traffic in DOCKER-USER):
//	                   drops everything to the blocked addresses, through
//	                   the infrafence-egress ipset or one rule each without
//	                   ipset. IPv4 only.
const (
	portsChainName  = "INFRAFENCE-PORTS"
	egressChainName = "INFRAFENCE-EGRESS"
	egressSetName   = "infrafence-egress"
	egressComment   = "infrafence-egress"
)

// privateSources are never affected by a closed port.
var privateSources = []string{"10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16"}

// portsEgressRules returns the contents of both chains as iptables -S lines.
func (s *fwState) portsEgressRules(ipset bool) (ports, egress []string) {
	if len(s.closedPorts) > 0 {
		ports = append(ports, fmt.Sprintf("-A %s -i lo -j RETURN", portsChainName))
		for _, n := range privateSources {
			ports = append(ports, fmt.Sprintf("-A %s -s %s -j RETURN", portsChainName, n))
		}
		for _, p := range s.closedPorts {
			ports = append(ports, fmt.Sprintf("-A %s -p tcp -m conntrack --ctstate NEW --ctorigdstport %d -j DROP", portsChainName, p))
		}
	}
	if ipset {
		if len(s.egress) > 0 {
			egress = append(egress, fmt.Sprintf("-A %s -m set --match-set %s dst -j DROP", egressChainName, egressSetName))
		}
	} else {
		for _, ip := range s.egress {
			egress = append(egress, fmt.Sprintf("-A %s -d %s/32 -j DROP", egressChainName, ip))
		}
	}
	return ports, egress
}

// SetPortsEgress replaces the closed ports and blocked egress addresses and
// applies them. Entries that are invalid or must never be blocked (the
// server's own and protected addresses, the allow list, private ranges,
// IPv6) are left out and returned as skipped.
func SetPortsEgress(closed []int, egress []string) (skipped []string, err error) {
	skipped, changed := setPortsEgress(closed, egress)
	if !changed {
		return skipped, nil
	}
	_, err = Ensure()
	return skipped, err
}

// LoadPortsEgress sets the closed ports and blocked egress addresses without
// applying them: the next Ensure (Init at startup) does, so a restart never
// passes through a moment with the ports open.
func LoadPortsEgress(closed []int, egress []string) (skipped []string) {
	skipped, _ = setPortsEgress(closed, egress)
	return skipped
}

func setPortsEgress(closed []int, egress []string) (skipped []string, changed bool) {
	fw.Lock()
	defer fw.Unlock()
	ports := map[int]bool{}
	for _, p := range closed {
		if p < 1 || p > 65535 {
			skipped = append(skipped, fmt.Sprintf("port %d", p))
			continue
		}
		ports[p] = true
	}
	ips := map[string]bool{}
	for _, e := range egress {
		if reason := fw.egressRefusal(e); reason != "" {
			skipped = append(skipped, e+" ("+reason+")")
			continue
		}
		ips[net.ParseIP(e).To4().String()] = true
	}
	newPorts := make([]int, 0, len(ports))
	for p := range ports {
		newPorts = append(newPorts, p)
	}
	sort.Ints(newPorts)
	newEgress := make([]string, 0, len(ips))
	for ip := range ips {
		newEgress = append(newEgress, ip)
	}
	sort.Strings(newEgress)
	changed = !equalInts(fw.closedPorts, newPorts) || !equal(fw.egress, newEgress)
	fw.closedPorts, fw.egress = newPorts, newEgress
	return skipped, changed
}

// PortsEgress returns the closed ports and blocked egress addresses in force:
// none while iptables refuses their rules or the egress set cannot be filled.
func PortsEgress() (closed []int, egress []string) {
	fw.Lock()
	defer fw.Unlock()
	if !fw.peInForce {
		return nil, nil
	}
	closed = append([]int(nil), fw.closedPorts...)
	if !HasIpset() || fw.egressSetErr == nil {
		egress = append([]string(nil), fw.egress...)
	}
	return closed, egress
}

// EgressRefusal returns why ip may not be blocked for egress, or "" when it
// may: "invalid", "ipv6_unsupported", "private_target" (reserved ranges,
// this server) or "allowlisted_target" (protected addresses such as the
// dashboard's, the allow list).
func EgressRefusal(ip string) string {
	fw.Lock()
	defer fw.Unlock()
	return fw.egressRefusal(ip)
}

func (s *fwState) egressRefusal(ip string) string {
	p := net.ParseIP(strings.TrimSpace(ip))
	switch {
	case p == nil:
		return "invalid"
	case p.To4() == nil:
		return "ipv6_unsupported"
	}
	p = p.To4()
	if isReservedIP(p) || isLocalIP(p) || p.IsUnspecified() || p.IsMulticast() || p[0] == 0 ||
		(p[0] == 100 && p[1]&0xC0 == 64) || p.Equal(net.IPv4bcast) {
		return "private_target"
	}
	for _, a := range s.allowEntries() {
		if n := parseNet(a); n != nil && n.Contains(p) {
			return "allowlisted_target"
		}
	}
	return ""
}

// ensureEgressSet makes the infrafence-egress set hold exactly s.egress.
func (s *fwState) ensureEgressSet() error {
	if err := createIpsetHashIP(egressSetName); err != nil {
		return err
	}
	have := map[string]bool{}
	for _, m := range ipsetListMembers(egressSetName) {
		have[m] = true
	}
	want := map[string]bool{}
	for _, ip := range s.egress {
		want[ip] = true
	}
	var b strings.Builder
	for ip := range want {
		if !have[ip] {
			fmt.Fprintf(&b, "add %s %s -exist\n", egressSetName, ip)
		}
	}
	for ip := range have {
		if !want[ip] {
			fmt.Fprintf(&b, "del %s %s -exist\n", egressSetName, ip)
		}
	}
	if b.Len() == 0 {
		return nil
	}
	if out, err := runStdin(b.String(), "ipset", "restore"); err != nil {
		return fmt.Errorf("ipset restore %s: %s (%w)", egressSetName, out, err)
	}
	return nil
}

// IsAllowListed reports whether ip is covered by the allow list or the
// protected addresses (IPv4 or IPv6).
func IsAllowListed(ip string) bool {
	p := net.ParseIP(strings.TrimSpace(ip))
	if p == nil {
		return false
	}
	fw.Lock()
	defer fw.Unlock()
	for _, a := range append(fw.allowEntries(), fw.allowEntries6()...) {
		if n := parseNet(a); n != nil && n.Contains(p) {
			return true
		}
	}
	return false
}

// DropConntrack deletes the tracked TCP flows to port (original destination
// port, so a published container port too) from public, not allow-listed
// sources, so a connection opened before the port was closed does not
// outlive it. Best effort: nothing happens without the conntrack tool.
// Returns how many sources were dropped.
func DropConntrack(port int) int {
	if _, err := exec.LookPath("conntrack"); err != nil {
		return 0
	}
	dropped := 0
	for _, family := range []string{"ipv4", "ipv6"} {
		out, err := run("conntrack", "-L", "-f", family, "-p", "tcp", "--orig-port-dst", strconv.Itoa(port))
		if err != nil {
			continue
		}
		for _, src := range conntrackSources(out) {
			ip := net.ParseIP(src)
			if ip == nil || isReservedIP(ip) || ip.IsUnspecified() || isLocalIP(ip) || IsAllowListed(src) {
				continue
			}
			if _, err := run("conntrack", "-D", "-f", family, "-p", "tcp", "--orig-port-dst", strconv.Itoa(port), "--orig-src", src); err == nil {
				dropped++
			}
		}
	}
	return dropped
}

// conntrackSources returns the distinct original source addresses of
// `conntrack -L` lines.
func conntrackSources(out string) []string {
	seen := map[string]bool{}
	var srcs []string
	for _, line := range strings.Split(out, "\n") {
		for _, w := range strings.Fields(line) {
			if v, ok := strings.CutPrefix(w, "src="); ok {
				if !seen[v] {
					seen[v] = true
					srcs = append(srcs, v)
				}
				break
			}
		}
	}
	return srcs
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
