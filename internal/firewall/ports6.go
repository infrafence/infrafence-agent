package firewall

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"sort"
	"strings"
)

// Closed ports over IPv6. A port closed only in iptables stays reachable at
// the server's IPv6 address, so INFRAFENCE-PORTS is mirrored into ip6tables
// whenever it is available: the same chain name and DROP rules, jumped to
// from INPUT ahead of any rule that can ACCEPT and first in DOCKER-USER when
// Docker has one. There is no INFRAFENCE chain in ip6tables, so the chain
// itself returns early for loopback, private (ULA, link-local) and
// allow-listed sources. Egress blocks stay IPv4 only.
const ports6Comment = "infrafence-ports"

// privateSources6 are never affected by a closed port.
var privateSources6 = []string{"fc00::/7", "fe80::/10"}

// hasIp6tables is replaced in tests.
var hasIp6tables = func() bool {
	if _, err := exec.LookPath("ip6tables"); err != nil {
		return false
	}
	_, err := run("ip6tables", "-S", "INPUT")
	return err == nil
}

// allowEntries6 is allowEntries for IPv6: protected addresses, the server's
// own public addresses and the dashboard whitelist.
func (s *fwState) allowEntries6() []string {
	seen := map[string]bool{}
	var out []string
	add := func(v string) {
		if n := parseNet(v); n != nil && n.IP.To4() == nil && !seen[n.String()] {
			seen[n.String()] = true
			out = append(out, n.String())
		}
	}
	for _, ip := range protectedList() {
		add(ip)
	}
	localIPsOnce.Do(func() { localIPs = collectLocalIPs() })
	for ip := range localIPs {
		if p := net.ParseIP(ip); p != nil && !isReservedIP(p) {
			add(ip)
		}
	}
	for _, a := range s.allow {
		add(a)
	}
	sort.Strings(out)
	return out
}

// ports6Rules returns the contents of the IPv6 INFRAFENCE-PORTS chain.
func (s *fwState) ports6Rules() []string {
	if len(s.closedPorts) == 0 {
		return nil
	}
	rules := []string{fmt.Sprintf("-A %s -i lo -j RETURN", portsChainName)}
	for _, n := range append(append([]string(nil), privateSources6...), s.allowEntries6()...) {
		rules = append(rules, fmt.Sprintf("-A %s -s %s -j RETURN", portsChainName, n))
	}
	for _, p := range s.closedPorts {
		rules = append(rules, fmt.Sprintf("-A %s -p tcp -m conntrack --ctstate NEW --ctorigdstport %d -j DROP", portsChainName, p))
	}
	return rules
}

// ensurePorts6 keeps the IPv6 chain and its jumps in place. Failures are
// logged and leave ports6InForce false: callers then report the ports as
// closed over IPv4 only.
func (s *fwState) ensurePorts6() (repaired []string) {
	if !hasIp6tables() {
		s.v6InForce = false
		return nil
	}
	want := s.ports6Rules()
	key := strings.Join(want, "\n")
	have, ok := currentRulesOf("ip6tables", portsChainName)
	if !ok || key != s.v6Desired || !equal(have, s.v6Applied) {
		var b strings.Builder
		fmt.Fprintf(&b, "*filter\n:%s - [0:0]\n", portsChainName)
		for _, l := range want {
			b.WriteString(l + "\n")
		}
		b.WriteString("COMMIT\n")
		if out, err := runStdin(b.String(), "ip6tables-restore", "--noflush"); err != nil {
			if key != s.v6FailedKey {
				log.Printf("[firewall] ip6tables-restore %s: %s (%v)", portsChainName, out, err)
			}
			s.v6FailedKey = key
			s.v6InForce = false
			return nil
		}
		if s.v6Desired != "" && key == s.v6Desired {
			repaired = append(repaired, "chain:ip6tables")
		}
		s.v6Desired, s.v6FailedKey = key, ""
		s.v6Applied, _ = currentRulesOf("ip6tables", portsChainName)
	}
	r, err := ensureJumpAheadOf("ip6tables", "INPUT", ports6Comment, portsChainName)
	repaired = append(repaired, r...)
	if err != nil {
		log.Printf("[firewall] ip6tables INPUT jump: %v", err)
		s.v6InForce = false
		return repaired
	}
	repaired = append(repaired, ensureFirstJump("ip6tables", dockerChain, ports6Comment, portsChainName)...)
	s.v6InForce = true
	return repaired
}

// removePorts6 removes the IPv6 chain and its jumps (uninstall).
func removePorts6() (done []string) {
	if !hasIp6tables() {
		return nil
	}
	return removePorts6Of("ip6tables")
}

// removePorts6Of removes the IPv6 closed-port jumps and chain with bin
// (ip6tables, or ip6tables-legacy for a backend the host left).
func removePorts6Of(bin string) (done []string) {
	for _, chain := range []string{"INPUT", dockerChain} {
		for {
			if _, err := run(bin, append([]string{"-D", chain}, jumpArgs(ports6Comment, portsChainName)...)...); err != nil {
				break
			}
			done = append(done, "jump:"+bin+":"+chain+"->"+portsChainName)
		}
	}
	if _, err := run(bin, "-F", portsChainName); err == nil {
		_, _ = run(bin, "-X", portsChainName)
		done = append(done, "chain:"+bin+":"+portsChainName)
	}
	return done
}

// Ports6InForce returns the closed ports in force over IPv6, or ok=false
// when ip6tables is missing or refused the rules (the ports are then
// closed over IPv4 only).
func Ports6InForce() (closed []int, ok bool) {
	fw.Lock()
	defer fw.Unlock()
	if !fw.v6InForce {
		return nil, false
	}
	return append([]int(nil), fw.closedPorts...), true
}
