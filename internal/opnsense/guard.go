package opnsense

import (
	"context"
	"net"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

// GuardEntry is a network that must never be blocked, with why.
type GuardEntry struct {
	CIDR string
	Why  string
}

// Guard implements pf.Guard: the firewall's own addresses, its internal
// networks, gateways, DNS servers, VPN peers, the dashboard and the
// addresses administrators logged in from.
type Guard struct {
	mu     sync.RWMutex
	nets   []*net.IPNet
	why    []string
	public []string
}

// NewGuard returns an empty guard.
func NewGuard() *Guard { return &Guard{} }

// Set replaces the protected networks.
func (g *Guard) Set(entries []GuardEntry) {
	var nets []*net.IPNet
	var why []string
	seen := map[string]bool{}
	var public []string
	for _, e := range entries {
		c := e.CIDR
		if !strings.Contains(c, "/") {
			if strings.Contains(c, ":") {
				c += "/128"
			} else {
				c += "/32"
			}
		}
		ip, n, err := net.ParseCIDR(c)
		if err != nil {
			continue
		}
		key := n.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		nets = append(nets, n)
		why = append(why, e.Why)
		if !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified() {
			public = append(public, key)
		}
	}
	sort.Strings(public)
	g.mu.Lock()
	g.nets, g.why, g.public = nets, why, public
	g.mu.Unlock()
}

// Why returns why ip is protected ("" when it is not).
func (g *Guard) Why(ip net.IP) string {
	if ip == nil {
		return "invalid address"
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	for i, n := range g.nets {
		if n.Contains(ip) {
			return g.why[i]
		}
	}
	return ""
}

// Overlaps returns why network n covers a protected address ("" when it
// does not).
func (g *Guard) Overlaps(n *net.IPNet) string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	for i, p := range g.nets {
		if p.Contains(n.IP) || n.Contains(p.IP) {
			return g.why[i]
		}
	}
	return ""
}

// Nets returns the protected public networks (private ones are never
// blocked anyway): the tables carry them negated.
func (g *Guard) Nets() []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return append([]string(nil), g.public...)
}

// GuardEntries lists what the configuration protects, plus the firewall's
// live addresses (DHCP/PPPoE WAN addresses are not in config.xml).
func GuardEntries(c *Config, own []string) []GuardEntry {
	var out []GuardEntry
	for _, a := range own {
		out = append(out, GuardEntry{a, "an address of this firewall"})
	}
	if c == nil {
		return out
	}
	for _, it := range c.Interfaces {
		for _, a := range []string{it.IPv4, it.IPv6} {
			if ip, _, err := net.ParseCIDR(a); err == nil {
				out = append(out, GuardEntry{ip.String(), "an address of this firewall"})
			} else if net.ParseIP(a) != nil {
				out = append(out, GuardEntry{a, "an address of this firewall"})
			}
		}
	}
	for _, n := range c.InternalNets() {
		out = append(out, GuardEntry{n, "an internal network of this firewall"})
	}
	for _, g := range c.Gateways {
		out = append(out, GuardEntry{g, "a gateway of this firewall"})
	}
	for _, d := range c.DNSServers {
		out = append(out, GuardEntry{d, "a DNS server of this firewall"})
	}
	for _, p := range c.Peers {
		out = append(out, GuardEntry{p, "a VPN peer of this firewall"})
	}
	return out
}

// DefaultGateways are the next hops of the default routes (a DHCP or PPPoE
// WAN gateway is not in config.xml), from route(8).
func DefaultGateways() []string {
	var out []string
	for _, fam := range []string{"-inet", "-inet6"} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		data, err := exec.CommandContext(ctx, "/sbin/route", "-n", "get", fam, "default").Output()
		cancel()
		if err != nil {
			continue
		}
		for _, l := range strings.Split(string(data), "\n") {
			k, v, ok := strings.Cut(strings.TrimSpace(l), ":")
			if !ok || k != "gateway" {
				continue
			}
			v = strings.TrimSpace(v)
			if i := strings.IndexByte(v, '%'); i >= 0 {
				v = v[:i]
			}
			if net.ParseIP(v) != nil {
				out = append(out, v)
			}
		}
	}
	return out
}

// OwnAddresses are the addresses on the firewall's interfaces.
func OwnAddresses() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			out = append(out, n.IP.String())
		}
	}
	return out
}
