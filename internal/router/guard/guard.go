// Package guard decides which addresses a router may block. A home router
// that blocks its own LAN, its gateway, its upstream DNS or the dashboard
// cuts the household off the internet (or the agent off its dashboard), so
// every ban and C2 entry passes through Check before reaching the firewall.
package guard

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/infrafence/infrafence-agent/internal/router/uci"
)

// Prefix widths no list may exceed: a /4 "ban" would drop a sixteenth of
// the internet.
const (
	MinBits4 = 8
	MinBits6 = 19
)

var reserved = mustPrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
	"::/127", "::ffff:0:0/96", "64:ff9b::/96", "fc00::/7", "fe80::/10", "ff00::/8",
)

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// Parse reads an address or CIDR into a canonical prefix (a single address
// is /32 or /128; IPv4-mapped IPv6 becomes IPv4).
func Parse(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("not an address or CIDR: %q", s)
		}
		a := p.Addr()
		bits := p.Bits()
		if a.Is4In6() {
			if bits < 96 {
				return netip.Prefix{}, fmt.Errorf("not an address or CIDR: %q", s)
			}
			a, bits = a.Unmap(), bits-96
		}
		return netip.PrefixFrom(a.WithZone(""), bits).Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("not an address or CIDR: %q", s)
	}
	a = a.Unmap().WithZone("")
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// Guard holds the addresses that must stay reachable.
type Guard struct {
	mu        sync.RWMutex
	protected []netip.Prefix // router addresses, gateway, DNS, dashboard
	allow     []netip.Prefix // the organization's whitelist
}

func New() *Guard { return &Guard{} }

// SetProtected replaces the router's own addresses, gateways, resolvers and
// the dashboard's addresses.
func (g *Guard) SetProtected(addrs []netip.Prefix) {
	g.mu.Lock()
	g.protected = append([]netip.Prefix(nil), addrs...)
	g.mu.Unlock()
}

// SetAllow replaces the whitelist (addresses and ranges never blocked).
func (g *Guard) SetAllow(addrs []netip.Prefix) {
	g.mu.Lock()
	g.allow = append([]netip.Prefix(nil), addrs...)
	g.mu.Unlock()
}

// Check says why p must not be blocked, or nil when it may.
func (g *Guard) Check(p netip.Prefix) error {
	if !p.IsValid() {
		return fmt.Errorf("invalid prefix")
	}
	if p.Addr().Is4() && p.Bits() < MinBits4 || p.Addr().Is6() && p.Bits() < MinBits6 {
		return fmt.Errorf("%s is wider than /%d (IPv4) or /%d (IPv6)", p, MinBits4, MinBits6)
	}
	for _, r := range reserved {
		if r.Overlaps(p) {
			return fmt.Errorf("%s is a private, local or reserved range", p)
		}
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	for _, q := range g.protected {
		if q.Overlaps(p) {
			return fmt.Errorf("%s contains an address the router needs (%s)", p, q)
		}
	}
	for _, q := range g.allow {
		if q.Overlaps(p) {
			return fmt.Errorf("%s is whitelisted (%s)", p, q)
		}
	}
	return nil
}

// Hosts turns addresses into single-address prefixes, skipping bad ones.
func Hosts(addrs []string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range addrs {
		if p, err := Parse(s); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// LocalAddresses are the router's own interface addresses (WAN and LAN).
func LocalAddresses() []netip.Prefix {
	var out []netip.Prefix
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok {
				ip = ip.Unmap()
				out = append(out, netip.PrefixFrom(ip, ip.BitLen()))
			}
		}
	}
	return out
}

// Gateways reads the IPv4 default gateways from /proc/net/route and the
// IPv6 ones from /proc/net/ipv6_route.
func Gateways() []netip.Prefix {
	return append(gateways4("/proc/net/route"), gateways6("/proc/net/ipv6_route")...)
}

func gateways4(path string) []netip.Prefix {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []netip.Prefix
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 3 || fs[0] == "Iface" {
			continue
		}
		v, err := strconv.ParseUint(fs[2], 16, 32)
		if err != nil || v == 0 {
			continue
		}
		// The kernel prints the address as a host-order integer.
		var b [4]byte
		binary.NativeEndian.PutUint32(b[:], uint32(v))
		out = append(out, netip.PrefixFrom(netip.AddrFrom4(b), 32))
	}
	return out
}

func gateways6(path string) []netip.Prefix {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []netip.Prefix
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 5 || len(fs[4]) != 32 || fs[4] == strings.Repeat("0", 32) {
			continue
		}
		var b [16]byte
		ok := true
		for i := 0; i < 16; i++ {
			v, err := strconv.ParseUint(fs[4][2*i:2*i+2], 16, 8)
			if err != nil {
				ok = false
				break
			}
			b[i] = byte(v)
		}
		if ok {
			out = append(out, netip.PrefixFrom(netip.AddrFrom16(b), 128))
		}
	}
	return out
}

// Resolvers reads the upstream DNS servers OpenWrt writes for dnsmasq
// (netifd's resolv.conf.auto) and /etc/resolv.conf.
func Resolvers() []netip.Prefix {
	var out []netip.Prefix
	for _, p := range []string{"/tmp/resolv.conf.d/resolv.conf.auto", "/tmp/resolv.conf.auto", "/etc/resolv.conf"} {
		out = append(out, resolvers(p)...)
	}
	return out
}

func resolvers(path string) []netip.Prefix {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []netip.Prefix
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) >= 2 && fs[0] == "nameserver" {
			if p, err := Parse(fs[1]); err == nil {
				out = append(out, p)
			}
		}
	}
	return out
}

// Peers are other addresses the router depends on, from netifd and UCI:
// route next hops (PPPoE / VPN peers have no default gateway in
// /proc/net/route), point-to-point peers, the DNS servers netifd learned,
// dnsmasq's server= upstreams and WireGuard endpoints given as addresses.
func Peers() []netip.Prefix {
	var out []netip.Prefix
	if b, err := exec.Command("ubus", "call", "network.interface", "dump").Output(); err == nil {
		out = append(out, ubusPeers(b)...)
	}
	for k, v := range uci.Show("dhcp") {
		if strings.HasSuffix(k, ".server") {
			out = append(out, dnsmasqServers(v)...)
		}
	}
	for k, v := range uci.Show("network") {
		if strings.HasSuffix(k, ".endpoint_host") {
			if p, err := Parse(v); err == nil {
				out = append(out, p)
			}
		}
	}
	return out
}

func ubusPeers(b []byte) []netip.Prefix {
	var dump struct {
		Interface []struct {
			Route []struct {
				Nexthop string `json:"nexthop"`
			} `json:"route"`
			DNSServer []string `json:"dns-server"`
			IPv4      []struct {
				PtP string `json:"ptpaddress"`
			} `json:"ipv4-address"`
		} `json:"interface"`
	}
	if json.Unmarshal(b, &dump) != nil {
		return nil
	}
	var out []netip.Prefix
	add := func(s string) {
		if p, err := Parse(s); err == nil && !p.Addr().IsUnspecified() {
			out = append(out, p)
		}
	}
	for _, i := range dump.Interface {
		for _, r := range i.Route {
			add(r.Nexthop)
		}
		for _, d := range i.DNSServer {
			add(d)
		}
		for _, a := range i.IPv4 {
			if a.PtP != "" {
				add(a.PtP)
			}
		}
	}
	return out
}

// dnsmasqServers reads uci dhcp server values: "8.8.8.8", "1.1.1.1#53",
// "/lan.example/192.168.1.2", several separated by spaces.
func dnsmasqServers(v string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range strings.Fields(v) {
		if i := strings.LastIndex(s, "/"); i >= 0 {
			s = s[i+1:]
		}
		s, _, _ = strings.Cut(s, "#")
		s, _, _ = strings.Cut(s, "@")
		if p, err := Parse(s); err == nil {
			out = append(out, p)
		}
	}
	return out
}
