package dbclients

import (
	"context"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Declared MySQL clients on cPanel/WHM: the "Additional MySQL Access Hosts"
// of WHM (SQL Services), which WHM keeps one per line in
// /var/cpanel/mysqlaccesshosts and grants on every account's databases.
// They may connect to MySQL from outside from the first minute, before any
// observation. Read only, the file and nothing else: the Remote MySQL hosts
// an account adds in cPanel exist only as MySQL's own grants, which the
// agent does not query; those clients are learned by observation.
//
// An entry is an address, a CIDR range, an address with a netmask
// (203.0.113.0/255.255.255.0), a MySQL pattern with % for whole trailing
// octets (203.0.113.%) or a host name (resolved, bounded). Private,
// loopback and reserved entries are left out (closing a port never affects
// them), and so are patterns that cannot be written as a range ("%" alone:
// any address).

// AccessHostsFile is replaced in tests.
var AccessHostsFile = "/var/cpanel/mysqlaccesshosts"

const (
	maxAccessHosts = 200
	maxResolve     = 20
	resolveTimeout = 3 * time.Second
	maxAccessFile  = 1 << 20
)

// Declared is one declared client: Entry is an address or a CIDR range,
// Host the line it comes from.
type Declared struct {
	Entry  string `json:"entry"`
	Host   string `json:"host"`
	Source string `json:"source"`
}

// Resolver looks a host name up (replaced in tests).
var Resolver = func(ctx context.Context, host string) []string {
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return nil
	}
	return addrs
}

// The last good answer per host name (at most maxResolve names are looked
// up per read, so the cache stays small).
var (
	resolvedMu    sync.Mutex
	resolvedCache = map[string][]string{}
)

// ReadCPanelAccessHosts reads the declared MySQL clients of WHM. ok is
// false when the file does not exist (not cPanel, or no access hosts).
func ReadCPanelAccessHosts() (out []Declared, ok bool) {
	f, err := os.Open(AccessHostsFile)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, maxAccessFile))
	return ParseAccessHosts(string(b), "cpanel_access_hosts"), true
}

// ParseAccessHosts parses the lines of an access hosts file.
func ParseAccessHosts(data, source string) []Declared {
	seen := map[string]bool{}
	var out []Declared
	resolved := 0
	add := func(entry, host string) {
		if entry != "" && !seen[entry] && len(out) < maxAccessHosts {
			seen[entry] = true
			out = append(out, Declared{Entry: entry, Host: host, Source: source})
		}
	}
	for _, line := range strings.Split(data, "\n") {
		host := strings.TrimSpace(line)
		if i := strings.IndexByte(host, '#'); i >= 0 {
			host = strings.TrimSpace(host[:i])
		}
		if host == "" || strings.ContainsAny(host, " \t") {
			continue
		}
		if e := hostEntry(host); e != "" {
			add(e, host)
			continue
		}
		if net.ParseIP(host) != nil || !hostName(host) || resolved >= maxResolve {
			continue
		}
		resolved++
		ctx, cancel := context.WithTimeout(context.Background(), resolveTimeout)
		addrs := Resolver(ctx, host)
		cancel()
		// A failed lookup keeps the last good answer for that name: a DNS
		// outage must not drop a declared client.
		resolvedMu.Lock()
		if len(addrs) > 0 {
			resolvedCache[host] = addrs
		} else {
			addrs = resolvedCache[host]
		}
		resolvedMu.Unlock()
		for _, a := range addrs {
			add(normIP(a), host)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Entry < out[j].Entry })
	return out
}

// hostEntry returns the address or range a host entry stands for when it is
// one (public only), else "".
func hostEntry(h string) string {
	if ip := normIP(h); ip != "" {
		return ip
	}
	if strings.Contains(h, "%") {
		return wildcardNet(h)
	}
	addr, mask, ok := strings.Cut(h, "/")
	if !ok {
		return ""
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return ""
	}
	var n *net.IPNet
	if bits, err := strconv.Atoi(mask); err == nil {
		_, n, err = net.ParseCIDR(addr + "/" + strconv.Itoa(bits))
		if err != nil {
			return ""
		}
	} else if m := net.ParseIP(mask).To4(); m != nil && ip.To4() != nil {
		mm := net.IPMask(m)
		if ones, bits := mm.Size(); bits == 0 || ones == 0 {
			return ""
		}
		n = &net.IPNet{IP: ip.To4().Mask(mm), Mask: mm}
	} else {
		return ""
	}
	if ones, _ := n.Mask.Size(); ones == 0 || !public(n.IP) {
		return ""
	}
	return n.String()
}

// wildcardNet turns "203.0.113.%" or "203.0.%" (whole trailing octets)
// into a CIDR range, else "".
func wildcardNet(h string) string {
	parts := strings.Split(h, ".")
	if len(parts) != 4 {
		return ""
	}
	fixed := 0
	for fixed < 4 && parts[fixed] != "%" {
		if _, err := strconv.ParseUint(parts[fixed], 10, 8); err != nil {
			return ""
		}
		fixed++
	}
	if fixed == 0 {
		return ""
	}
	for _, p := range parts[fixed:] {
		if p != "%" {
			return ""
		}
	}
	ip := make([]string, 4)
	for i := range ip {
		if i < fixed {
			ip[i] = parts[i]
		} else {
			ip[i] = "0"
		}
	}
	_, n, err := net.ParseCIDR(strings.Join(ip, ".") + "/" + strconv.Itoa(fixed*8))
	if err != nil || !public(n.IP) {
		return ""
	}
	return n.String()
}

// hostName: a plain DNS name (no wildcard), not localhost.
func hostName(h string) bool {
	if len(h) > 253 || !strings.Contains(h, ".") || strings.EqualFold(h, "localhost") ||
		strings.HasSuffix(strings.ToLower(h), ".localhost") {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}
