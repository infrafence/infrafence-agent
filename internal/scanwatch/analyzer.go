// Package scanwatch detects port scans from the connection attempts (TCP
// SYN packets) the server receives, read-only.
//
// Every SYN is seen as it arrives — to open or closed ports — through a
// kernel filter, as the DNS inspection does. Two kinds of scan are
// reported:
//
//   - one address trying many ports (Threshold distinct ports in Window);
//   - a network spreading a scan over many of its addresses, each trying a
//     few ports so that no single address stands out (on the demo server:
//     addresses of one /24 trying 2–6 random ports each, dozens in total).
//     Networks are /24 for IPv4 and /64 for IPv6.
package scanwatch

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// Distinct destination ports from one address within Window that make a
	// port scan. Normal clients use one or two (80/443, 22), so the window
	// can be long enough to catch slow scanners.
	Threshold = 15
	Window    = 10 * time.Minute
	// Distinct ports, from at least NetworkAddresses different addresses of
	// one network, within Window.
	NetworkThreshold = 30
	NetworkAddresses = 3
	// One report per address per Cooldown; per network per NetworkCooldown.
	Cooldown        = 10 * time.Minute
	NetworkCooldown = 30 * time.Minute
	// Addresses and networks tracked at most; beyond that the idle ones are
	// dropped (a flood of sources starts over rather than growing memory).
	maxTracked = 20000
	// Ports and addresses kept per network: enough to cross the thresholds
	// (an IPv6 /64 has more addresses than memory).
	maxNetworkPorts = 256
)

// Scan is a detected port scan.
type Scan struct {
	// Scope is "address" (one address) or "network" (spread over a network).
	Scope string
	// IP is the address, or for a network scan its most active address.
	IP string
	// Network and Addresses are set for network scans.
	Network   string
	Addresses int
	Ports     int      // distinct destination ports in the window
	Sample    []uint16 // up to 20, sorted
}

// Details for the event.
func (s Scan) Details() map[string]string {
	sample := make([]string, len(s.Sample))
	for i, p := range s.Sample {
		sample[i] = strconv.Itoa(int(p))
	}
	d := map[string]string{
		"scope":         s.Scope,
		"ports_scanned": strconv.Itoa(s.Ports),
		"ports_sample":  strings.Join(sample, ","),
		"window":        fmt.Sprintf("%dm", int(Window.Minutes())),
		"detection":     "syn",
	}
	if s.Scope == "network" {
		d["network"] = s.Network
		d["addresses"] = strconv.Itoa(s.Addresses)
	}
	return d
}

type tracked struct {
	ports    map[uint16]time.Time
	addrs    map[string]time.Time // networks only
	lastSeen time.Time
}

// Analyzer counts the distinct ports each address and network tries.
type Analyzer struct {
	mu        sync.Mutex
	sources   map[string]*tracked
	networks  map[string]*tracked
	reported  map[string]time.Time // addresses
	reportedN map[string]time.Time // networks
	// Skip is true for addresses that must never be reported (private,
	// this server's own, whitelisted).
	Skip func(ip net.IP) bool
}

// NewAnalyzer returns an empty analyzer.
func NewAnalyzer(skip func(net.IP) bool) *Analyzer {
	return &Analyzer{
		sources:   map[string]*tracked{},
		networks:  map[string]*tracked{},
		reported:  map[string]time.Time{},
		reportedN: map[string]time.Time{},
		Skip:      skip,
	}
}

// networkOf returns the /24 (IPv4) or /64 (IPv6) containing ip.
func networkOf(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return (&net.IPNet{IP: v4.Mask(net.CIDRMask(24, 32)), Mask: net.CIDRMask(24, 32)}).String()
	}
	return (&net.IPNet{IP: ip.Mask(net.CIDRMask(64, 128)), Mask: net.CIDRMask(64, 128)}).String()
}

// inWindow keeps the entries seen within Window and returns them sorted.
func inWindow(m map[uint16]time.Time, now time.Time) []uint16 {
	var out []uint16
	for p, t := range m {
		if now.Sub(t) <= Window {
			out = append(out, p)
		} else {
			delete(m, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sample(ports []uint16) []uint16 {
	if len(ports) > 20 {
		return append([]uint16(nil), ports[:20]...)
	}
	return ports
}

// Observe records a connection attempt from src to dstPort. It returns the
// scans src (or its network) crossed the threshold with — at most one of
// each kind.
func (a *Analyzer) Observe(src net.IP, dstPort uint16, now time.Time) []Scan {
	if src == nil || (a.Skip != nil && a.Skip(src)) {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []Scan
	if s, ok := a.observeAddress(src.String(), dstPort, now); ok {
		out = append(out, s)
	}
	if s, ok := a.observeNetwork(networkOf(src), src.String(), dstPort, now); ok {
		out = append(out, s)
	}
	return out
}

func (a *Analyzer) observeAddress(key string, port uint16, now time.Time) (Scan, bool) {
	if t, ok := a.reported[key]; ok {
		if now.Sub(t) < Cooldown {
			return Scan{}, false
		}
		delete(a.reported, key)
	}
	tr := a.sources[key]
	if tr == nil {
		if len(a.sources) >= maxTracked {
			a.pruneLocked(now, true)
		}
		tr = &tracked{ports: map[uint16]time.Time{}}
		a.sources[key] = tr
	}
	tr.lastSeen = now
	tr.ports[port] = now
	if len(tr.ports) < Threshold {
		return Scan{}, false
	}
	ports := inWindow(tr.ports, now)
	if len(ports) < Threshold {
		return Scan{}, false
	}
	a.reported[key] = now
	delete(a.sources, key)
	return Scan{Scope: "address", IP: key, Ports: len(ports), Sample: sample(ports)}, true
}

func (a *Analyzer) observeNetwork(key, addr string, port uint16, now time.Time) (Scan, bool) {
	if t, ok := a.reportedN[key]; ok {
		if now.Sub(t) < NetworkCooldown {
			return Scan{}, false
		}
		delete(a.reportedN, key)
	}
	tr := a.networks[key]
	if tr == nil {
		if len(a.networks) >= maxTracked {
			a.pruneLocked(now, true)
		}
		tr = &tracked{ports: map[uint16]time.Time{}, addrs: map[string]time.Time{}}
		a.networks[key] = tr
	}
	tr.lastSeen = now
	if _, ok := tr.addrs[addr]; ok || len(tr.addrs) < maxNetworkPorts {
		tr.addrs[addr] = now
	}
	if _, ok := tr.ports[port]; ok || len(tr.ports) < maxNetworkPorts {
		tr.ports[port] = now
	}
	if len(tr.ports) < NetworkThreshold || len(tr.addrs) < NetworkAddresses {
		return Scan{}, false
	}
	ports := inWindow(tr.ports, now)
	var addrs []string
	for ad, t := range tr.addrs {
		if now.Sub(t) <= Window {
			addrs = append(addrs, ad)
		} else {
			delete(tr.addrs, ad)
		}
	}
	// A single busy address is an address scan, not a network one.
	if len(ports) < NetworkThreshold || len(addrs) < NetworkAddresses {
		return Scan{}, false
	}
	sort.Strings(addrs)
	a.reportedN[key] = now
	delete(a.networks, key)
	return Scan{
		Scope:     "network",
		IP:        addr,
		Network:   key,
		Addresses: len(addrs),
		Ports:     len(ports),
		Sample:    sample(ports),
	}, true
}

// Prune forgets addresses and networks idle for longer than the window;
// call periodically.
func (a *Analyzer) Prune(now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pruneLocked(now, false)
}

func (a *Analyzer) pruneLocked(now time.Time, full bool) {
	for k, tr := range a.sources {
		if now.Sub(tr.lastSeen) > Window {
			delete(a.sources, k)
		}
	}
	for k, tr := range a.networks {
		if now.Sub(tr.lastSeen) > Window {
			delete(a.networks, k)
		}
	}
	for k, t := range a.reported {
		if now.Sub(t) > Cooldown {
			delete(a.reported, k)
		}
	}
	for k, t := range a.reportedN {
		if now.Sub(t) > NetworkCooldown {
			delete(a.reportedN, k)
		}
	}
	if full {
		if len(a.sources) >= maxTracked {
			a.sources = map[string]*tracked{}
		}
		if len(a.networks) >= maxTracked {
			a.networks = map[string]*tracked{}
		}
	}
}
