package firewall

import (
	"errors"
	"log"
	"net"
	"strings"
)

const (
	threatSetName = "infrafence-threat"
	// Refuse anything broader than a /8: no legitimate blocklist entry should
	// be, and a malformed one must not take out a large part of the internet.
	minThreatPrefix = 8
)

// ErrNoIpset means inbound threat-feed blocking needs ipset, which is missing.
// Individual iptables rules don't scale to thousands of feed entries.
var ErrNoIpset = errors.New("ipset not available")

// ApplyThreatSet replaces the inbound threat-feed blocklist (IPv4 IPs and
// CIDRs) atomically. Entries that cover an IP the agent must never block —
// reserved, local, protected (API server) or in keep (the org whitelist) —
// are skipped and counted.
func ApplyThreatSet(entries []string, keep []string) (applied, skipped int, err error) {
	if !HasIpset() {
		return 0, 0, ErrNoIpset
	}

	cidrs, skipped := filterThreatNets(entries, keep)
	if err := replaceNetSet(threatSetName, cidrs); err != nil {
		return 0, skipped, err
	}
	fw.Lock()
	fw.threat = cidrs
	fw.Unlock()
	if _, err := Ensure(); err != nil {
		return 0, skipped, err
	}
	return len(cidrs), skipped, nil
}

// ClearThreatSet stops inbound threat-feed blocking (e.g. in monitor mode)
// without touching the rest of the firewall.
func ClearThreatSet() {
	fw.Lock()
	active := fw.threat != nil
	fw.threat = nil
	fw.Unlock()
	if !active || !HasIpset() {
		return
	}
	if _, err := Ensure(); err != nil {
		log.Printf("[threat-feed] remove blocklist rule: %v", err)
	}
	_ = flushIpset(threatSetName)
}

// filterThreatNets keeps the IPv4 entries that are safe to block.
func filterThreatNets(entries []string, keep []string) (cidrs []string, skipped int) {
	var keepNets []*net.IPNet
	for _, k := range keep {
		if n := parseNet(k); n != nil {
			keepNets = append(keepNets, n)
		}
	}
	for _, e := range entries {
		n := parseNet(e)
		if n == nil || n.IP.To4() == nil {
			continue
		}
		if ones, _ := n.Mask.Size(); ones < minThreatPrefix || coversSafeIP(n, keepNets) {
			skipped++
			continue
		}
		cidrs = append(cidrs, n.String())
	}
	return cidrs, skipped
}

func parseNet(s string) *net.IPNet {
	s = strings.TrimSpace(s)
	if ip := net.ParseIP(s); ip != nil {
		bits := 128
		if ip.To4() != nil {
			ip, bits = ip.To4(), 32
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
	}
	if _, n, err := net.ParseCIDR(s); err == nil {
		return n
	}
	return nil
}

// coversSafeIP reports whether n contains an IP the agent must never block,
// or overlaps a whitelisted network.
func coversSafeIP(n *net.IPNet, keep []*net.IPNet) bool {
	if isReservedIP(n.IP) {
		return true
	}
	localIPsOnce.Do(func() { localIPs = collectLocalIPs() })
	for s := range localIPs {
		if ip := net.ParseIP(s); ip != nil && n.Contains(ip) && !isReservedIP(ip) {
			return true
		}
	}
	for _, s := range protectedList() {
		if ip := net.ParseIP(s); ip != nil && n.Contains(ip) {
			return true
		}
	}
	for _, k := range keep {
		if n.Contains(k.IP) || k.Contains(n.IP) {
			return true
		}
	}
	return false
}
