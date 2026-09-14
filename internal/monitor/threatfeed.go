package monitor

import (
	"net"
	"sync"

	"github.com/infrafence/infrafence-agent/internal/api"
)

// ThreatFeedIndex is an in-memory, concurrency-safe lookup of the IPs and
// CIDRs from the synced threat feed. The firewall ban path (applyThreatFeed)
// only blocks inbound traffic — this index lets other detectors (e.g.
// EgressDetector) check live outbound connections against the same feed,
// since a compromised host can still dial out to known-bad infrastructure.
type ThreatFeedIndex struct {
	mu    sync.RWMutex
	ips   map[string]string // ip -> source
	cidrs []cidrEntry
}

type cidrEntry struct {
	ipnet  *net.IPNet
	source string
}

func NewThreatFeedIndex() *ThreatFeedIndex {
	return &ThreatFeedIndex{ips: make(map[string]string)}
}

// Update replaces the index contents with the given threat feed entries.
// Safe to call concurrently with Lookup.
func (t *ThreatFeedIndex) Update(entries []api.ThreatEntry) {
	ips := make(map[string]string, len(entries))
	var cidrs []cidrEntry

	for _, e := range entries {
		if e.IP != nil && *e.IP != "" {
			ips[*e.IP] = e.Source
			continue
		}
		if e.CIDR != nil && *e.CIDR != "" {
			if _, ipnet, err := net.ParseCIDR(*e.CIDR); err == nil {
				cidrs = append(cidrs, cidrEntry{ipnet: ipnet, source: e.Source})
			}
		}
	}

	t.mu.Lock()
	t.ips = ips
	t.cidrs = cidrs
	t.mu.Unlock()
}

// Lookup reports whether ip matches a known-bad entry, and its feed source.
func (t *ThreatFeedIndex) Lookup(ip net.IP) (bool, string) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if src, ok := t.ips[ip.String()]; ok {
		return true, src
	}
	for _, c := range t.cidrs {
		if c.ipnet.Contains(ip) {
			return true, c.source
		}
	}
	return false, ""
}
