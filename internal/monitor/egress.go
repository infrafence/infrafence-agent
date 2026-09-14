package monitor

import (
	"fmt"
	"log"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
)

const egressCooldown = 30 * time.Minute

// EgressDetector flags established outbound connections to IPs/CIDRs present
// in the synced threat feed — e.g. an already-compromised host beaconing out
// to known C2 infrastructure. Inbound bans (iptables INPUT, applied from the
// same feed) don't cover this direction.
type EgressDetector struct {
	feed     *ThreatFeedIndex
	reported map[string]time.Time
}

func NewEgressDetector(feed *ThreatFeedIndex) *EgressDetector {
	return &EgressDetector{
		feed:     feed,
		reported: make(map[string]time.Time),
	}
}

func (d *EgressDetector) Scan() ScanResult {
	conns, err := ParseProcNetTCP()
	if err != nil {
		log.Printf("[egress] error reading /proc/net/tcp: %v", err)
		return ScanResult{Summary: map[string]string{"error": err.Error()}}
	}

	now := time.Now()

	// Prune expired cooldowns
	for ip, t := range d.reported {
		if now.Sub(t) > egressCooldown {
			delete(d.reported, ip)
		}
	}

	var events []api.EventRequest
	checked := 0
	matched := 0

	for _, c := range conns {
		if c.State != TCPEstablished || IsPrivateIP(c.RemoteIP) {
			continue
		}
		checked++

		bad, source := d.feed.Lookup(c.RemoteIP)
		if !bad {
			continue
		}
		matched++

		ipStr := c.RemoteIP.String()
		if _, cooled := d.reported[ipStr]; cooled {
			continue
		}

		events = append(events, api.EventRequest{
			Type:       "egress_threat_match",
			Severity:   "critical",
			SourceIP:   ipStr,
			SourcePort: portPtr(c.LocalPort),
			TargetPort: portPtr(c.RemotePort),
			Protocol:   "tcp",
			Details: map[string]string{
				"threat_source": source,
			},
			OccurredAt: now.UTC().Format(time.RFC3339),
		})
		d.reported[ipStr] = now
	}

	return ScanResult{
		Events: events,
		Summary: map[string]string{
			"connections_checked": fmt.Sprintf("%d", len(conns)),
			"external_checked":    fmt.Sprintf("%d", checked),
			"threat_matches":      fmt.Sprintf("%d", matched),
		},
	}
}

func portPtr(p uint16) *int {
	v := int(p)
	return &v
}
