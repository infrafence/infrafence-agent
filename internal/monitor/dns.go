package monitor

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
)

const (
	dnsPort         = 53
	dnsCooldown     = 30 * time.Minute
	dnsHopWindow    = 5 * time.Minute
	dnsHopThreshold = 5 // distinct external resolvers in the window = resolver-hopping
)

// DNSDetector flags outbound DNS traffic (UDP/53) that looks suspicious:
//   - the resolver IP is present in the synced threat feed
//   - the resolver isn't one configured in /etc/resolv.conf (legitimate
//     software almost always goes through the system resolver; a direct
//     query to an arbitrary external IP:53 is unusual)
//   - "resolver hopping": many distinct external IPs on port 53 in a short
//     window, a pattern common to DNS-tunneling tools trying to evade a
//     single-resolver block
//
// Coverage note: this polls /proc/net/udp on the same cycle as the other
// monitors. A single DNS query/response is typically sub-millisecond, so a
// one-off lookup can fall between polls — this reliably catches *sustained*
// traffic (tunneling, repeated beaconing), not every individual query. It
// complements EgressDetector; it is not full packet-level DNS inspection.
type DNSDetector struct {
	feed          *ThreatFeedIndex
	configured    map[string]bool
	seenResolvers map[string]time.Time
	reported      map[string]time.Time

	// connSource is overridable in tests; production always uses ParseProcNetUDP.
	connSource func() ([]UDPFlow, error)
}

func NewDNSDetector(feed *ThreatFeedIndex) *DNSDetector {
	return &DNSDetector{
		feed:          feed,
		configured:    readConfiguredResolvers(),
		seenResolvers: make(map[string]time.Time),
		reported:      make(map[string]time.Time),
		connSource:    ParseProcNetUDP,
	}
}

// readConfiguredResolvers parses "nameserver <ip>" lines from /etc/resolv.conf.
func readConfiguredResolvers() map[string]bool {
	out := make(map[string]bool)

	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return out
	}

	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 2 && fields[0] == "nameserver" {
			out[fields[1]] = true
		}
	}
	return out
}

func (d *DNSDetector) Scan() ScanResult {
	flows, err := d.connSource()
	if err != nil {
		log.Printf("[dns] error reading /proc/net/udp: %v", err)
		return ScanResult{Summary: map[string]string{"error": err.Error()}}
	}

	now := time.Now()

	// Prune expired cooldowns and resolver-hopping window
	for k, t := range d.reported {
		if now.Sub(t) > dnsCooldown {
			delete(d.reported, k)
		}
	}
	for k, t := range d.seenResolvers {
		if now.Sub(t) > dnsHopWindow {
			delete(d.seenResolvers, k)
		}
	}

	var events []api.EventRequest
	checked := 0

	for _, f := range flows {
		if f.RemotePort != dnsPort || IsPrivateIP(f.RemoteIP) {
			continue
		}
		checked++

		ipStr := f.RemoteIP.String()
		d.seenResolvers[ipStr] = now

		if bad, source := d.feed.Lookup(f.RemoteIP); bad {
			if _, cooled := d.reported[ipStr]; !cooled {
				events = append(events, api.EventRequest{
					Type:       "dns_threat_resolver",
					Severity:   "critical",
					SourceIP:   ipStr,
					Protocol:   "udp",
					TargetPort: portPtr(dnsPort),
					Details:    map[string]string{"threat_source": source},
					OccurredAt: now.UTC().Format(time.RFC3339),
				})
				d.reported[ipStr] = now
			}
			continue
		}

		if len(d.configured) > 0 && !d.configured[ipStr] {
			key := "unlisted:" + ipStr
			if _, cooled := d.reported[key]; !cooled {
				events = append(events, api.EventRequest{
					Type:       "dns_unlisted_resolver",
					Severity:   "info",
					SourceIP:   ipStr,
					Protocol:   "udp",
					TargetPort: portPtr(dnsPort),
					OccurredAt: now.UTC().Format(time.RFC3339),
				})
				d.reported[key] = now
			}
		}
	}

	if len(d.seenResolvers) >= dnsHopThreshold {
		if _, cooled := d.reported["hopping"]; !cooled {
			events = append(events, api.EventRequest{
				Type:     "dns_resolver_hopping",
				Severity: "warning",
				Details: map[string]string{
					"distinct_resolvers": fmt.Sprintf("%d", len(d.seenResolvers)),
				},
				OccurredAt: now.UTC().Format(time.RFC3339),
			})
			d.reported["hopping"] = now
		}
	}

	return ScanResult{
		Events: events,
		Summary: map[string]string{
			"udp_flows_checked":  fmt.Sprintf("%d", len(flows)),
			"dns_flows_checked":  fmt.Sprintf("%d", checked),
			"distinct_resolvers": fmt.Sprintf("%d", len(d.seenResolvers)),
		},
	}
}
