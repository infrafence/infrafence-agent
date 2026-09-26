package monitor

import (
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
)

const (
	dnsPort         = 53
	dnsCooldown     = 30 * time.Minute
	dnsHopWindow    = 5 * time.Minute
	dnsHopThreshold = 5 // distinct external resolvers in the window = resolver-hopping
	dnsConfRefresh  = 5 * time.Minute
)

// resolverFiles list the DNS servers the machine is configured to use. With
// systemd-resolved (Ubuntu's default) /etc/resolv.conf only names the local
// stub 127.0.0.53; the real upstream servers are in its own resolv.conf, and
// NetworkManager keeps them in its own files.
var resolverFiles = []string{
	"/etc/resolv.conf",
	"/run/systemd/resolve/resolv.conf",
	"/run/NetworkManager/resolv.conf",
	"/run/NetworkManager/no-stub-resolv.conf",
}

// DNSDetector flags outbound DNS traffic (UDP/53) that looks suspicious:
//   - the resolver IP is present in the synced threat feed
//   - the resolver isn't one the machine is configured to use (legitimate
//     software almost always goes through the system resolver; a direct
//     query to an arbitrary external IP:53 is unusual). Queries made by the
//     machine's own DNS service (systemd-resolved, dnsmasq, unbound...) to
//     its upstream or root servers are its job and not flagged.
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
	configuredAt  time.Time
	seenResolvers map[string]time.Time
	reported      map[string]time.Time

	// Overridable in tests; production reads /proc and the resolver files.
	connSource  func() ([]UDPFlow, error)
	owners      func(inodes map[uint64]bool) map[uint64]*ProcInfo
	readConfigs func() map[string]bool
}

func NewDNSDetector(feed *ThreatFeedIndex) *DNSDetector {
	d := &DNSDetector{
		feed:          feed,
		seenResolvers: make(map[string]time.Time),
		reported:      make(map[string]time.Time),
		connSource:    ParseProcNetUDP,
		owners:        socketOwners,
		readConfigs:   func() map[string]bool { return readConfiguredResolvers(resolverFiles) },
	}
	d.configured, d.configuredAt = d.readConfigs(), time.Now()
	return d
}

// readConfiguredResolvers parses "nameserver <ip>" lines from files.
func readConfiguredResolvers(files []string) map[string]bool {
	out := make(map[string]bool)
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) >= 2 && fields[0] == "nameserver" {
				out[fields[1]] = true
			}
		}
	}
	return out
}

func (d *DNSDetector) configuredList() string {
	var l []string
	for ip := range d.configured {
		l = append(l, ip)
	}
	sort.Strings(l)
	return strings.Join(l, ", ")
}

func (d *DNSDetector) Scan() ScanResult {
	flows, err := d.connSource()
	if err != nil {
		log.Printf("[dns] error reading /proc/net/udp: %v", err)
		return ScanResult{Summary: map[string]string{"error": err.Error()}}
	}

	now := time.Now()

	// DHCP and VPNs can change the configured servers.
	if now.Sub(d.configuredAt) > dnsConfRefresh && d.readConfigs != nil {
		d.configured, d.configuredAt = d.readConfigs(), now
	}

	// Who sent each external DNS query (only looked up when there is one).
	inodes := map[uint64]bool{}
	for _, f := range flows {
		if f.RemotePort == dnsPort && !IsPrivateIP(f.RemoteIP) && f.Inode != 0 {
			inodes[f.Inode] = true
		}
	}
	owners := map[uint64]*ProcInfo{}
	if len(inodes) > 0 && d.owners != nil {
		owners = d.owners(inodes)
	}
	hopProcs := map[string]bool{}

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
		owner := owners[f.Inode]
		details := func() map[string]string {
			det := owner.Details()
			if owner == nil {
				det["process"] = "unknown"
				det["process_note"] = "the query ended before its process could be identified"
			}
			det["local_port"] = fmt.Sprintf("%d", f.LocalPort)
			if len(d.configured) > 0 {
				det["configured_resolvers"] = d.configuredList()
			}
			return det
		}

		// Threat-listed resolvers are reported whoever queries them.
		if bad, source := d.feed.Lookup(f.RemoteIP); bad {
			if _, cooled := d.reported[ipStr]; !cooled {
				det := details()
				det["threat_source"] = source
				events = append(events, api.EventRequest{
					Type:       "dns_threat_resolver",
					Severity:   "critical",
					SourceIP:   ipStr,
					Protocol:   "udp",
					TargetPort: portPtr(dnsPort),
					Details:    det,
					OccurredAt: now.UTC().Format(time.RFC3339),
				})
				d.reported[ipStr] = now
			}
			continue
		}

		// The machine's own DNS service talking to its upstream or root
		// servers is what it's for.
		if isSystemResolver(owner) {
			continue
		}
		d.seenResolvers[ipStr] = now
		if owner != nil {
			hopProcs[owner.Name] = true
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
					Details:    details(),
					OccurredAt: now.UTC().Format(time.RFC3339),
				})
				d.reported[key] = now
			}
		}
	}

	if len(d.seenResolvers) >= dnsHopThreshold {
		if _, cooled := d.reported["hopping"]; !cooled {
			events = append(events, api.EventRequest{
				Type:       "dns_resolver_hopping",
				Severity:   "warning",
				Details:    hoppingDetails(d.seenResolvers, hopProcs),
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

func hoppingDetails(seen map[string]time.Time, procs map[string]bool) map[string]string {
	var ips, names []string
	for ip := range seen {
		ips = append(ips, ip)
	}
	for n := range procs {
		names = append(names, n)
	}
	sort.Strings(ips)
	sort.Strings(names)
	det := map[string]string{
		"distinct_resolvers": fmt.Sprintf("%d", len(seen)),
		"resolvers":          strings.Join(ips, ", "),
	}
	if len(names) > 0 {
		det["processes"] = strings.Join(names, ", ")
	}
	return det
}
