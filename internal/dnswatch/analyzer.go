package dnswatch

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/monitor"
)

const (
	cooldown       = 30 * time.Minute
	window         = 5 * time.Minute
	tunnelUnique   = 60   // distinct long subdomains of one domain in the window
	tunnelMinLen   = 24   // average length of those subdomain parts
	dgaDistinct    = 20   // distinct random-looking non-existent domains in the window
	dgaMaxWordLike = 0.55 // share of common letter pairs: real words >= 0.75, random strings ~0.38
	dgaMinLength   = 12
	maxTracked     = 5000 // bound on per-window state
)

// Sources are what the analyzer consults; overridable in tests.
type Sources struct {
	Configured func() map[string]bool                       // resolvers the host is configured to use
	Threat     func(ip net.IP) (bool, string)               // IP threat lists
	Owner      func(port uint16, v6 bool) *monitor.ProcInfo // process owning a local UDP port
	Now        func() time.Time
}

// Analyzer turns DNS packets into security events.
type Analyzer struct {
	src Sources

	mu        sync.Mutex
	reported  map[string]time.Time
	subs      map[string]map[string]time.Time // base domain -> subdomain part -> seen
	nx        map[string]time.Time            // non-existent random-looking domains
	loopQuery map[string]loopSeen             // name -> app that asked the local stub
}

type loopSeen struct {
	port uint16
	v6   bool
	at   time.Time
}

func NewAnalyzer(src Sources) *Analyzer {
	if src.Now == nil {
		src.Now = time.Now
	}
	return &Analyzer{
		src:       src,
		reported:  map[string]time.Time{},
		subs:      map[string]map[string]time.Time{},
		nx:        map[string]time.Time{},
		loopQuery: map[string]loopSeen{},
	}
}

// Handle analyzes one packet and returns the events it causes.
func (a *Analyzer) Handle(p Packet) []api.EventRequest {
	msg, ok := parseMessage(p.Payload)
	if !ok || msg.Name == "" {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.src.Now()
	a.prune(now)

	// Only this server's own lookups: queries it sends and the answers it
	// receives. If it runs a DNS server, the queries it answers for others
	// are not its own lookups.
	if !msg.Response && p.DstPort == 53 && p.Outgoing {
		return a.query(p, msg, now)
	}
	if msg.Response && p.SrcPort == 53 && (!p.Outgoing || p.Src.IsLoopback()) {
		return a.response(p, msg, now)
	}
	return nil
}

func (a *Analyzer) query(p Packet, msg Message, now time.Time) []api.EventRequest {
	var out []api.EventRequest
	v6 := p.Src.To4() == nil
	if p.Dst.IsLoopback() {
		// An application asking the local stub (systemd-resolved): remember
		// who, to attribute what the stub forwards upstream.
		if len(a.loopQuery) < maxTracked {
			a.loopQuery[msg.Name] = loopSeen{port: p.SrcPort, v6: v6, at: now}
		}
	} else if p.Outgoing && !monitor.IsPrivateIP(p.Dst) {
		owner := a.owner(p.SrcPort, v6, msg.Name, now)
		dst := p.Dst.String()
		if bad, source := a.threat(p.Dst); bad {
			if a.due("threat-resolver:"+dst, now) {
				d := details(owner, msg.Name, dst)
				d["threat_source"] = source
				out = append(out, event("dns_threat_resolver", "critical", dst, d, now))
			}
		} else if conf := a.configured(); len(conf) > 0 && !conf[dst] && !monitor.IsSystemResolver(owner) {
			key := "unlisted:" + dst + ":" + procKey(owner)
			if a.due(key, now) {
				d := details(owner, msg.Name, dst)
				d["configured_resolvers"] = joinKeys(conf)
				out = append(out, event("dns_unlisted_resolver", "info", dst, d, now))
			}
		}
	}

	// Tunneling: many long, distinct subdomains of one domain.
	base, sub := splitBase(msg.Name)
	if sub != "" && !allowlisted(base) && (len(sub) >= 16 || msg.QType == typeTXT || msg.QType == typeNULL) {
		set := a.subs[base]
		if set == nil && len(a.subs) < maxTracked {
			set = map[string]time.Time{}
			a.subs[base] = set
		}
		if set != nil && len(set) < maxTracked {
			set[sub] = now
			if len(set) >= tunnelUnique && avgLen(set) >= tunnelMinLen && a.due("tunnel:"+base, now) {
				owner := a.owner(p.SrcPort, v6, msg.Name, now)
				d := details(owner, msg.Name, p.Dst.String())
				d["base_domain"] = base
				d["distinct_subdomains"] = fmt.Sprintf("%d", len(set))
				d["average_length"] = fmt.Sprintf("%d", avgLen(set))
				d["window"] = window.String()
				out = append(out, event("dns_tunneling", "warning", "", d, now))
			}
		}
	}
	return out
}

func (a *Analyzer) response(p Packet, msg Message, now time.Time) []api.EventRequest {
	var out []api.EventRequest
	v6 := p.Dst.To4() == nil

	// A domain that resolves to a malicious IP.
	for _, ip := range msg.Answers {
		if bad, source := a.threat(ip); bad && a.due("answer:"+msg.Name+":"+ip.String(), now) {
			owner := a.owner(p.DstPort, v6, msg.Name, now)
			d := details(owner, msg.Name, p.Src.String())
			d["resolved_ip"] = ip.String()
			d["threat_source"] = source
			out = append(out, event("dns_threat_answer", "warning", ip.String(), d, now))
		}
	}

	// DGA: bursts of random-looking domains that don't exist.
	if msg.RCode == rcodeNX && !p.Src.IsLoopback() {
		base, _ := splitBase(msg.Name)
		if label := firstLabel(base); len(label) >= dgaMinLength && wordLikeness(label) < dgaMaxWordLike && !allowlisted(base) {
			if len(a.nx) < maxTracked {
				a.nx[base] = now
			}
			if len(a.nx) >= dgaDistinct && a.due("dga", now) {
				owner := a.owner(p.DstPort, v6, msg.Name, now)
				d := details(owner, msg.Name, p.Src.String())
				d["nonexistent_domains"] = fmt.Sprintf("%d", len(a.nx))
				d["examples"] = strings.Join(firstKeys(a.nx, 5), ", ")
				d["window"] = window.String()
				out = append(out, event("dns_dga", "warning", "", d, now))
			}
		}
	}
	return out
}

// owner attributes a packet to a process: the app that asked the local stub
// for this name if there was one, else the owner of the local port.
func (a *Analyzer) owner(port uint16, v6 bool, name string, now time.Time) *monitor.ProcInfo {
	if a.src.Owner == nil {
		return nil
	}
	if l, ok := a.loopQuery[name]; ok && now.Sub(l.at) < 5*time.Second {
		if p := a.src.Owner(l.port, l.v6); p != nil {
			return p
		}
	}
	return a.src.Owner(port, v6)
}

func (a *Analyzer) threat(ip net.IP) (bool, string) {
	if a.src.Threat == nil {
		return false, ""
	}
	return a.src.Threat(ip)
}

func (a *Analyzer) configured() map[string]bool {
	if a.src.Configured == nil {
		return nil
	}
	return a.src.Configured()
}

func (a *Analyzer) due(key string, now time.Time) bool {
	if t, ok := a.reported[key]; ok && now.Sub(t) < cooldown {
		return false
	}
	a.reported[key] = now
	return true
}

func (a *Analyzer) prune(now time.Time) {
	for k, t := range a.reported {
		if now.Sub(t) > cooldown {
			delete(a.reported, k)
		}
	}
	for base, set := range a.subs {
		for s, t := range set {
			if now.Sub(t) > window {
				delete(set, s)
			}
		}
		if len(set) == 0 {
			delete(a.subs, base)
		}
	}
	for k, t := range a.nx {
		if now.Sub(t) > window {
			delete(a.nx, k)
		}
	}
	for k, l := range a.loopQuery {
		if now.Sub(l.at) > 10*time.Second {
			delete(a.loopQuery, k)
		}
	}
}

func details(owner *monitor.ProcInfo, name, resolver string) map[string]string {
	d := owner.Details()
	if owner == nil {
		d["process"] = "unknown"
		d["process_note"] = "the query ended before its process could be identified"
	}
	d["domain"] = name
	if resolver != "" {
		d["resolver"] = resolver
	}
	return d
}

func event(typ, sev, ip string, d map[string]string, now time.Time) api.EventRequest {
	port := 53
	return api.EventRequest{
		Type: typ, Severity: sev, SourceIP: ip, Protocol: "udp", TargetPort: &port,
		Details: d, OccurredAt: now.UTC().Format(time.RFC3339),
	}
}

func procKey(p *monitor.ProcInfo) string {
	if p == nil {
		return "?"
	}
	return p.Name + "|" + p.Exe
}

// Second-level labels under which domains are registered (co.uk, com.br...).
var secondLevel = map[string]bool{"co": true, "com": true, "net": true, "org": true, "gov": true, "ac": true, "edu": true, "or": true, "ne": true, "go": true}

// splitBase splits a name into its registered domain and the rest:
// "a1b2.c3.evil.co.uk" -> ("evil.co.uk", "a1b2.c3").
func splitBase(name string) (base, sub string) {
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	n := 2
	if len(labels) >= 3 && len(labels[len(labels)-1]) == 2 && secondLevel[labels[len(labels)-2]] {
		n = 3
	}
	if len(labels) <= n {
		return name, ""
	}
	return strings.Join(labels[len(labels)-n:], "."), strings.Join(labels[:len(labels)-n], ".")
}

func firstLabel(s string) string {
	l, _, _ := strings.Cut(s, ".")
	return l
}

// Services that legitimately encode data in DNS names: antivirus hash
// lookups, anti-spam and reputation lists, CDNs' and clouds' own names.
var allowlist = []string{
	"sophosxl.net", "e5.sk", "avqs.mcafee.com", "mcafee.com", "trendmicro.com", "eset.com", "kaspersky.com",
	"spamhaus.org", "spamhaus.net", "surbl.org", "uribl.com", "dnswl.org", "spamcop.net", "barracudacentral.org",
	"sorbs.net", "mailspike.net", "senderscore.com", "abuseat.org", "dnsbl.info",
	"amazonaws.com", "cloudfront.net", "akamaiedge.net", "akamai.net", "edgekey.net", "azureedge.net",
	"cloudapp.net", "googleusercontent.com", "1e100.net", "in-addr.arpa", "ip6.arpa",
}

func allowlisted(base string) bool {
	for _, a := range allowlist {
		if base == a || strings.HasSuffix(base, "."+a) || strings.HasSuffix(a, "."+base) {
			return true
		}
	}
	return false
}

func avgLen(set map[string]time.Time) int {
	if len(set) == 0 {
		return 0
	}
	total := 0
	for s := range set {
		total += len(s)
	}
	return total / len(set)
}

func joinKeys(m map[string]bool) string {
	var l []string
	for k := range m {
		l = append(l, k)
	}
	sort.Strings(l)
	return strings.Join(l, ", ")
}

func firstKeys(m map[string]time.Time, n int) []string {
	var l []string
	for k := range m {
		l = append(l, k)
	}
	sort.Strings(l)
	if len(l) > n {
		l = l[:n]
	}
	return l
}
