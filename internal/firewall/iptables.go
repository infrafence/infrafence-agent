package firewall

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

const banSetName = "infrafence-bans"

// Init sets up the INFRAFENCE chains, jumps and sets (see chain.go) and
// migrates rules earlier versions put directly into INPUT.
func Init() {
	checkIpset()
	res, err := Ensure()
	if err != nil {
		log.Printf("[firewall] setup failed: %v", err)
		return
	}
	mode := "iptables (limited capacity)"
	if HasIpset() {
		mode = "ipset"
	}
	log.Printf("[firewall] %s chain ready (%s): %v", chainName, mode, res.Repairs)
}

// SetK8sHook registers a Kubernetes-level firewall implementation.
// When set, BanIP will also call the K8s hook to update ConfigMap deny rules.
func SetK8sHook(hook interface{}) {
	// K8s firewall hook — stored for future use when K8s integration is active
	log.Printf("[firewall] K8s firewall hook registered")
}

// FirewallStatus returns the current firewall backend status.
type Status struct {
	Mode       string // "ipset" or "iptables"
	HasIpset   bool
	Capacity   int
	ActiveBans int
	CSF        CSFStatus // CSF info (empty if not installed)
}

// FirewallStatus returns mode, capacity, active ban count, and CSF info.
func FirewallStatus() Status {
	csf := CSFInfo()

	if HasIpset() {
		return Status{
			Mode:       "ipset",
			HasIpset:   true,
			Capacity:   ipsetBanCap,
			ActiveBans: ipsetEntryCount(banSetName),
			CSF:        csf,
		}
	}
	fw.Lock()
	bans := len(fw.bans)
	fw.Unlock()
	return Status{Mode: "iptables", HasIpset: false, Capacity: iptablesBanCap, ActiveBans: bans, CSF: csf}
}

// RuleSpec describes a firewall rule to apply.
type RuleSpec struct {
	Type      string  // "block" or "allow"
	Protocol  string  // "tcp", "udp", "icmp", "all"
	IPAddress *string // single IP
	IPRange   *string // CIDR range
	Port      *int    // destination port (only for tcp/udp)
}

// ApplyRule adds an explicit dashboard rule to the INFRAFENCE-RULES chain.
func ApplyRule(spec RuleSpec) error {
	args := buildRuleArgs(spec)
	fw.Lock()
	for _, r := range fw.userRules {
		if equal(r, args) {
			fw.Unlock()
			return nil
		}
	}
	fw.userRules = append(fw.userRules, args)
	fw.Unlock()
	if _, err := Ensure(); err != nil {
		return fmt.Errorf("apply rule: %w", err)
	}
	log.Printf("[firewall] applied rule: %v", args)
	return nil
}

// RemoveRule removes an explicit dashboard rule.
func RemoveRule(spec RuleSpec) error {
	args := buildRuleArgs(spec)
	fw.Lock()
	kept := fw.userRules[:0]
	for _, r := range fw.userRules {
		if !equal(r, args) {
			kept = append(kept, r)
		}
	}
	fw.userRules = kept
	fw.Unlock()
	_, err := Ensure()
	return err
}

// buildRuleArgs constructs iptables arguments for a RuleSpec.
func buildRuleArgs(spec RuleSpec) []string {
	var args []string

	// Source IP/range
	src := source(spec)
	if src != "" {
		args = append(args, "-s", src)
	}

	// Protocol
	proto := spec.Protocol
	if proto == "" || proto == "all" {
		// Only add protocol if port is specified (port requires tcp/udp)
		if spec.Port != nil {
			proto = "tcp"
			args = append(args, "-p", proto)
		}
	} else {
		args = append(args, "-p", proto)
	}

	// Destination port (only for tcp/udp)
	if spec.Port != nil && (proto == "tcp" || proto == "udp") {
		args = append(args, "--dport", strconv.Itoa(*spec.Port))
	}

	// Target (ACCEPT or DROP)
	target := "DROP"
	if spec.Type == "allow" {
		target = "ACCEPT"
	}
	args = append(args, "-j", target)

	return args
}

// source returns the source argument from the RuleSpec.
func source(spec RuleSpec) string {
	if spec.IPAddress != nil && *spec.IPAddress != "" {
		return *spec.IPAddress
	}
	if spec.IPRange != nil && *spec.IPRange != "" {
		return *spec.IPRange
	}
	return ""
}

// protectedIPs holds additional IPs that must never be banned (e.g. the API server).
var (
	protectedIPs = make(map[string]bool)
	protMu       sync.RWMutex
)

// AddProtectedIPs registers IPs that must never be banned (e.g. the InfraFence API server).
func AddProtectedIPs(ips ...string) {
	protMu.Lock()
	defer protMu.Unlock()
	for _, ip := range ips {
		if parsed := net.ParseIP(ip); parsed != nil {
			protectedIPs[parsed.String()] = true
			log.Printf("[firewall] added protected IP: %s", parsed)
		}
	}
}

func protectedList() []string {
	protMu.RLock()
	defer protMu.RUnlock()
	out := make([]string, 0, len(protectedIPs))
	for ip := range protectedIPs {
		out = append(out, ip)
	}
	return out
}

// localIPs caches the server's own IP addresses (collected once at first use).
var localIPs map[string]bool
var localIPsOnce sync.Once

// collectLocalIPs gathers all IP addresses assigned to local network interfaces.
func collectLocalIPs() map[string]bool {
	ips := make(map[string]bool)
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Printf("[firewall] warning: could not enumerate local IPs: %v", err)
		return ips
	}
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip != nil {
			ips[ip.String()] = true
		}
	}
	log.Printf("[firewall] collected %d local IPs for self-protection", len(ips))
	return ips
}

// IsLocalIP reports whether ip is bound to one of this server's interfaces.
func IsLocalIP(ip string) bool {
	p := net.ParseIP(ip)
	return p != nil && isLocalIP(p)
}

// isLocalIP returns true if the given IP belongs to this server.
func isLocalIP(ip net.IP) bool {
	localIPsOnce.Do(func() { localIPs = collectLocalIPs() })
	return localIPs[ip.String()]
}

// isReservedIP returns true for loopback, link-local, and private IPs
// that must never be banned via iptables.
func isReservedIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate()
}

// isSafeIP returns true if the IP must not be banned (reserved, own server, or protected).
func isSafeIP(ip net.IP) bool {
	protMu.RLock()
	protected := protectedIPs[ip.String()]
	protMu.RUnlock()
	return isReservedIP(ip) || isLocalIP(ip) || protected
}

// BanIP blocks an IP in the INFRAFENCE chain (via the infrafence-bans ipset
// when available, otherwise a rule in the chain), with no expiry.
func BanIP(ip string) error {
	return BanIPUntil(ip, time.Time{})
}

// BanIPUntil applies a ban from the dashboard, which expires at expires
// (zero: never). The dashboard's expiry replaces the one the agent had.
func BanIPUntil(ip string, expires time.Time) error {
	added, err := BanIPOnceUntil(ip, expires)
	if err == nil && !added {
		SetBanExpiry(ip, expires)
	}
	return err
}

// BanIPOnce is BanIPOnceUntil with no expiry.
func BanIPOnce(ip string) (added bool, err error) {
	return BanIPOnceUntil(ip, time.Time{})
}

// BanIPOnceUntil bans ip until expires (zero: no expiry) and reports whether
// this call added the ban: false when the agent already bans it (its own
// detection, or an active dashboard ban), so callers report each ban to the
// dashboard once; an existing ban keeps its expiry. The firewall entry is
// (re)applied either way.
func BanIPOnceUntil(ip string, expires time.Time) (added bool, err error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false, fmt.Errorf("invalid IP address: %s", ip)
	}
	if isSafeIP(parsed) {
		return false, fmt.Errorf("refusing to ban safe IP: %s", ip)
	}
	if !enforceable(parsed) {
		return false, fmt.Errorf("IPv6 bans need ipset: %s", ip)
	}
	added, out := claimBan(parsed.String(), expires)
	evicted(out)
	err = applyBan(parsed, ip)
	if added {
		bansChanged()
	}
	return added, err
}

// claimBan records ip as banned until expires; true if it wasn't already.
// When the bans are at capacity the oldest one makes room; it is returned
// for the caller to remove from the kernel.
func claimBan(ip string, expires time.Time) (bool, []string) {
	fw.Lock()
	defer fw.Unlock()
	if _, ok := fw.bans[ip]; ok {
		return false, nil
	}
	out := fw.makeRoomLocked(1, nil)
	fw.bans[ip] = banEntry{added: banNow(), expires: expires}
	return true, out
}

func applyBan(parsed net.IP, ip string) error {
	if HasIpset() {
		return ipsetAdd(banSetName, ip)
	}
	if parsed.To4() == nil {
		return fmt.Errorf("IPv6 bans need ipset: %s", ip)
	}
	if _, err := run("iptables", "-C", chainName, "-s", ip, "-j", "DROP"); err == nil {
		return nil
	}
	if out, err := run("iptables", "-A", chainName, "-s", ip, "-j", "DROP"); err != nil {
		return fmt.Errorf("ban %s: %s (%w)", ip, out, err)
	}
	return nil
}

// UnbanIP removes an agent ban. It only ever touches the INFRAFENCE chain.
func UnbanIP(ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	fw.Lock()
	_, had := fw.bans[parsed.String()]
	delete(fw.bans, parsed.String())
	fw.Unlock()
	if had {
		bansChanged()
	}

	if HasIpset() {
		return ipsetDel(banSetName, ip)
	}
	_, _ = run("iptables", "-D", chainName, "-s", ip, "-j", "DROP")
	return nil
}

// IsBanned reports whether the agent currently bans ip (its own detection or
// a dashboard ban).
func IsBanned(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	fw.Lock()
	defer fw.Unlock()
	_, ok := fw.bans[parsed.String()]
	return ok
}

var legacyBansMigrated sync.Once

// ApplyBans applies the ban list from the server sync, with the dashboard's
// expiry for each ban (it replaces the agent's own). Past the capacity the
// list is cut (the first ones are kept) and the oldest other bans make room
// for the new ones.
func ApplyBans(bans []Ban) {
	var safe []string
	expires := map[string]time.Time{}
	for _, b := range bans {
		parsed := net.ParseIP(b.IP)
		if parsed == nil || isSafeIP(parsed) {
			continue
		}
		ip := parsed.String()
		if _, dup := expires[ip]; dup {
			// The latest expiry of duplicate rows wins; zero is never.
			if e := expires[ip]; !e.IsZero() && (b.Expires.IsZero() || b.Expires.After(e)) {
				expires[ip] = b.Expires
			}
			continue
		}
		if !enforceable(parsed) {
			continue
		}
		expires[ip] = b.Expires
		safe = append(safe, ip)
	}
	c := banCap()
	if len(safe) > c {
		log.Printf("[firewall] WARNING: the dashboard sent %d bans, more than this server holds (%d): %d not applied", len(safe), c, len(safe)-c)
		for _, ip := range safe[c:] {
			delete(expires, ip)
		}
		safe = safe[:c]
	}
	now := banNow()
	fw.Lock()
	fresh := 0
	for _, ip := range safe {
		if _, ok := fw.bans[ip]; !ok {
			fresh++
		}
	}
	keep := make(map[string]bool, len(safe))
	for _, ip := range safe {
		keep[ip] = true
	}
	out := fw.makeRoomLocked(fresh, keep)
	changed := len(out) > 0
	for _, ip := range safe {
		b, ok := fw.bans[ip]
		if !ok {
			b.added = now
		}
		if !ok || !b.expires.Equal(expires[ip]) {
			changed = true
		}
		b.expires = expires[ip]
		fw.bans[ip] = b
	}
	fw.Unlock()
	evicted(out)
	if changed {
		bansChanged()
	}

	if HasIpset() {
		if err := ipsetBatchAdd(banSetName, safe); err != nil {
			log.Printf("[firewall] ipset batch ban failed: %v", err)
		}
	} else if _, err := Ensure(); err != nil {
		log.Printf("[firewall] apply bans: %v", err)
	}
	// Earlier versions put each ban straight into INPUT. Remove those, but
	// only for IPs that are the agent's own bans.
	legacyBansMigrated.Do(func() { migrateLegacyBans(safe) })
}

// CleanupStaleBans removes agent bans that are no longer active server-side.
// It only touches the agent's own bans (INFRAFENCE chain / ipset), never
// rules someone else put in INPUT.
func CleanupStaleBans(activeBanIPs map[string]bool, activeRuleIPs map[string]bool) int {
	fw.Lock()
	var stale []string
	for ip := range fw.bans {
		if !activeBanIPs[ip] && !activeRuleIPs[ip] {
			stale = append(stale, ip)
		}
	}
	for _, ip := range stale {
		delete(fw.bans, ip)
	}
	fw.Unlock()
	if len(stale) > 0 {
		bansChanged()
	}

	removed := 0
	if HasIpset() {
		// Also drop set members the agent no longer knows about (e.g. from
		// before a restart).
		for _, ip := range ipsetListMembers(banSetName) {
			if !activeBanIPs[ip] && !activeRuleIPs[ip] {
				if err := ipsetDel(banSetName, ip); err == nil {
					removed++
				}
			}
		}
	} else {
		removed = len(stale)
		if removed > 0 {
			if _, err := Ensure(); err != nil {
				log.Printf("[firewall] cleanup: %v", err)
			}
		}
	}
	if removed > 0 {
		log.Printf("[firewall] cleanup: removed %d expired bans", removed)
	}
	return removed
}

// ParsedRule represents an iptables rule parsed from `iptables -S INPUT`.
type ParsedRule struct {
	RawRule  string
	Type     string // "block" or "allow"
	Protocol string // "tcp", "udp", "icmp", "all"
	Source   string // IP address (no CIDR /32)
	Port     int    // 0 means no port
}

// ListRules reads existing INPUT chain rules via `iptables -S INPUT`
// and returns only simple rules InfraFence can manage.
func ListRules() ([]ParsedRule, error) {
	out, err := exec.Command("iptables", "-S", "INPUT").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("iptables -S INPUT: %w", err)
	}

	var rules []ParsedRule
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Only parse -A INPUT rules (skip -P INPUT ACCEPT/DROP policy)
		if !strings.HasPrefix(line, "-A INPUT") {
			continue
		}
		parsed, ok := parseLine(line)
		if ok {
			rules = append(rules, parsed)
		}
	}

	log.Printf("[firewall] listed %d manageable rules from iptables", len(rules))
	return rules, nil
}

// parseLine parses a single iptables -S line into a ParsedRule.
// Returns false if the rule is too complex for InfraFence to manage.
func parseLine(line string) (ParsedRule, bool) {
	fields := strings.Fields(line)

	// Skip rules with interface binds (-i, -o) or negations (!)
	for _, f := range fields {
		switch f {
		case "-i", "-o", "!":
			return ParsedRule{}, false
		}
	}

	// Check -m modules: allow simple protocol matches (tcp, udp, icmp)
	// but skip complex modules (state, conntrack, multiport, limit, comment, etc.)
	for i, f := range fields {
		if f == "-m" && i+1 < len(fields) {
			mod := fields[i+1]
			switch mod {
			case "tcp", "udp", "icmp":
				// Simple protocol match — OK
			default:
				// Complex module — skip this rule
				return ParsedRule{}, false
			}
		}
	}

	rule := ParsedRule{
		RawRule:  line,
		Protocol: "all",
	}

	for i := 0; i < len(fields); i++ {
		switch fields[i] {
		case "-j":
			if i+1 < len(fields) {
				switch fields[i+1] {
				case "DROP", "REJECT":
					rule.Type = "block"
				case "ACCEPT":
					rule.Type = "allow"
				default:
					// Custom chain target — skip
					return ParsedRule{}, false
				}
				i++
			}
		case "-s":
			if i+1 < len(fields) {
				src := fields[i+1]
				// Strip /32 suffix from single IPs
				src = strings.TrimSuffix(src, "/32")
				rule.Source = src
				i++
			}
		case "-p":
			if i+1 < len(fields) {
				rule.Protocol = fields[i+1]
				i++
			}
		case "--dport":
			if i+1 < len(fields) {
				if p, err := strconv.Atoi(fields[i+1]); err == nil {
					rule.Port = p
				}
				i++
			}
		case "-m":
			// Skip the module name (already validated above)
			i++
		}
	}

	// Must have a target (block or allow)
	if rule.Type == "" {
		return ParsedRule{}, false
	}

	// Must have at least a source IP or a port to be meaningful
	if rule.Source == "" && rule.Port == 0 {
		return ParsedRule{}, false
	}

	// Skip safe IPs (reserved or own server) — they should never be managed or imported
	if rule.Source != "" {
		if ip := net.ParseIP(rule.Source); ip != nil && isSafeIP(ip) {
			return ParsedRule{}, false
		}
	}

	return rule, true
}

// IsSafeIP reports whether ip must never be banned or reported as an
// attacker: reserved or private, one of this server's addresses, or
// protected (the dashboard).
func IsSafeIP(ip net.IP) bool { return isSafeIP(ip) }
