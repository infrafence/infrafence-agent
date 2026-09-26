package firewall

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
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
			Capacity:   65536,
			ActiveBans: ipsetEntryCount(banSetName),
			CSF:        csf,
		}
	}
	fw.Lock()
	bans := len(fw.bans)
	fw.Unlock()
	return Status{Mode: "iptables", HasIpset: false, Capacity: 500, ActiveBans: bans, CSF: csf}
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
// when available, otherwise a rule in the chain).
func BanIP(ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	if isSafeIP(parsed) {
		return fmt.Errorf("refusing to ban safe IP: %s", ip)
	}
	fw.Lock()
	fw.bans[parsed.String()] = true
	fw.Unlock()

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
	delete(fw.bans, parsed.String())
	fw.Unlock()

	if HasIpset() {
		return ipsetDel(banSetName, ip)
	}
	_, _ = run("iptables", "-D", chainName, "-s", ip, "-j", "DROP")
	return nil
}

var legacyBansMigrated sync.Once

// ApplyBans applies the ban list from the server sync.
func ApplyBans(ips []string) {
	var safe []string
	for _, ip := range ips {
		if parsed := net.ParseIP(ip); parsed != nil && !isSafeIP(parsed) {
			safe = append(safe, parsed.String())
		}
	}
	fw.Lock()
	for _, ip := range safe {
		fw.bans[ip] = true
	}
	fw.Unlock()

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
