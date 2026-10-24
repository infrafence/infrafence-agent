package firewall

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Everything the agent enforces lives in its own chains, so it never has to
// guess which rules in INPUT are its own (earlier versions deleted any simple
// "-s IP -j DROP" in INPUT they didn't recognize — including the customer's):
//
//	INFRAFENCE        jumped to from INPUT and, when Docker is present, from
//	                  DOCKER-USER (published container ports never traverse
//	                  INPUT). Allow-list RETURNs first, then DROPs for bans,
//	                  threat feeds and blocked countries. Never ACCEPTs: a
//	                  whitelisted IP is simply not blocked by InfraFence, it
//	                  does not bypass the host's own rules.
//	INFRAFENCE-RULES  explicit rules created from the dashboard (may ACCEPT),
//	                  jumped to from INPUT only.
//	INFRAFENCE-PORTS, INFRAFENCE-EGRESS
//	                  closed ports and blocked egress, see portsegress.go.
//
// Ensure() re-creates chains, jumps and sets when another tool (ufw reload,
// firewall-cmd --reload, csf -r, netfilter-persistent, iptables-restore)
// removes them, and keeps the INPUT jump ahead of any rule that can ACCEPT.
const (
	chainName      = "INFRAFENCE"
	rulesChainName = "INFRAFENCE-RULES"
	allowSetName   = "infrafence-allow"
	jumpComment    = "infrafence"
	rulesComment   = "infrafence-rules"
	dockerChain    = "DOCKER-USER"
)

type fwState struct {
	sync.Mutex
	initialized bool
	allow       []string            // whitelist IPs/CIDRs from the dashboard
	bans        map[string]banEntry // every IP currently banned by the agent
	// disabled: protection is switched off (Disable): nothing of the
	// agent's is in the kernel and nothing is put there until Enable; the
	// desired state above is kept.
	disabled bool
	// restored: bans were loaded from the state file (RestoreBans) and are
	// not in the ipset yet.
	restored    bool
	threat      []string // threat-feed CIDRs; nil when not blocking
	geo         map[string][]string
	userRules   [][]string // iptables args of dashboard rules, in order
	closedPorts []int      // TCP ports closed to public sources
	egress      []string   // IPv4 addresses the host may not reach
	legacyDone  bool

	// What the chains looked like right after our last rebuild, as iptables
	// prints them (it normalizes, e.g. adds /32 and -m tcp), and the desired
	// state that produced it. Drift = chains differ from that snapshot.
	lastDesired string
	applied     map[string][]string
	// Desired state whose port/egress rules iptables refused (e.g. no
	// conntrack match): not retried until the state changes, and the other
	// chains are kept working without them.
	peFailedKey string
	// peInForce: the port and egress rules of the current state are in the
	// kernel (false while they are left out after a failure).
	peInForce bool
	// egressSetErr is the last failure to fill the infrafence-egress set.
	egressSetErr error

	// IPv6 mirror of INFRAFENCE-PORTS (ports6.go): the desired contents
	// last applied, the chain as ip6tables printed it then, a desired state
	// ip6tables refused, and whether the closed ports are in force.
	v6Desired   string
	v6Applied   []string
	v6FailedKey string
	v6InForce   bool
}

var fw = &fwState{bans: map[string]banEntry{}, geo: map[string][]string{}}

// run executes iptables with args and returns combined output.
var run = func(name string, args ...string) (string, error) {
	return command("", name, args...)
}

var runStdin = func(stdin, name string, args ...string) (string, error) {
	return command(stdin, name, args...)
}

// execTimeout bounds every command the firewall code runs: a wedged
// iptables or ipset must not stall the guard or keep fw locked (the
// callers hold fw only through deferred unlocks, so a timeout releases it).
var execTimeout = 15 * time.Second

func command(stdin, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, withWait(name, args)...)
	// A child that keeps the output pipe open must not outlive the timeout.
	cmd.WaitDelay = time.Second
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("%s timed out after %s: %w", name, execTimeout, ctx.Err())
	}
	return strings.TrimSpace(string(out)), err
}

// waitBins wait up to 5 s for the xtables lock with "-w 5" instead of
// failing at once while another tool (csf, fail2ban) holds it. Versions
// older than 1.6 lack "-w <seconds>", so support is probed once per binary.
var (
	waitBins = map[string]bool{"iptables": true, "ip6tables": true, "iptables-restore": true, "ip6tables-restore": true, "iptables-legacy": true, "ip6tables-legacy": true}
	waitOK   sync.Map // binary name -> bool
)

func withWait(name string, args []string) []string {
	if !waitBins[name] {
		return args
	}
	ok, probed := waitOK.Load(name)
	if !probed {
		ok = probeWait(name)
		waitOK.Store(name, ok)
	}
	if !ok.(bool) {
		return args
	}
	return append([]string{"-w", "5"}, args...)
}

func probeWait(name string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
	defer cancel()
	return exec.CommandContext(ctx, name, "-w", "5", "-V").Run() == nil
}

// allowEntries is everything InfraFence must never block: reserved ranges
// are handled by isSafeIP, so this is protected IPs, public local IPs and
// the dashboard whitelist.
func (s *fwState) allowEntries() []string {
	seen := map[string]bool{}
	var out []string
	add := func(v string) {
		if n := parseNet(v); n != nil && n.IP.To4() != nil && !seen[n.String()] {
			seen[n.String()] = true
			out = append(out, n.String())
		}
	}
	for _, ip := range protectedList() {
		add(ip)
	}
	localIPsOnce.Do(func() { localIPs = collectLocalIPs() })
	for ip := range localIPs {
		if p := net.ParseIP(ip); p != nil && !isReservedIP(p) {
			add(ip)
		}
	}
	for _, a := range s.allow {
		add(a)
	}
	sort.Strings(out)
	return out
}

// desiredRules returns the exact contents of both chains as iptables -S lines.
func (s *fwState) desiredRules(ipset bool) (main []string, user []string) {
	allow := s.allowEntries()
	if ipset {
		if len(allow) > 0 {
			main = append(main, fmt.Sprintf("-A %s -m set --match-set %s src -j RETURN", chainName, allowSetName))
		}
		main = append(main, subJumps()...)
		main = append(main, fmt.Sprintf("-A %s -m set --match-set %s src -j DROP", chainName, banSetName))
		if s.threat != nil {
			main = append(main, fmt.Sprintf("-A %s -m set --match-set %s src -j DROP", chainName, threatSetName))
		}
		var geo []string
		for set := range s.geo {
			geo = append(geo, set)
		}
		sort.Strings(geo)
		for _, set := range geo {
			main = append(main, fmt.Sprintf("-A %s -m set --match-set %s src -j DROP", chainName, set))
		}
	} else {
		for _, a := range allow {
			main = append(main, fmt.Sprintf("-A %s -s %s -j RETURN", chainName, a))
		}
		main = append(main, subJumps()...)
		var bans []string
		for ip := range s.bans {
			if n := parseNet(ip); n != nil && n.IP.To4() != nil {
				bans = append(bans, n.String())
			}
		}
		sort.Strings(bans)
		for _, b := range bans {
			main = append(main, fmt.Sprintf("-A %s -s %s -j DROP", chainName, b))
		}
	}
	for _, r := range s.userRules {
		user = append(user, "-A "+rulesChainName+" "+strings.Join(r, " "))
	}
	return main, user
}

func subJumps() []string {
	return []string{
		fmt.Sprintf("-A %s -j %s", chainName, portsChainName),
		fmt.Sprintf("-A %s -j %s", chainName, egressChainName),
	}
}

// ensureSets (re)creates and repopulates the ipsets the chain references.
// A set can also survive emptied: "csf -r" with LF_IPSET=1 flushes every
// set before destroying it, and the destroy fails for a set that a rule
// still references (in the other iptables backend, say); a set left with
// fewer entries than it should have is filled again.
func (s *fwState) ensureSets() (repaired []string) {
	existing := map[string]bool{}
	if out, err := run("ipset", "list", "-n"); err == nil {
		for _, n := range strings.Fields(out) {
			existing[n] = true
		}
	}
	// Entries per set, from one listing of every set's header, read the
	// first time a set that exists may need them.
	var entries map[string]int
	count := func(name string) (int, bool) {
		if entries == nil {
			entries = setEntries()
		}
		n, ok := entries[name]
		return n, ok
	}
	if !existing[banSetName] {
		if err := createIpsetHashIP(banSetName); err == nil {
			var ips []string
			for ip := range s.bans {
				ips = append(ips, ip)
			}
			_ = ipsetBatchAdd(banSetName, ips)
			repaired = append(repaired, "set:"+banSetName)
		}
	} else if ips, settled := s.v4Bans(); len(ips) > 0 {
		if n, ok := count(banSetName); ok && n < len(ips) {
			if err := refillSet(banSetName, ips); err != nil {
				log.Printf("[firewall] ban set: %v", err)
			} else if n < settled {
				// (A ban just recorded may not be in the set yet: the
				// ipset add follows, outside the lock. Not a repair.)
				repaired = append(repaired, "set-contents:"+banSetName)
			}
		}
	}
	allow := s.allowEntries()
	if len(allow) > 0 {
		if err := replaceNetSet(allowSetName, allow); err != nil {
			log.Printf("[firewall] allow set: %v", err)
		} else if !existing[allowSetName] {
			repaired = append(repaired, "set:"+allowSetName)
		}
	}
	if s.threat != nil {
		if what := netSetRepair(threatSetName, s.threat, existing[threatSetName], count); what != "" {
			repaired = append(repaired, what)
		}
	}
	for set, cidrs := range s.geo {
		if what := netSetRepair(set, cidrs, existing[set], count); what != "" {
			repaired = append(repaired, what)
		}
	}
	s.egressSetErr = s.ensureEgressSet()
	if err := s.egressSetErr; err != nil {
		log.Printf("[firewall] egress set: %v", err)
	} else if !existing[egressSetName] && len(s.egress) > 0 {
		repaired = append(repaired, "set:"+egressSetName)
	}
	return repaired
}

// v4Bans are the bans the ban set holds (a hash:ip set of family inet),
// and how many of them are older than banSettle.
func (s *fwState) v4Bans() (ips []string, settled int) {
	cutoff := banNow().Add(-banSettle)
	for ip, b := range s.bans {
		if p := net.ParseIP(ip); p != nil && p.To4() != nil {
			ips = append(ips, ip)
			if b.added.Before(cutoff) {
				settled++
			}
		}
	}
	sort.Strings(ips)
	return ips, settled
}

// banSettle is how long a new ban may take to reach the ban set.
const banSettle = 30 * time.Second

// netSetRepair recreates a missing hash:net set, or refills one that has
// been emptied, and names the repair ("" for none).
func netSetRepair(name string, cidrs []string, exists bool, count func(string) (int, bool)) string {
	if exists {
		if n, ok := count(name); !ok || n > 0 || len(cidrs) == 0 {
			return ""
		}
	}
	if err := replaceNetSet(name, cidrs); err != nil {
		return ""
	}
	if exists {
		return "set-contents:" + name
	}
	return "set:" + name
}

// setEntries reads every set's number of entries from the headers "ipset
// list -t" prints; a set whose count cannot be read is left out.
func setEntries() map[string]int {
	counts := map[string]int{}
	out, err := run("ipset", "list", "-t")
	if err != nil {
		return counts
	}
	name := ""
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if v, found := strings.CutPrefix(l, "Name:"); found {
			name = strings.TrimSpace(v)
		} else if v, found := strings.CutPrefix(l, "Number of entries:"); found && name != "" {
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				counts[name] = n
			}
			name = ""
		}
	}
	return counts
}

// refillSet adds ips to a set again (those still in it are kept).
func refillSet(name string, ips []string) error {
	var b strings.Builder
	for _, ip := range ips {
		fmt.Fprintf(&b, "add %s %s -exist\n", name, ip)
	}
	if out, err := runStdin(b.String(), "ipset", "restore"); err != nil {
		return fmt.Errorf("ipset restore %s: %s (%w)", name, out, err)
	}
	return nil
}

// replaceNetSet atomically replaces the contents of a hash:net set.
func replaceNetSet(name string, cidrs []string) error {
	tmp := name + "-tmp"
	if err := createIpsetHashNet(name); err != nil {
		return err
	}
	if err := createIpsetHashNet(tmp); err != nil {
		return err
	}
	defer destroyIpset(tmp)
	if err := flushIpset(tmp); err != nil {
		return err
	}
	if err := populateIpsetBatch(tmp, cidrs); err != nil {
		return err
	}
	if out, err := run("ipset", "swap", tmp, name); err != nil {
		return fmt.Errorf("ipset swap %s: %s (%w)", name, out, err)
	}
	return nil
}

// currentRules returns the -A lines of a chain, or ok=false if it's missing.
func currentRules(chain string) (lines []string, ok bool) {
	return currentRulesOf("iptables", chain)
}

// currentRulesOf is currentRules for iptables or ip6tables.
func currentRulesOf(bin, chain string) (lines []string, ok bool) {
	out, err := run(bin, "-S", chain)
	if err != nil {
		return nil, false
	}
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "-A ") {
			lines = append(lines, strings.TrimSpace(l))
		}
	}
	return lines, true
}

// errPortsEgress: iptables refused the closed-port or egress rules; every
// other chain was applied without them.
var errPortsEgress = errors.New("closed ports and egress blocks not applied")

// ourChains are rebuilt together, in this order, by syncChains.
var ourChains = []string{chainName, rulesChainName, portsChainName, egressChainName}

// syncChains makes every chain contain exactly the desired rules, atomically.
func (s *fwState) syncChains(ipset bool) (repaired []string, err error) {
	want := map[string][]string{}
	want[chainName], want[rulesChainName] = s.desiredRules(ipset)
	want[portsChainName], want[egressChainName] = s.portsEgressRules(ipset)
	key := chainsKey(want)
	withPE := true
	if key == s.peFailedKey {
		want[portsChainName], want[egressChainName] = nil, nil
		key = chainsKey(want)
		withPE = false
	}
	have := map[string][]string{}
	allPresent, same := true, key == s.lastDesired
	for _, c := range ourChains {
		lines, ok := currentRules(c)
		if !ok {
			allPresent = false
		}
		have[c] = lines
		if !equal(lines, s.applied[c]) {
			same = false
		}
	}
	if allPresent && same {
		s.peInForce = withPE
		return nil, nil
	}
	drift := s.lastDesired != "" && key == s.lastDesired
	var peErr error
	if err := restoreChains(want); err != nil {
		if len(want[portsChainName])+len(want[egressChainName]) == 0 {
			return nil, err
		}
		// Keep bans and rules working without the port/egress rules.
		peErr = err
		failedKey := key
		want[portsChainName], want[egressChainName] = nil, nil
		if err := restoreChains(want); err != nil {
			s.peInForce = false
			return nil, err
		}
		s.peFailedKey = failedKey
		key = chainsKey(want)
		withPE = false
	}
	s.peInForce = withPE
	s.lastDesired = key
	s.applied = map[string][]string{}
	for _, c := range ourChains {
		s.applied[c], _ = currentRules(c)
	}
	// Only report a repair when something outside the agent changed the
	// chains; rebuilding because the agent's own state changed is normal.
	if !allPresent {
		repaired = append(repaired, "chain")
	} else if drift {
		repaired = append(repaired, "chain-contents")
	}
	if peErr != nil {
		return repaired, fmt.Errorf("%w: %v", errPortsEgress, peErr)
	}
	return repaired, nil
}

func chainsKey(want map[string][]string) string {
	var b strings.Builder
	for _, c := range ourChains {
		b.WriteString(strings.Join(want[c], "\n"))
		b.WriteString("\n--\n")
	}
	return b.String()
}

// restoreChains replaces the contents of our chains in one iptables-restore.
func restoreChains(want map[string][]string) error {
	var b strings.Builder
	b.WriteString("*filter\n")
	for _, c := range ourChains {
		fmt.Fprintf(&b, ":%s - [0:0]\n", c)
	}
	for _, c := range ourChains {
		for _, l := range want[c] {
			b.WriteString(l + "\n")
		}
	}
	b.WriteString("COMMIT\n")
	if out, err := runStdin(b.String(), "iptables-restore", "--noflush"); err != nil {
		return fmt.Errorf("iptables-restore: %s (%w)", out, err)
	}
	return nil
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// mayAccept reports whether an INPUT rule can accept traffic before it
// reaches later rules: an ACCEPT, or a jump to another chain that isn't
// known to only drop (fail2ban, CrowdSec) or to be ours.
func mayAccept(line string) bool {
	f := strings.Fields(line)
	for i := 0; i+1 < len(f); i++ {
		if f[i] != "-j" && f[i] != "-g" {
			continue
		}
		t := f[i+1]
		switch {
		case t == "ACCEPT":
			return true
		case t == "DROP" || t == "REJECT" || t == "RETURN" || t == "LOG":
			return false
		case t == chainName || t == rulesChainName || t == portsChainName || t == egressChainName:
			return false
		case strings.HasPrefix(t, "f2b-") || strings.HasPrefix(t, "fail2ban") || strings.HasPrefix(strings.ToLower(t), "crowdsec"):
			return false
		default:
			return true
		}
	}
	return false
}

func jumpArgs(comment, target string) []string {
	return []string{"-m", "comment", "--comment", comment, "-j", target}
}

func jumpLine(chain, comment, target string) string {
	return "-A " + chain + " " + strings.Join(jumpArgs(comment, target), " ")
}

// ensureInputJumps keeps the INFRAFENCE jump ahead of the first rule that can
// ACCEPT, and the INFRAFENCE-RULES jump right after it.
func ensureInputJumps() (repaired []string, err error) {
	repaired, err = ensureJumpAhead("INPUT", jumpComment, chainName)
	if err != nil {
		return nil, err
	}
	main := jumpLine("INPUT", jumpComment, chainName)

	if _, err := run("iptables", append([]string{"-C", "INPUT"}, jumpArgs(rulesComment, rulesChainName)...)...); err != nil {
		lines, _ := currentRules("INPUT")
		pos := 1
		for i, l := range lines {
			if l == main {
				pos = i + 2
				break
			}
		}
		if out, err := run("iptables", append([]string{"-I", "INPUT", strconv.Itoa(pos)}, jumpArgs(rulesComment, rulesChainName)...)...); err != nil {
			return repaired, fmt.Errorf("insert rules jump: %s (%w)", out, err)
		}
		repaired = append(repaired, "jump:INPUT-rules")
	}
	return repaired, nil
}

// ensureJumpAhead keeps a jump from chain to target ahead of the first rule
// of chain that can ACCEPT.
func ensureJumpAhead(chain, comment, target string) (repaired []string, err error) {
	return ensureJumpAheadOf("iptables", chain, comment, target)
}

// ensureJumpAheadOf is ensureJumpAhead for iptables or ip6tables.
func ensureJumpAheadOf(bin, chain, comment, target string) (repaired []string, err error) {
	prefix := ""
	if bin != "iptables" {
		prefix = bin + ":"
	}
	lines, ok := currentRulesOf(bin, chain)
	if !ok {
		return nil, fmt.Errorf("cannot list %s", chain)
	}
	ours, firstAccept := jumpPosition(lines, jumpLine(chain, comment, target))
	switch {
	case ours < 0:
		if out, err := run(bin, append([]string{"-I", chain, "1"}, jumpArgs(comment, target)...)...); err != nil {
			return nil, fmt.Errorf("insert %s jump: %s (%w)", chain, out, err)
		}
		repaired = append(repaired, "jump:"+prefix+chain)
	case firstAccept >= 0 && ours > firstAccept:
		// Insert the new jump first, then delete the old one by number, so
		// there is never a moment without it.
		if out, err := run(bin, append([]string{"-I", chain, "1"}, jumpArgs(comment, target)...)...); err != nil {
			return nil, fmt.Errorf("move %s jump: %s (%w)", chain, out, err)
		}
		if out, err := run(bin, "-D", chain, strconv.Itoa(ours+2)); err != nil {
			return nil, fmt.Errorf("remove old %s jump: %s (%w)", chain, out, err)
		}
		repaired = append(repaired, "jump-order:"+prefix+chain)
	}
	return repaired, nil
}

// jumpPosition returns the index of jump in lines and of the first rule
// that can ACCEPT, -1 for none.
func jumpPosition(lines []string, jump string) (ours, firstAccept int) {
	ours, firstAccept = -1, -1
	for i, l := range lines {
		if l == jump && ours < 0 {
			ours = i
		}
		if firstAccept < 0 && mayAccept(l) {
			firstAccept = i
		}
	}
	return ours, firstAccept
}

// ensureDockerJump protects containers with published ports: that traffic
// is forwarded, so it goes through DOCKER-USER, never INPUT.
func ensureDockerJump() (repaired []string) {
	return ensureFirstJump("iptables", dockerChain, jumpComment, chainName)
}

// ensureFirstJump keeps a jump to target as the first rule of chain, when
// chain exists.
func ensureFirstJump(bin, chain, comment, target string) (repaired []string) {
	lines, ok := currentRulesOf(bin, chain)
	if !ok {
		return nil // no Docker (yet)
	}
	jump := jumpLine(chain, comment, target)
	if len(lines) > 0 && lines[0] == jump {
		return nil
	}
	// Present but not first: remove it before re-inserting at the top.
	for i := len(lines) - 1; i >= 0; i-- {
		if lines[i] == jump {
			_, _ = run(bin, "-D", chain, strconv.Itoa(i+1))
		}
	}
	if out, err := run(bin, append([]string{"-I", chain, "1"}, jumpArgs(comment, target)...)...); err != nil {
		log.Printf("[firewall] insert %s %s jump: %s (%v)", bin, chain, out, err)
		return nil
	}
	if bin != "iptables" {
		return []string{"jump:" + bin + ":" + chain}
	}
	return []string{"jump:" + chain}
}

// migrateLegacy removes rules that earlier versions put straight into INPUT
// and that are provably InfraFence's: DROPs matching an infrafence-* ipset.
// Anything else in INPUT (including ACCEPTs earlier versions inserted for
// protected IPs) is left alone, because it could be the customer's.
func migrateLegacy() {
	lines, ok := currentRules("INPUT")
	if !ok {
		return
	}
	for i := len(lines) - 1; i >= 0; i-- {
		l := lines[i]
		if strings.Contains(l, "--match-set infrafence-") && strings.HasSuffix(l, "-j DROP") {
			if out, err := run("iptables", "-D", "INPUT", strconv.Itoa(i+1)); err != nil {
				log.Printf("[firewall] migrate: could not remove legacy rule %q: %s", l, out)
			} else {
				log.Printf("[firewall] migrate: moved legacy rule into %s chain: %s", chainName, l)
			}
		}
	}
}

// migrateLegacyBans removes old per-IP DROP rules from INPUT, but only for
// IPs that are the agent's own bans (they now live in the INFRAFENCE chain).
func migrateLegacyBans(ips []string) {
	for _, ip := range ips {
		if _, err := run("iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"); err == nil {
			_, _ = run("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
		}
	}
}

// EnsureResult lists what Ensure had to repair.
type EnsureResult struct {
	Repairs []string
	// First is true for the initial setup at startup (not a repair).
	First bool
}

// Ensure makes the host's firewall match the agent's state. Safe to call
// often: it only changes what is missing or wrong.
func Ensure() (EnsureResult, error) {
	fw.Lock()
	defer fw.Unlock()
	res := EnsureResult{First: !fw.initialized}
	if fw.disabled {
		return res, nil
	}

	ipset := HasIpset()
	if ipset {
		res.Repairs = append(res.Repairs, fw.ensureSets()...)
		// Bans restored from the state file: an existing set (the agent
		// restarted, the host did not) may lack some of them. Retried at
		// the next Ensure until it works.
		if fw.restored {
			ips := make([]string, 0, len(fw.bans))
			for ip := range fw.bans {
				ips = append(ips, ip)
			}
			if err := ipsetBatchAdd(banSetName, ips); err != nil {
				log.Printf("[firewall] restore bans: %v", err)
			} else {
				fw.restored = false
			}
		}
	}
	r, err := fw.syncChains(ipset)
	res.Repairs = append(res.Repairs, r...)
	var peErr error
	if errors.Is(err, errPortsEgress) {
		peErr, err = err, nil
	}
	if err != nil {
		return res, err
	}
	if !fw.legacyDone {
		migrateLegacy()
		fw.legacyDone = true
	}
	r, err = ensureInputJumps()
	res.Repairs = append(res.Repairs, r...)
	if err != nil {
		return res, err
	}
	r, err = ensureJumpAhead("OUTPUT", egressComment, egressChainName)
	res.Repairs = append(res.Repairs, r...)
	if err != nil {
		return res, err
	}
	res.Repairs = append(res.Repairs, ensureDockerJump()...)
	res.Repairs = append(res.Repairs, fw.ensurePorts6()...)
	// Only now, and only what is in force in nf_tables.
	res.Repairs = append(res.Repairs, removeStaleLegacy(peErr == nil, fw.v6InForce, false)...)
	fw.initialized = true
	return res, peErr
}

// NeedsRepair reports whether the INPUT jump to the INFRAFENCE chain is
// gone or no longer ahead of the first rule that can ACCEPT (a banned
// address would pass behind it), with a single "iptables -S INPUT": cheap
// enough for the guard to ask every few seconds, so the bans are back within
// seconds of a firewall rebuild (csf -r, a ufw or firewalld reload,
// iptables-restore) instead of at the next full Ensure. An error (iptables
// failed or timed out) is not a verdict. False before the first Ensure and
// while switched off.
func NeedsRepair() (bool, error) {
	fw.Lock()
	skip := !fw.initialized || fw.disabled
	fw.Unlock()
	if skip {
		return false, nil
	}
	out, err := run("iptables", "-S", "INPUT")
	if err != nil {
		return false, fmt.Errorf("iptables -S INPUT: %s (%w)", out, err)
	}
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "-A ") {
			lines = append(lines, strings.TrimSpace(l))
		}
	}
	ours, firstAccept := jumpPosition(lines, jumpLine("INPUT", jumpComment, chainName))
	return ours < 0 || (firstAccept >= 0 && ours > firstAccept), nil
}

// SetAllowList sets the dashboard whitelist (IPs or CIDRs). InfraFence never
// blocks them; it does not open anything in the host firewall for them.
// Egress blocks to an address the list now covers are lifted.
func SetAllowList(entries []string) {
	fw.Lock()
	changed := !equal(fw.allow, entries)
	fw.allow = append([]string{}, entries...)
	if changed {
		kept := fw.egress[:0:0]
		for _, ip := range fw.egress {
			if reason := fw.egressRefusal(ip); reason != "" {
				log.Printf("[firewall] egress block to %s lifted: %s", ip, reason)
				continue
			}
			kept = append(kept, ip)
		}
		fw.egress = kept
	}
	fw.Unlock()
	if changed {
		if _, err := Ensure(); err != nil {
			log.Printf("[firewall] apply allow list: %v", err)
		}
	}
}

// ErrDisabled is returned by changes refused while protection is off.
var ErrDisabled = errors.New("InfraFence protection is switched off on this server")

// Disabled reports whether protection is switched off (Disable).
func Disabled() bool {
	fw.Lock()
	defer fw.Unlock()
	return fw.disabled
}

// SetDisabled marks protection as off without touching the kernel: at
// startup, before Init, when it was switched off before the restart.
func SetDisabled(off bool) {
	fw.Lock()
	fw.disabled = off
	fw.Unlock()
}

// Disable switches InfraFence's protection off: it removes every chain,
// jump and set of its own (RemoveAll: other tools' rules and the tables are
// never touched) and keeps them out, whatever Ensure, bans, country blocks
// or threat feeds ask, until Enable. What it should enforce is kept in
// memory for Enable. It returns what was removed.
func Disable() []string {
	fw.Lock()
	fw.disabled = true
	fw.resetSnapshotsLocked()
	fw.Unlock()
	return RemoveAll()
}

// Enable switches protection back on and rebuilds the chains and sets from
// the kept state (the sync that follows brings the dashboard's).
func Enable() (EnsureResult, error) {
	fw.Lock()
	fw.disabled = false
	fw.resetSnapshotsLocked()
	fw.restored = len(fw.bans) > 0 // an existing ban set may lack them
	fw.Unlock()
	return Ensure()
}

// resetSnapshotsLocked forgets what the chains looked like, so the next
// Ensure rebuilds them all.
func (s *fwState) resetSnapshotsLocked() {
	s.lastDesired, s.applied = "", nil
	s.peFailedKey, s.peInForce = "", false
	s.v6Desired, s.v6Applied, s.v6FailedKey, s.v6InForce = "", nil, "", false
	s.legacyDone = true
}

// RestoreAllowList sets the allow list saved before a restart, before Init,
// so the first setup already exempts it (SetAllowList would set the firewall
// up at once).
func RestoreAllowList(entries []string) {
	fw.Lock()
	fw.allow = append([]string{}, entries...)
	fw.Unlock()
}

// RemoveAll removes every chain, jump and set InfraFence created. Used by
// "infrafence-agent uninstall --clean".
func RemoveAll() []string {
	done := removeChainsOf("iptables")
	migrateLegacy()
	done = append(done, removePorts6()...)
	done = append(done, removeStaleLegacy(true, true, true)...)
	if HasIpset() {
		if out, err := run("ipset", "list", "-n"); err == nil {
			for _, n := range strings.Fields(out) {
				if strings.HasPrefix(n, "infrafence-") {
					if _, err := run("ipset", "destroy", n); err == nil {
						done = append(done, "set:"+n)
					}
				}
			}
		}
	}
	return done
}

// removeChainsOf removes the agent's IPv4 jumps and chains with bin
// (iptables, or iptables-legacy for a backend the host left).
func removeChainsOf(bin string) []string {
	prefix := ""
	if bin != "iptables" {
		prefix = bin + ":"
	}
	var done []string
	for _, c := range []struct{ chain, comment, target string }{
		{"INPUT", jumpComment, chainName},
		{"INPUT", rulesComment, rulesChainName},
		{dockerChain, jumpComment, chainName},
		{"OUTPUT", egressComment, egressChainName},
	} {
		for {
			if _, err := run(bin, append([]string{"-D", c.chain}, jumpArgs(c.comment, c.target)...)...); err != nil {
				break
			}
			done = append(done, "jump:"+prefix+c.chain+"->"+c.target)
		}
	}
	// Flush all first: INFRAFENCE jumps to the ports and egress chains.
	var flushed []string
	for _, ch := range ourChains {
		if _, err := run(bin, "-F", ch); err == nil {
			flushed = append(flushed, ch)
		}
	}
	for _, ch := range flushed {
		_, _ = run(bin, "-X", ch)
		done = append(done, "chain:"+prefix+ch)
	}
	return done
}

// The x_tables (legacy) tables loaded in the kernel, one name a line.
var (
	legacyTables4 = "/proc/net/ip_tables_names"
	legacyTables6 = "/proc/net/ip6_tables_names"
)

// removeStaleLegacy removes the agent's chains from the legacy backend
// when iptables (ip6tables for IPv6) is now the nf_tables one: on Fedora
// "dnf install iptables" gives iptables-legacy, and CSF's installer
// switches the iptables command to iptables-nft once that is installed.
// The agent then rebuilds everything in nf_tables, and the legacy copy is
// stale: it keeps closed ports and dashboard rules that were changed since,
// and its references keep the sets from being destroyed. Only ever the
// agent's own jumps and chains, and only where the nf_tables copy is in
// force (v4, v6: false while its rules were refused there, so the legacy
// copy stays the one that works). Left alone while Docker's DOCKER-USER
// chain is only in legacy (Docker still runs on that backend until it
// restarts): there the legacy jump is what protects published ports;
// uninstall removes them all the same. Nothing when the legacy filter table is not loaded (listing it would load
// it).
func removeStaleLegacy(v4, v6, uninstall bool) []string {
	v4 = v4 && tableLoaded(legacyTables4, "filter")
	v6 = v6 && tableLoaded(legacyTables6, "filter")
	if !v4 && !v6 {
		return nil
	}
	isNft := func(bin string) bool {
		out, err := run(bin, "-V")
		return err == nil && strings.Contains(out, "nf_tables")
	}
	legacy := func(bin string) string {
		out, err := run(bin, "-S")
		if err != nil || !strings.Contains(out, chainName) {
			return ""
		}
		return out
	}
	// Docker still on legacy: our jump from its DOCKER-USER is there, and
	// the nf_tables backend has no DOCKER-USER chain.
	dockerOnLegacy := func(bin, legacyRules, comment, target string) bool {
		if uninstall {
			return false
		}
		_, nftDocker := currentRulesOf(bin, dockerChain)
		return !nftDocker && strings.Contains(legacyRules, jumpLine(dockerChain, comment, target))
	}
	var done []string
	if v4 && isNft("iptables") {
		if out := legacy("iptables-legacy"); out != "" {
			if dockerOnLegacy("iptables", out, jumpComment, chainName) {
				log.Printf("[firewall] the agent's rules are also in the iptables-legacy backend, kept while Docker uses it")
			} else {
				done = append(done, removeChainsOf("iptables-legacy")...)
			}
		}
	}
	if v6 && isNft("ip6tables") {
		if out := legacy("ip6tables-legacy"); out != "" && !dockerOnLegacy("ip6tables", out, ports6Comment, portsChainName) {
			done = append(done, removePorts6Of("ip6tables-legacy")...)
		}
	}
	if len(done) > 0 {
		log.Printf("[firewall] removed the agent's stale rules from the iptables-legacy backend (iptables is nf_tables now): %v", done)
	}
	return done
}

func tableLoaded(file, table string) bool {
	data, err := os.ReadFile(file)
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(l) == table {
			return true
		}
	}
	return false
}
