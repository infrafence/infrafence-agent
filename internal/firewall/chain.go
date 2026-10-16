package firewall

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
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
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

var runStdin = func(stdin, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
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
func (s *fwState) ensureSets() (repaired []string) {
	existing := map[string]bool{}
	if out, err := run("ipset", "list", "-n"); err == nil {
		for _, n := range strings.Fields(out) {
			existing[n] = true
		}
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
	}
	allow := s.allowEntries()
	if len(allow) > 0 {
		if err := replaceNetSet(allowSetName, allow); err != nil {
			log.Printf("[firewall] allow set: %v", err)
		} else if !existing[allowSetName] {
			repaired = append(repaired, "set:"+allowSetName)
		}
	}
	if s.threat != nil && !existing[threatSetName] {
		if err := replaceNetSet(threatSetName, s.threat); err == nil {
			repaired = append(repaired, "set:"+threatSetName)
		}
	}
	for set, cidrs := range s.geo {
		if !existing[set] {
			if err := replaceNetSet(set, cidrs); err == nil {
				repaired = append(repaired, "set:"+set)
			}
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
	jump := jumpLine(chain, comment, target)
	ours, firstAccept := -1, -1
	for i, l := range lines {
		if l == jump && ours < 0 {
			ours = i
		}
		if firstAccept < 0 && mayAccept(l) {
			firstAccept = i
		}
	}
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

	ipset := HasIpset()
	if ipset {
		res.Repairs = append(res.Repairs, fw.ensureSets()...)
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
	fw.initialized = true
	return res, peErr
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
	var done []string
	for _, c := range []struct{ chain, comment, target string }{
		{"INPUT", jumpComment, chainName},
		{"INPUT", rulesComment, rulesChainName},
		{dockerChain, jumpComment, chainName},
		{"OUTPUT", egressComment, egressChainName},
	} {
		for {
			if _, err := run("iptables", append([]string{"-D", c.chain}, jumpArgs(c.comment, c.target)...)...); err != nil {
				break
			}
			done = append(done, "jump:"+c.chain+"->"+c.target)
		}
	}
	migrateLegacy()
	done = append(done, removePorts6()...)
	// Flush all first: INFRAFENCE jumps to the ports and egress chains.
	var flushed []string
	for _, ch := range ourChains {
		if _, err := run("iptables", "-F", ch); err == nil {
			flushed = append(flushed, ch)
		}
	}
	for _, ch := range flushed {
		_, _ = run("iptables", "-X", ch)
		done = append(done, "chain:"+ch)
	}
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
