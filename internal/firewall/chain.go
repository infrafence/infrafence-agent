package firewall

import (
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
	allow       []string        // whitelist IPs/CIDRs from the dashboard
	bans        map[string]bool // every IP currently banned by the agent
	threat      []string        // threat-feed CIDRs; nil when not blocking
	geo         map[string][]string
	userRules   [][]string // iptables args of dashboard rules, in order
	legacyDone  bool

	// What the chains looked like right after our last rebuild, as iptables
	// prints them (it normalizes, e.g. adds /32 and -m tcp), and the desired
	// state that produced it. Drift = chains differ from that snapshot.
	lastDesired string
	appliedMain []string
	appliedUser []string
}

var fw = &fwState{bans: map[string]bool{}, geo: map[string][]string{}}

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
	out, err := run("iptables", "-S", chain)
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

// syncChains makes both chains contain exactly the desired rules, atomically.
func (s *fwState) syncChains(ipset bool) (repaired []string, err error) {
	want, wantUser := s.desiredRules(ipset)
	key := strings.Join(want, "\n") + "\n--\n" + strings.Join(wantUser, "\n")
	have, okMain := currentRules(chainName)
	haveUser, okUser := currentRules(rulesChainName)
	if okMain && okUser && key == s.lastDesired && equal(have, s.appliedMain) && equal(haveUser, s.appliedUser) {
		return nil, nil
	}
	drift := s.lastDesired != "" && key == s.lastDesired
	var b strings.Builder
	b.WriteString("*filter\n")
	fmt.Fprintf(&b, ":%s - [0:0]\n:%s - [0:0]\n", chainName, rulesChainName)
	for _, l := range append(want, wantUser...) {
		b.WriteString(l + "\n")
	}
	b.WriteString("COMMIT\n")
	if out, err := runStdin(b.String(), "iptables-restore", "--noflush"); err != nil {
		return nil, fmt.Errorf("iptables-restore: %s (%w)", out, err)
	}
	s.lastDesired = key
	s.appliedMain, _ = currentRules(chainName)
	s.appliedUser, _ = currentRules(rulesChainName)
	// Only report a repair when something outside the agent changed the
	// chains; rebuilding because the agent's own state changed is normal.
	if !okMain || !okUser {
		repaired = append(repaired, "chain")
	} else if drift {
		repaired = append(repaired, "chain-contents")
	}
	return repaired, nil
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
		case t == chainName || t == rulesChainName:
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
	lines, ok := currentRules("INPUT")
	if !ok {
		return nil, fmt.Errorf("cannot list INPUT")
	}
	main := jumpLine("INPUT", jumpComment, chainName)
	ours, firstAccept := -1, -1
	for i, l := range lines {
		if l == main && ours < 0 {
			ours = i
		}
		if firstAccept < 0 && mayAccept(l) {
			firstAccept = i
		}
	}
	switch {
	case ours < 0:
		if out, err := run("iptables", append([]string{"-I", "INPUT", "1"}, jumpArgs(jumpComment, chainName)...)...); err != nil {
			return nil, fmt.Errorf("insert INPUT jump: %s (%w)", out, err)
		}
		repaired = append(repaired, "jump:INPUT")
	case firstAccept >= 0 && ours > firstAccept:
		// Insert the new jump first, then delete the old one by number, so
		// there is never a moment without it.
		if out, err := run("iptables", append([]string{"-I", "INPUT", "1"}, jumpArgs(jumpComment, chainName)...)...); err != nil {
			return nil, fmt.Errorf("move INPUT jump: %s (%w)", out, err)
		}
		if out, err := run("iptables", "-D", "INPUT", strconv.Itoa(ours+2)); err != nil {
			return nil, fmt.Errorf("remove old INPUT jump: %s (%w)", out, err)
		}
		repaired = append(repaired, "jump-order:INPUT")
	}

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

// ensureDockerJump protects containers with published ports: that traffic
// is forwarded, so it goes through DOCKER-USER, never INPUT.
func ensureDockerJump() (repaired []string) {
	lines, ok := currentRules(dockerChain)
	if !ok {
		return nil // no Docker (yet)
	}
	if len(lines) > 0 && lines[0] == jumpLine(dockerChain, jumpComment, chainName) {
		return nil
	}
	// Present but not first: remove it before re-inserting at the top.
	for i := len(lines) - 1; i >= 0; i-- {
		if lines[i] == jumpLine(dockerChain, jumpComment, chainName) {
			_, _ = run("iptables", "-D", dockerChain, strconv.Itoa(i+1))
		}
	}
	if out, err := run("iptables", append([]string{"-I", dockerChain, "1"}, jumpArgs(jumpComment, chainName)...)...); err != nil {
		log.Printf("[firewall] insert %s jump: %s (%v)", dockerChain, out, err)
		return nil
	}
	return []string{"jump:" + dockerChain}
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
	if err != nil {
		return res, err
	}
	res.Repairs = append(res.Repairs, r...)
	if !fw.legacyDone {
		migrateLegacy()
		fw.legacyDone = true
	}
	r, err = ensureInputJumps()
	res.Repairs = append(res.Repairs, r...)
	if err != nil {
		return res, err
	}
	res.Repairs = append(res.Repairs, ensureDockerJump()...)
	fw.initialized = true
	return res, nil
}

// SetAllowList sets the dashboard whitelist (IPs or CIDRs). InfraFence never
// blocks them; it does not open anything in the host firewall for them.
func SetAllowList(entries []string) {
	fw.Lock()
	changed := !equal(fw.allow, entries)
	fw.allow = append([]string{}, entries...)
	fw.Unlock()
	if changed {
		if _, err := Ensure(); err != nil {
			log.Printf("[firewall] apply allow list: %v", err)
		}
	}
}

// RemoveAll removes every chain, jump and set InfraFence created. Used by
// "infrafence-agent uninstall --clean".
func RemoveAll() []string {
	var done []string
	for _, c := range []struct{ chain, comment, target string }{
		{"INPUT", jumpComment, chainName},
		{"INPUT", rulesComment, rulesChainName},
		{dockerChain, jumpComment, chainName},
	} {
		for {
			if _, err := run("iptables", append([]string{"-D", c.chain}, jumpArgs(c.comment, c.target)...)...); err != nil {
				break
			}
			done = append(done, "jump:"+c.chain+"->"+c.target)
		}
	}
	migrateLegacy()
	for _, ch := range []string{chainName, rulesChainName} {
		if _, err := run("iptables", "-F", ch); err == nil {
			_, _ = run("iptables", "-X", ch)
			done = append(done, "chain:"+ch)
		}
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
