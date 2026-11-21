package firewall

import (
	"fmt"
	"log"
	"strings"
	"time"
)

// Early drop in the raw table. INFRAFENCE drops banned addresses in filter
// INPUT, ahead of the first rule that can ACCEPT, but another tool can put
// its own chain first for the seconds until the guard moves the jump back:
// Imunify360 recreates its rules every minute with INPUT_imunify360 first,
// and that chain ACCEPTs graylisted and captcha traffic on its webshield
// ports (52223-52232, where its nat PREROUTING sends it). INFRAFENCE-RAW,
// jumped to from raw PREROUTING, drops the same bans before conntrack, NAT
// and every filter chain, so a ban holds whatever the order in INPUT:
//
//	-A INFRAFENCE-RAW -i lo -j RETURN
//	-A INFRAFENCE-RAW -m set --match-set infrafence-allow src -j RETURN
//	-A INFRAFENCE-RAW -m set --match-set infrafence-bans src -j DROP
//
// Never more than INFRAFENCE drops: the same allow set (protected
// addresses, the server's own public ones, the dashboard whitelist) returns
// first, as it does there, and the ban set never holds a reserved, local or
// protected address (isSafeIP). Nothing is accepted here (an ACCEPT in raw
// would only end the raw table, not skip filter). Threat feeds and country
// blocks stay in filter only.
//
// raw PREROUTING also sees forwarded traffic: Docker's published ports
// (already covered through DOCKER-USER) and anything else the host routes
// (VMs, LXC bridges). A banned source reaches none of them, which is what a
// ban means. Traffic the host sends itself never passes PREROUTING.
//
// Only with ipset (without it bans are rules in INFRAFENCE and are not
// copied here), only while early drop is on (SetEarlyDrop: protection
// active, not monitor mode or suspended) and never while switched off.
// IPv4 only: there is no IPv6 ban set. Where the raw table or the set match
// is missing (old kernels, some containers, OpenVZ), iptables-restore
// refuses the chain: logged once, and the bans stay in filter as before.
const (
	rawChainName = "INFRAFENCE-RAW"
	rawComment   = "infrafence-raw"
	rawTable     = "raw"
	rawHook      = "PREROUTING"
)

// rawRetry: a chain iptables refused is tried again after this long, or as
// soon as what it should contain changes.
const rawRetry = time.Hour

// Replaced in tests.
var rawNow = time.Now

// rawRules returns the contents of INFRAFENCE-RAW, nil when there should
// be none.
func (s *fwState) rawRules(ipset bool) []string {
	if !ipset || !s.earlyDrop {
		return nil
	}
	rules := []string{fmt.Sprintf("-A %s -i lo -j RETURN", rawChainName)}
	if len(s.allowEntries()) > 0 {
		rules = append(rules, fmt.Sprintf("-A %s -m set --match-set %s src -j RETURN", rawChainName, allowSetName))
	}
	return append(rules, fmt.Sprintf("-A %s -m set --match-set %s src -j DROP", rawChainName, banSetName))
}

// ensureRaw keeps INFRAFENCE-RAW and its jump in place, or removes them
// when early drop is off. Called by Ensure after ensureSets (the chain
// matches the sets). Failures are logged once and leave rawInForce false.
// Until SetEarlyDrop is first called (the monitor mode is not known yet,
// at startup) nothing is created or removed: a chain the previous run left
// keeps working through the restart.
func (s *fwState) ensureRaw(ipset bool) (repaired []string) {
	if !s.earlyDropSet {
		return nil
	}
	want := s.rawRules(ipset)
	if want == nil {
		// Removed when something of ours may be there: in force, created
		// but its jump refused, refused later, or left by an earlier run
		// (looked for once). Checked afterwards, retried if still there.
		if s.rawInForce || s.rawDesired != "" || !s.rawChecked {
			s.rawChecked = true
			if done := removeRawOf("iptables"); len(done) > 0 {
				log.Printf("[firewall] early drop off: removed %v", done)
			}
			s.rawInForce, s.rawApplied = false, nil
			if _, still := currentRulesIn("iptables", rawTable, rawChainName); still && rawTablePresent("iptables") {
				s.rawDesired = "(remove)"
				log.Printf("[firewall] early drop off: %s still in the raw table, retried at the next check", rawChainName)
			} else {
				s.rawDesired = ""
			}
		}
		return nil
	}
	s.rawChecked = true
	key := strings.Join(want, "\n")
	if key == s.rawFailedKey && rawNow().Sub(s.rawFailedAt) < rawRetry {
		return nil
	}
	failed := func(err error) {
		s.rawFailedKey, s.rawFailedAt, s.rawInForce = key, rawNow(), false
		if !s.rawLogged {
			s.rawLogged = true
			log.Printf("[firewall] early drop in the raw table not available, bans stay in the filter table only: %v", err)
		}
	}
	had := s.rawInForce
	have, ok := currentRulesIn("iptables", rawTable, rawChainName)
	if !ok || key != s.rawDesired || !equal(have, s.rawApplied) {
		if err := restoreRaw(want); err != nil {
			failed(err)
			return nil
		}
		if had && key == s.rawDesired {
			if !ok {
				repaired = append(repaired, "chain:raw")
			} else {
				repaired = append(repaired, "chain-contents:raw")
			}
		}
		s.rawDesired, s.rawFailedKey = key, ""
		s.rawApplied, _ = currentRulesIn("iptables", rawTable, rawChainName)
	}
	r, err := ensureJumpAheadIn("iptables", rawTable, rawHook, rawComment, rawChainName)
	if err != nil {
		failed(err)
		return repaired
	}
	if had {
		repaired = append(repaired, r...)
	} else {
		log.Printf("[firewall] early drop on: bans are also dropped in the raw table, before NAT and any filter chain")
	}
	s.rawInForce = true
	return repaired
}

// restoreRaw replaces the contents of INFRAFENCE-RAW in one iptables-restore.
func restoreRaw(want []string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "*%s\n:%s - [0:0]\n", rawTable, rawChainName)
	for _, l := range want {
		b.WriteString(l + "\n")
	}
	b.WriteString("COMMIT\n")
	if out, err := runStdin(b.String(), "iptables-restore", "--noflush"); err != nil {
		return fmt.Errorf("iptables-restore -t raw: %s (%w)", out, err)
	}
	return nil
}

// removeRawOf removes the raw jump and chain with bin (iptables, or
// iptables-legacy for a backend the host left). The legacy raw table is
// not listed when it is not loaded: that would load it.
func removeRawOf(bin string) (done []string) {
	if !rawTablePresent(bin) {
		return nil
	}
	prefix := rawTable + ":"
	if bin != "iptables" {
		prefix = bin + ":" + prefix
	}
	for {
		if _, err := run(bin, append([]string{"-t", rawTable, "-D", rawHook}, jumpArgs(rawComment, rawChainName)...)...); err != nil {
			break
		}
		done = append(done, "jump:"+prefix+rawHook+"->"+rawChainName)
	}
	if _, err := run(bin, "-t", rawTable, "-F", rawChainName); err == nil {
		_, _ = run(bin, "-t", rawTable, "-X", rawChainName)
		done = append(done, "chain:"+prefix+rawChainName)
	}
	return done
}

// rawTablePresent: with nf_tables, iptables lists a table without creating
// it; with the legacy backend only a loaded table is looked at.
func rawTablePresent(bin string) bool {
	if strings.HasSuffix(bin, "-legacy") {
		return tableLoaded(legacyTables4, rawTable)
	}
	if out, err := run(bin, "-V"); err == nil && !strings.Contains(out, "nf_tables") {
		return tableLoaded(legacyTables4, rawTable)
	}
	return true
}

// SetEarlyDrop switches the raw-table early drop on or off: on while
// protection is active, off in monitor mode and while the agent is
// suspended (nothing new is dropped there). Until first set, nothing is
// added or removed (ensureRaw).
func SetEarlyDrop(on bool) {
	fw.Lock()
	changed := fw.earlyDrop != on || !fw.earlyDropSet
	fw.earlyDrop, fw.earlyDropSet = on, true
	apply := changed && fw.initialized && !fw.disabled
	fw.Unlock()
	if apply {
		if _, err := Ensure(); err != nil {
			log.Printf("[firewall] early drop: %v", err)
		}
	}
}

// EarlyDropInForce reports whether bans are also dropped in the raw table.
func EarlyDropInForce() bool {
	fw.Lock()
	defer fw.Unlock()
	return fw.rawInForce
}
