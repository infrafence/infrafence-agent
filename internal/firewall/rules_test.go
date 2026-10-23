package firewall

import (
	"fmt"
	"strings"
	"testing"
)

// withRules starts from no dashboard rules, on a fake host.
func withRules(t *testing.T) *fakeHost {
	t.Helper()
	f := withFakeHost(t)
	reset := func() {
		fw.Lock()
		fw.userRules = nil
		ruleArgs, ruleTouched, ruleRemoved = map[int64][]string{}, map[int64]uint64{}, map[int64]bool{}
		fw.Unlock()
	}
	reset()
	t.Cleanup(reset)
	return f
}

// lastRulesChain returns the INFRAFENCE-RULES lines of the last
// iptables-restore.
func lastRulesChain(t *testing.T, f *fakeHost) []string {
	t.Helper()
	var last string
	for _, c := range f.take() {
		if strings.HasPrefix(c, "iptables-restore") {
			last = c
		}
	}
	if last == "" {
		t.Fatal("chains not rebuilt")
	}
	var out []string
	for _, l := range strings.Split(last, "\n") {
		if strings.HasPrefix(l, "-A "+rulesChainName+" ") {
			out = append(out, l)
		}
	}
	return out
}

func ruleSpec(ip, typ string) RuleSpec {
	return RuleSpec{Type: typ, Protocol: "all", IPAddress: &ip}
}

// After a rule.removed message the rule is gone from INFRAFENCE-RULES at
// once, without a restart.
func TestRemoveRuleIDTakesEffectAtOnce(t *testing.T) {
	f := withRules(t)
	if err := ApplyRuleID(7, ruleSpec("203.0.113.7", "block")); err != nil {
		t.Fatal(err)
	}
	if err := ApplyRuleID(8, ruleSpec("203.0.113.8", "allow")); err != nil {
		t.Fatal(err)
	}
	if got := lastRulesChain(t, f); len(got) != 2 {
		t.Fatalf("rules chain: %q", got)
	}

	had, err := RemoveRuleID(7)
	if err != nil || !had {
		t.Fatalf("RemoveRuleID: had=%v err=%v", had, err)
	}
	got := lastRulesChain(t, f)
	if len(got) != 1 || !strings.Contains(got[0], "203.0.113.8") {
		t.Errorf("after removal: %q", got)
	}

	// Unknown ID: nothing to do, nothing rebuilt.
	if had, err := RemoveRuleID(99); had || err != nil {
		t.Errorf("unknown rule: had=%v err=%v", had, err)
	}
	for _, c := range f.take() {
		if strings.HasPrefix(c, "iptables-restore") {
			t.Errorf("rebuilt for an unknown rule: %q", c)
		}
	}
}

// Two dashboard rules with the same args: removing one keeps the other.
func TestRemoveRuleIDKeepsSameArgsOfAnother(t *testing.T) {
	f := withRules(t)
	ApplyRuleID(1, ruleSpec("203.0.113.1", "block"))
	ApplyRuleID(2, ruleSpec("203.0.113.1", "block"))
	f.take()
	if _, err := RemoveRuleID(1); err != nil {
		t.Fatal(err)
	}
	fw.Lock()
	n := len(fw.userRules)
	fw.Unlock()
	if n != 1 {
		t.Errorf("%d rules in force, want 1", n)
	}
}

// Every sync drops the rules the dashboard no longer lists (a missed
// rule.removed message), but not those applied since its request, and a
// rule removed since is not applied again.
func TestReconcileRules(t *testing.T) {
	f := withRules(t)
	ApplyRuleID(1, ruleSpec("203.0.113.1", "block"))
	ApplyRuleID(2, ruleSpec("203.0.113.2", "block"))
	ApplyRuleID(3, ruleSpec("203.0.113.3", "block"))

	gen := RulesGeneration()                         // the sync's request
	ApplyRuleID(4, ruleSpec("203.0.113.4", "block")) // rule.created meanwhile
	RemoveRuleID(3)                                  // rule.removed meanwhile
	f.take()

	// The sync lists 1 and 3 (fetched before 3 was removed), not 2.
	var keep []int64
	for _, id := range []int64{1, 3} {
		if RuleRemovedSince(id, gen) {
			continue
		}
		ApplyRuleID(id, ruleSpec(fmt.Sprint("203.0.113.", id), "block"))
		keep = append(keep, id)
	}
	if err := ReconcileRules(gen, keep); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(lastRulesChain(t, f), "\n")
	for ip, want := range map[string]bool{"203.0.113.1": true, "203.0.113.2": false, "203.0.113.3": false, "203.0.113.4": true} {
		if strings.Contains(got, ip) != want {
			t.Errorf("%s in force = %v, want %v:\n%s", ip, !want, want, got)
		}
	}

	// The next sync lists only 1: 4 goes too, as it is no longer newer.
	gen = RulesGeneration()
	ApplyRuleID(1, ruleSpec("203.0.113.1", "block"))
	ReconcileRules(gen, []int64{1})
	if got := lastRulesChain(t, f); len(got) != 1 || !strings.Contains(got[0], "203.0.113.1") {
		t.Errorf("second sync: %q", got)
	}
}
