package firewall

import (
	"fmt"
	"log"
)

// Dashboard rules by ID. A rule deleted from the dashboard comes as its ID
// alone (rule.removed), and every sync lists the rules in force: the agent
// keeps which iptables args each ID stands for, removes a deleted rule from
// INFRAFENCE-RULES at once, and at every sync drops whatever the dashboard
// no longer lists, so the chain cannot drift from it until a restart.
//
// Guarded by fw's lock.
var (
	ruleArgs = map[int64][]string{} // rule ID → iptables args
	// ruleGen counts the changes by ID; ruleTouched holds, for each ID
	// applied or removed by ID, the count at that change, so that a sync
	// fetched before it does not undo it.
	ruleGen     uint64
	ruleTouched = map[int64]uint64{}
	ruleRemoved = map[int64]bool{}
)

// RulesGeneration returns the current count of rule changes. A sync takes it
// before it asks the dashboard for the rules, and gives it back to
// ReconcileRules and RuleRemovedSince.
func RulesGeneration() uint64 {
	fw.Lock()
	defer fw.Unlock()
	return ruleGen
}

// ApplyRuleID applies the dashboard rule id (see ApplyRule) and records it,
// under one lock: a RemoveRuleID in between cannot leave it applied.
func ApplyRuleID(id int64, spec RuleSpec) error {
	args := buildRuleArgs(spec)
	fw.Lock()
	ruleGen++
	ruleArgs[id] = args
	ruleTouched[id] = ruleGen
	delete(ruleRemoved, id)
	present := false
	for _, r := range fw.userRules {
		if equal(r, args) {
			present = true
			break
		}
	}
	if !present {
		fw.userRules = append(fw.userRules, args)
	}
	fw.Unlock()
	if present {
		return nil
	}
	if _, err := Ensure(); err != nil {
		return fmt.Errorf("apply rule: %w", err)
	}
	log.Printf("[firewall] applied rule %d: %v", id, args)
	return nil
}

// RemoveRuleID removes the dashboard rule id from INFRAFENCE-RULES at once
// (unless another rule in force has the same args). It reports whether the
// agent had it.
func RemoveRuleID(id int64) (bool, error) {
	fw.Lock()
	ruleGen++
	ruleTouched[id] = ruleGen
	ruleRemoved[id] = true
	args, ok := ruleArgs[id]
	delete(ruleArgs, id)
	changed := ok && fw.dropUnusedRuleArgsLocked()
	fw.Unlock()
	if !changed {
		return ok, nil
	}
	if _, err := Ensure(); err != nil {
		return true, fmt.Errorf("remove rule %d: %w", id, err)
	}
	log.Printf("[firewall] removed rule %d: %v", id, args)
	return true, nil
}

// RuleRemovedSince reports whether the rule id was removed by ID after gen
// (from RulesGeneration): a sync fetched before must not apply it again.
func RuleRemovedSince(id int64, gen uint64) bool {
	fw.Lock()
	defer fw.Unlock()
	return ruleRemoved[id] && ruleTouched[id] > gen
}

// ReconcileRules makes INFRAFENCE-RULES hold the rules a sync listed as in
// force (keep, already applied with ApplyRuleID) and nothing else, except
// rules applied by ID since gen (from RulesGeneration, taken before the
// sync's request), which that sync could not list yet.
func ReconcileRules(gen uint64, keep []int64) error {
	keepSet := map[int64]bool{}
	for _, id := range keep {
		keepSet[id] = true
	}
	fw.Lock()
	var dropped []int64
	for id := range ruleArgs {
		if !keepSet[id] && ruleTouched[id] <= gen {
			delete(ruleArgs, id)
			dropped = append(dropped, id)
		}
	}
	for id, g := range ruleTouched {
		if g <= gen && ruleArgs[id] == nil {
			delete(ruleTouched, id)
			delete(ruleRemoved, id)
		}
	}
	changed := fw.dropUnusedRuleArgsLocked()
	fw.Unlock()
	if !changed {
		return nil
	}
	if len(dropped) > 0 {
		log.Printf("[firewall] rules no longer on the dashboard removed: %v", dropped)
	}
	_, err := Ensure()
	return err
}

// dropUnusedRuleArgsLocked removes from the chain's rules those no ID in
// force stands for, keeping the order of the others. It reports whether any
// went.
func (s *fwState) dropUnusedRuleArgsLocked() bool {
	kept := s.userRules[:0:0]
	for _, r := range s.userRules {
		for _, args := range ruleArgs {
			if equal(r, args) {
				kept = append(kept, r)
				break
			}
		}
	}
	if len(kept) == len(s.userRules) {
		return false
	}
	s.userRules = kept
	return true
}
