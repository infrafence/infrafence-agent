package firewall

import (
	"strings"
	"testing"
)

// withBanSet fakes a host whose ban set exists and holds entries entries,
// and records every "ipset restore".
func withBanSet(t *testing.T, entries string) *[]string {
	t.Helper()
	resetBans(t)
	var restores []string
	oldRun, oldStdin := run, runStdin
	run = func(name string, args ...string) (string, error) {
		switch name + " " + strings.Join(args, " ") {
		case "ipset list -n":
			return banSetName, nil
		case "ipset list -t":
			return "Name: chain_DENY\nType: hash:net\nNumber of entries: 5\n\nName: " + banSetName + "\nType: hash:ip\nReferences: 2\nNumber of entries: " + entries, nil
		}
		return "", nil
	}
	runStdin = func(stdin, name string, args ...string) (string, error) {
		if name == "ipset" && len(args) == 1 && args[0] == "restore" {
			restores = append(restores, stdin)
		}
		return "", nil
	}
	t.Cleanup(func() { run, runStdin = oldRun, oldStdin })
	fw.Lock()
	fw.bans["198.18.0.2"] = banEntry{}
	fw.bans["203.0.113.9"] = banEntry{}
	fw.bans["2001:db8::1"] = banEntry{} // not in the inet set
	fw.Unlock()
	return &restores
}

func ensureSetsNow() []string {
	fw.Lock()
	defer fw.Unlock()
	return fw.ensureSets()
}

func hasRepair(rs []string, want string) bool {
	for _, r := range rs {
		if r == want {
			return true
		}
	}
	return false
}

// "csf -r" with LF_IPSET=1 flushes every set and then destroys it; a set a
// rule still references survives, empty. The bans go back in.
func TestEnsureSetsRefillsEmptiedBanSet(t *testing.T) {
	restores := withBanSet(t, "0")
	rs := ensureSetsNow()
	if !hasRepair(rs, "set-contents:"+banSetName) {
		t.Errorf("repairs = %v, want set-contents:%s", rs, banSetName)
	}
	var refill string
	for _, r := range *restores {
		if strings.Contains(r, "add "+banSetName+" ") {
			refill = r
		}
	}
	for _, ip := range []string{"198.18.0.2", "203.0.113.9"} {
		if !strings.Contains(refill, "add "+banSetName+" "+ip+" -exist\n") {
			t.Errorf("%s not added back: %q", ip, refill)
		}
	}
	if strings.Contains(refill, "2001:db8::1") {
		t.Errorf("IPv6 ban put in the inet set: %q", refill)
	}
}

// A ban recorded a moment ago may not be in the set yet (the ipset add
// follows): it is added, but that is no repair to report.
func TestEnsureSetsFreshBanIsNoRepair(t *testing.T) {
	restores := withBanSet(t, "1")
	fw.Lock()
	fw.bans["203.0.113.9"] = banEntry{added: banNow()}
	fw.Unlock()
	rs := ensureSetsNow()
	if hasRepair(rs, "set-contents:"+banSetName) {
		t.Errorf("a fresh ban reported as a repair: %v", rs)
	}
	added := false
	for _, r := range *restores {
		added = added || strings.Contains(r, "add "+banSetName+" 203.0.113.9 -exist")
	}
	if !added {
		t.Error("fresh ban not added")
	}
}

// A set with all its bans is left alone, and nothing is reported.
func TestEnsureSetsKeepsFullBanSet(t *testing.T) {
	restores := withBanSet(t, "2")
	rs := ensureSetsNow()
	if hasRepair(rs, "set-contents:"+banSetName) {
		t.Errorf("full set reported as repaired: %v", rs)
	}
	for _, r := range *restores {
		if strings.Contains(r, "add "+banSetName+" ") {
			t.Errorf("full set refilled: %q", r)
		}
	}
}

func TestSetEntries(t *testing.T) {
	oldRun := run
	t.Cleanup(func() { run = oldRun })
	run = func(string, ...string) (string, error) {
		return "Name: chain_DENY\nType: hash:net\nRevision: 7\nHeader: family inet hashsize 1024 maxelem 65536\nSize in memory: 456\nReferences: 1\nNumber of entries: 17\n" +
			"Name: infrafence-bans\nType: hash:ip\nNumber of entries: 0\n" +
			"Name: broken\nType: hash:ip\nNumber of entries: x\n" +
			"Name: nocount\nType: hash:ip\n", nil
	}
	got := setEntries()
	want := map[string]int{"chain_DENY": 17, "infrafence-bans": 0}
	if len(got) != len(want) {
		t.Errorf("setEntries = %v, want %v", got, want)
	}
	for k, v := range want {
		if n, ok := got[k]; !ok || n != v {
			t.Errorf("%s: %d, %v; want %d", k, n, ok, v)
		}
	}
	run = func(string, ...string) (string, error) { return "", errNoRule }
	if got := setEntries(); len(got) != 0 {
		t.Errorf("on error: %v", got)
	}
}
