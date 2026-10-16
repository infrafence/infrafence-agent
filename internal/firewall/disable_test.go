package firewall

import (
	"errors"
	"strings"
	"sync"
	"testing"
)

// fakeHost records every command and answers like a host with InfraFence's
// chains and sets next to another tool's (a "f2b-sshd" chain, a "blocklist"
// set).
type fakeHost struct {
	mu      sync.Mutex
	cmds    []string
	deleted map[string]bool
}

func (f *fakeHost) log(c string) {
	f.mu.Lock()
	f.cmds = append(f.cmds, c)
	f.mu.Unlock()
}

func (f *fakeHost) take() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.cmds
	f.cmds = nil
	return out
}

func withFakeHost(t *testing.T) *fakeHost {
	t.Helper()
	f := &fakeHost{deleted: map[string]bool{}}
	resetBans(t)
	checkIpset()
	oldRun, oldStdin, oldIpset, oldHas6 := run, runStdin, ipsetAvailable, hasIp6tables
	run = func(name string, args ...string) (string, error) {
		c := name + " " + strings.Join(args, " ")
		f.log(c)
		if c == "ipset list -n" {
			return "infrafence-bans\ninfrafence-geo-cn\nblocklist\ninfrafence-allow", nil
		}
		// Each jump exists once: deleting it again fails, as iptables does.
		if len(args) > 0 && args[0] == "-D" {
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.deleted[c] {
				return "", errNoRule
			}
			f.deleted[c] = true
		}
		return "", nil
	}
	runStdin = func(stdin, name string, args ...string) (string, error) {
		f.log(name + " " + strings.Join(args, " ") + " <<" + stdin)
		return "", nil
	}
	ipsetAvailable = true
	hasIp6tables = func() bool { return false }
	t.Cleanup(func() {
		run, runStdin, ipsetAvailable, hasIp6tables = oldRun, oldStdin, oldIpset, oldHas6
		SetDisabled(false)
		fw.Lock()
		fw.resetSnapshotsLocked()
		fw.Unlock()
	})
	return f
}

// Disable removes only InfraFence's chains, jumps and sets: never another
// tool's chain or set, never a whole table, never a policy.
func TestDisableRemovesOnlyOurs(t *testing.T) {
	f := withFakeHost(t)
	Disable()
	cmds := f.take()
	if len(cmds) == 0 {
		t.Fatal("nothing removed")
	}
	for _, c := range cmds {
		fields := strings.Fields(c)
		switch {
		case strings.Contains(c, "f2b") || strings.Contains(c, "destroy blocklist") || strings.Contains(c, "flush blocklist"):
			t.Errorf("touched another tool: %q", c)
		case strings.Contains(c, " -t ") || strings.Contains(c, " -P "):
			t.Errorf("table or policy changed: %q", c)
		case len(fields) == 2 && (fields[1] == "-F" || fields[1] == "-X"):
			t.Errorf("whole table flushed: %q", c)
		case (fields[0] == "iptables" || fields[0] == "ip6tables") && (fields[1] == "-F" || fields[1] == "-X") && !strings.HasPrefix(fields[2], "INFRAFENCE"):
			t.Errorf("flushed a chain that is not ours: %q", c)
		case fields[0] == "ipset" && fields[1] == "destroy" && !strings.HasPrefix(fields[2], "infrafence-"):
			t.Errorf("destroyed a set that is not ours: %q", c)
		case (fields[0] == "iptables") && fields[1] == "-D" && !strings.Contains(c, "INFRAFENCE"):
			t.Errorf("deleted a rule that is not a jump to ours: %q", c)
		}
	}
	joined := strings.Join(cmds, "\n")
	for _, want := range []string{"ipset destroy infrafence-bans", "ipset destroy infrafence-geo-cn", "iptables -X INFRAFENCE"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in\n%s", want, joined)
		}
	}
}

// While switched off nothing reaches the kernel (guard, bans, allow list,
// threat feed, country blocks); Enable rebuilds from the kept state.
func TestDisabledChangesNothingAndEnableRestores(t *testing.T) {
	f := withFakeHost(t)
	Disable()
	f.take()
	if _, err := Ensure(); err != nil {
		t.Fatal(err)
	}
	BanIPOnce("203.0.113.5")
	ApplyBans([]Ban{{IP: "203.0.113.6"}})
	SetAllowList([]string{"198.51.100.0/24"})
	if _, _, err := ApplyThreatSet([]string{"192.0.2.0/24"}, nil); err != ErrDisabled {
		t.Errorf("threat set while disabled: %v", err)
	}
	NewGeoBlocker(func(string) ([]string, error) { return []string{"192.0.2.0/24"}, nil }, "").ApplyCountryBlocks([]string{"CN"})
	if cmds := f.take(); len(cmds) != 0 {
		t.Fatalf("commands while switched off:\n%s", strings.Join(cmds, "\n"))
	}
	if !IsBanned("203.0.113.5") || !IsBanned("203.0.113.6") {
		t.Fatal("bans made meanwhile not kept for later")
	}

	if _, err := Enable(); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(f.take(), "\n")
	// The set contents go through ipset itself (not faked here); the chain
	// is rebuilt referencing them, from the kept bans and allow list.
	for _, want := range []string{"iptables-restore", "--match-set infrafence-bans src -j DROP", "--match-set infrafence-allow src -j RETURN", "-I INPUT 1 -m comment --comment infrafence -j INFRAFENCE"} {
		if !strings.Contains(joined, want) {
			t.Errorf("Enable did not restore %q:\n%s", want, joined)
		}
	}
	if Disabled() {
		t.Fatal("still disabled")
	}
}

var errNoRule = errors.New("iptables: Bad rule (does a matching rule exist in that chain?)")
