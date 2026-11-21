package firewall

import (
	"bytes"
	"errors"
	"log"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// rawHost fakes iptables' raw table: INFRAFENCE-RAW (nil: missing) and
// PREROUTING, as "iptables -t raw -S" prints them, and records every
// command and restore.
type rawHost struct {
	chain      []string
	prerouting []string
	failLoad   bool // iptables-restore refuses the raw table
	failJump   bool // inserting the PREROUTING jump fails
	cmds       []string
	restores   []string
}

func fakeRaw(t *testing.T, h *rawHost) {
	t.Helper()
	oldRun, oldStdin, oldNow := run, runStdin, rawNow
	run = func(name string, args ...string) (string, error) {
		c := name + " " + strings.Join(args, " ")
		h.cmds = append(h.cmds, c)
		jump := strings.Join(jumpArgs(rawComment, rawChainName), " ")
		switch {
		case c == "iptables -V":
			return nftV, nil
		case c == "iptables -t raw -S "+rawChainName:
			if h.chain == nil {
				return "iptables: No chain/target/match by that name.", errors.New("exit status 1")
			}
			return strings.Join(append([]string{"-N " + rawChainName}, h.chain...), "\n"), nil
		case c == "iptables -t raw -S PREROUTING":
			return strings.Join(append([]string{"-P PREROUTING ACCEPT"}, h.prerouting...), "\n"), nil
		case c == "iptables -t raw -I PREROUTING 1 "+jump && h.failJump:
			return "iptables: Resource temporarily unavailable.", errors.New("exit status 4")
		case c == "iptables -t raw -I PREROUTING 1 "+jump:
			h.prerouting = append([]string{"-A PREROUTING " + jump}, h.prerouting...)
			return "", nil
		case c == "iptables -t raw -D PREROUTING "+jump:
			for i, l := range h.prerouting {
				if l == "-A PREROUTING "+jump {
					h.prerouting = append(h.prerouting[:i:i], h.prerouting[i+1:]...)
					return "", nil
				}
			}
			return "", errors.New("exit status 1")
		case strings.HasPrefix(c, "iptables -t raw -D PREROUTING "):
			n, _ := strconv.Atoi(args[len(args)-1])
			h.prerouting = append(h.prerouting[:n-1:n-1], h.prerouting[n:]...)
			return "", nil
		case c == "iptables -t raw -F "+rawChainName:
			if h.chain == nil {
				return "", errors.New("exit status 1")
			}
			h.chain = []string{}
			return "", nil
		case c == "iptables -t raw -X "+rawChainName:
			h.chain = nil
			return "", nil
		}
		return "", nil
	}
	runStdin = func(stdin, name string, args ...string) (string, error) {
		h.restores = append(h.restores, stdin)
		if h.failLoad {
			return "iptables-restore: unable to initialize table 'raw'", errors.New("exit status 2")
		}
		h.chain = []string{}
		for _, l := range strings.Split(stdin, "\n") {
			if strings.HasPrefix(l, "-A ") {
				h.chain = append(h.chain, l)
			}
		}
		return "", nil
	}
	fw.Lock()
	old := struct {
		allow                   []string
		earlyDrop, earlyDropSet bool
		rawDesired              string
		rawApplied              []string
		rawFailedKey            string
		rawFailedAt             time.Time
		rawLogged, rawInForce   bool
		rawChecked              bool
		ahead                   map[string]string
	}{fw.allow, fw.earlyDrop, fw.earlyDropSet, fw.rawDesired, fw.rawApplied, fw.rawFailedKey, fw.rawFailedAt, fw.rawLogged, fw.rawInForce, fw.rawChecked, fw.ahead}
	fw.allow = []string{"198.51.100.1"}
	fw.earlyDrop, fw.earlyDropSet = true, true
	fw.rawDesired, fw.rawApplied, fw.rawFailedKey, fw.rawFailedAt = "", nil, "", time.Time{}
	fw.rawLogged, fw.rawInForce, fw.rawChecked = false, false, false
	fw.ahead = nil
	fw.Unlock()
	t.Cleanup(func() {
		run, runStdin, rawNow = oldRun, oldStdin, oldNow
		fw.Lock()
		fw.allow, fw.earlyDrop, fw.earlyDropSet = old.allow, old.earlyDrop, old.earlyDropSet
		fw.rawDesired, fw.rawApplied, fw.rawFailedKey, fw.rawFailedAt = old.rawDesired, old.rawApplied, old.rawFailedKey, old.rawFailedAt
		fw.rawLogged, fw.rawInForce, fw.rawChecked = old.rawLogged, old.rawInForce, old.rawChecked
		fw.ahead = old.ahead
		fw.Unlock()
	})
}

func ensureRawNow(ipset bool) []string {
	fw.Lock()
	defer fw.Unlock()
	return fw.ensureRaw(ipset)
}

func rawLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &buf
}

// The raw chain: loopback and the allow set return first, then the ban
// set drops. Never an ACCEPT, never more than the ban set.
func TestRawRules(t *testing.T) {
	fakeRaw(t, &rawHost{})
	fw.Lock()
	got := fw.rawRules(true)
	fw.earlyDrop = false
	off := fw.rawRules(true)
	fw.earlyDrop = true
	noIpset := fw.rawRules(false)
	fw.Unlock()
	want := []string{
		"-A INFRAFENCE-RAW -i lo -j RETURN",
		"-A INFRAFENCE-RAW -m set --match-set infrafence-allow src -j RETURN",
		"-A INFRAFENCE-RAW -m set --match-set infrafence-bans src -j DROP",
	}
	if !equal(got, want) {
		t.Errorf("rawRules =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, l := range got {
		if strings.Contains(l, "ACCEPT") {
			t.Errorf("raw rule accepts: %s", l)
		}
	}
	if off != nil || noIpset != nil {
		t.Errorf("early drop off: %v, without ipset: %v; want none", off, noIpset)
	}
}

// First Ensure: the chain and its jump are created (not a repair), then
// left alone; a flushed chain or a removed jump are repaired and reported.
func TestEnsureRawCreatesAndRepairs(t *testing.T) {
	h := &rawHost{prerouting: []string{"-A PREROUTING -p udp --dport 53 -j CT --notrack"}}
	fakeRaw(t, h)
	rawLog(t)
	if rs := ensureRawNow(true); len(rs) != 0 {
		t.Errorf("first setup reported repairs %v", rs)
	}
	if len(h.restores) != 1 || !strings.HasPrefix(h.restores[0], "*raw\n:INFRAFENCE-RAW - [0:0]\n") || !strings.HasSuffix(h.restores[0], "COMMIT\n") {
		t.Fatalf("restores = %q", h.restores)
	}
	if h.prerouting[0] != jumpLine("PREROUTING", rawComment, rawChainName) {
		t.Fatalf("jump not first in raw PREROUTING: %v", h.prerouting)
	}
	if !EarlyDropInForce() {
		t.Error("not in force")
	}
	// Unchanged: nothing rewritten.
	if rs := ensureRawNow(true); len(rs) != 0 || len(h.restores) != 1 {
		t.Errorf("clean Ensure: repairs %v, %d restores", rs, len(h.restores))
	}
	h.chain = []string{}
	if rs := ensureRawNow(true); strings.Join(rs, ",") != "chain-contents:raw" || len(h.chain) != 3 {
		t.Errorf("flushed chain: repairs %v, chain %v", rs, h.chain)
	}
	h.prerouting = h.prerouting[1:]
	if rs := ensureRawNow(true); strings.Join(rs, ",") != "jump:raw:PREROUTING" {
		t.Errorf("removed jump: repairs %v", rs)
	}
	// A tool's rule put ahead: moved back, and the chain ahead is noted.
	h.prerouting = append([]string{"-A PREROUTING -j OTHER_raw"}, h.prerouting...)
	if rs := ensureRawNow(true); strings.Join(rs, ",") != "jump-order:raw:PREROUTING" {
		t.Errorf("jump behind: repairs %v", rs)
	}
	if h.prerouting[0] != jumpLine("PREROUTING", rawComment, rawChainName) || len(h.prerouting) != 3 {
		t.Errorf("PREROUTING = %v", h.prerouting)
	}
	if fw.ahead["jump-order:raw:PREROUTING"] != "OTHER_raw" {
		t.Errorf("ahead = %v", fw.ahead)
	}
}

// Without a raw table (or the set match): today's behaviour, logged once,
// retried after an hour, nothing reported as a repair.
func TestEnsureRawUnavailable(t *testing.T) {
	h := &rawHost{failLoad: true}
	fakeRaw(t, h)
	buf := rawLog(t)
	now := time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)
	rawNow = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if rs := ensureRawNow(true); len(rs) != 0 {
			t.Errorf("repairs %v", rs)
		}
	}
	if len(h.restores) != 1 {
		t.Errorf("%d restores within the hour, want 1", len(h.restores))
	}
	if n := strings.Count(buf.String(), "early drop in the raw table not available"); n != 1 {
		t.Errorf("logged %d times:\n%s", n, buf.String())
	}
	if EarlyDropInForce() || len(h.prerouting) != 0 {
		t.Errorf("in force %v, PREROUTING %v", EarlyDropInForce(), h.prerouting)
	}
	now = now.Add(rawRetry)
	ensureRawNow(true)
	if len(h.restores) != 2 || strings.Count(buf.String(), "not available") != 1 {
		t.Errorf("after an hour: %d restores, log:\n%s", len(h.restores), buf.String())
	}
	h.failLoad = false
	now = now.Add(rawRetry)
	ensureRawNow(true)
	if !EarlyDropInForce() {
		t.Error("not in force once the table works")
	}
}

// Early drop switched off (monitor mode): chain and jump go, other raw
// rules stay; nothing is listed again at the next Ensure.
func TestEnsureRawOffRemoves(t *testing.T) {
	h := &rawHost{prerouting: []string{"-A PREROUTING -j CT --notrack"}}
	fakeRaw(t, h)
	rawLog(t)
	ensureRawNow(true)
	fw.Lock()
	fw.earlyDrop = false
	fw.Unlock()
	ensureRawNow(true)
	if h.chain != nil || len(h.prerouting) != 1 || h.prerouting[0] != "-A PREROUTING -j CT --notrack" {
		t.Fatalf("after off: chain %v, PREROUTING %v", h.chain, h.prerouting)
	}
	if EarlyDropInForce() {
		t.Error("still in force")
	}
	n := len(h.cmds)
	ensureRawNow(true)
	if len(h.cmds) != n {
		t.Errorf("Ensure with early drop off ran %v", h.cmds[n:])
	}
}

// An agent that starts in monitor mode removes a raw chain an earlier run
// left, once.
func TestEnsureRawLeftoverRemovedOnce(t *testing.T) {
	jump := jumpLine("PREROUTING", rawComment, rawChainName)
	h := &rawHost{chain: []string{"-A INFRAFENCE-RAW -m set --match-set infrafence-bans src -j DROP"}, prerouting: []string{jump}}
	fakeRaw(t, h)
	rawLog(t)
	fw.Lock()
	fw.earlyDrop = false
	fw.Unlock()
	ensureRawNow(true)
	if h.chain != nil || len(h.prerouting) != 0 {
		t.Fatalf("leftover kept: chain %v, PREROUTING %v", h.chain, h.prerouting)
	}
	n := len(h.cmds)
	ensureRawNow(true)
	if len(h.cmds) != n {
		t.Errorf("looked again: %v", h.cmds[n:])
	}
}

// The chain whose jump was ahead of ours is noted for the guard.
func TestJumpOrderNotesAhead(t *testing.T) {
	ours := jumpLine("INPUT", jumpComment, chainName)
	input := []string{"-A INPUT -j INPUT_imunify360", ours, "-A INPUT -m state --state ESTABLISHED -j ACCEPT"}
	oldRun := run
	t.Cleanup(func() { run = oldRun; fw.ahead = nil })
	var cmds []string
	run = func(name string, args ...string) (string, error) {
		c := name + " " + strings.Join(args, " ")
		cmds = append(cmds, c)
		if c == "iptables -S INPUT" {
			return strings.Join(input, "\n"), nil
		}
		return "", nil
	}
	fw.Lock()
	fw.ahead = nil
	rs, err := ensureJumpAhead("INPUT", jumpComment, chainName)
	ahead := fw.ahead["jump-order:INPUT"]
	fw.Unlock()
	if err != nil || strings.Join(rs, ",") != "jump-order:INPUT" {
		t.Fatalf("repairs %v, %v", rs, err)
	}
	if ahead != "INPUT_imunify360" {
		t.Errorf("ahead = %q", ahead)
	}
	if len(cmds) != 3 || !strings.HasPrefix(cmds[1], "iptables -I INPUT 1 ") || cmds[2] != "iptables -D INPUT 3" {
		t.Errorf("commands %v", cmds)
	}
}

func TestJumpTarget(t *testing.T) {
	for line, want := range map[string]string{
		"-A INPUT -j INPUT_imunify360":                  "INPUT_imunify360",
		"-A INPUT -p tcp --dport 22 -g ufw-user":        "ufw-user",
		"-A INPUT -m comment --comment x -j INFRAFENCE": "INFRAFENCE",
		"-A INPUT -s 1.2.3.4":                           "",
	} {
		if got := jumpTarget(line); got != want {
			t.Errorf("jumpTarget(%q) = %q, want %q", line, got, want)
		}
	}
}

// Uninstall (RemoveAll, removeChainsOf) also removes the raw chain; a
// legacy raw table that is not loaded is not touched (listing it would
// load it).
func TestRemoveRaw(t *testing.T) {
	h := &rawHost{chain: []string{}, prerouting: []string{jumpLine("PREROUTING", rawComment, rawChainName), "-A PREROUTING -j CT --notrack"}}
	fakeRaw(t, h)
	done := removeRawOf("iptables")
	if strings.Join(done, ",") != "jump:raw:PREROUTING->INFRAFENCE-RAW,chain:raw:INFRAFENCE-RAW" {
		t.Errorf("done = %v", done)
	}
	if h.chain != nil || len(h.prerouting) != 1 {
		t.Errorf("chain %v, PREROUTING %v", h.chain, h.prerouting)
	}

	dir := t.TempDir()
	old := legacyTables4
	t.Cleanup(func() { legacyTables4 = old })
	legacyTables4 = dir + "/ip_tables_names"
	_ = os.WriteFile(legacyTables4, []byte("filter\n"), 0o644)
	n := len(h.cmds)
	if done := removeRawOf("iptables-legacy"); done != nil || len(h.cmds) != n {
		t.Errorf("unloaded legacy raw table touched: %v %v", done, h.cmds[n:])
	}
}

// Before SetEarlyDrop is first called (startup, monitor mode not known
// yet) a chain the previous run left is neither removed nor rewritten.
func TestEnsureRawUnsetLeavesChain(t *testing.T) {
	jump := jumpLine("PREROUTING", rawComment, rawChainName)
	h := &rawHost{chain: []string{"-A INFRAFENCE-RAW -m set --match-set infrafence-bans src -j DROP"}, prerouting: []string{jump}}
	fakeRaw(t, h)
	fw.Lock()
	fw.earlyDropSet = false
	fw.Unlock()
	ensureRawNow(true)
	if len(h.cmds) != 0 || len(h.restores) != 0 || h.chain == nil {
		t.Errorf("unset early drop touched the raw table: %v %v", h.cmds, h.restores)
	}
}

// A chain whose jump was refused is still removed when early drop goes
// off (monitor mode), and a removal that did not work is retried.
func TestEnsureRawOffAfterJumpFailure(t *testing.T) {
	h := &rawHost{failJump: true}
	fakeRaw(t, h)
	buf := rawLog(t)
	ensureRawNow(true)
	if h.chain == nil || EarlyDropInForce() || !strings.Contains(buf.String(), "not available") {
		t.Fatalf("setup: chain %v, in force %v, log %s", h.chain, EarlyDropInForce(), buf.String())
	}
	fw.Lock()
	fw.earlyDrop = false
	fw.Unlock()
	ensureRawNow(true)
	if h.chain != nil {
		t.Fatalf("chain left after early drop off: %v", h.chain)
	}

	// The removal fails (the chain cannot be flushed): tried again.
	h2 := &rawHost{}
	fakeRaw(t, h2)
	ensureRawNow(true)
	fw.Lock()
	fw.earlyDrop = false
	fw.Unlock()
	oldRun := run
	run = func(name string, args ...string) (string, error) {
		if len(args) > 2 && args[2] == "-F" {
			return "busy", errors.New("exit status 4")
		}
		return oldRun(name, args...)
	}
	ensureRawNow(true)
	if h2.chain == nil {
		t.Fatal("setup: the chain should have stayed")
	}
	run = oldRun
	ensureRawNow(true)
	if h2.chain != nil {
		t.Errorf("removal not retried: %v", h2.chain)
	}
}

func TestAcceptersAhead(t *testing.T) {
	lines := []string{"-A INPUT -j INPUT_imunify360", "-A INPUT -s 1.2.3.4 -j DROP", "-A INPUT -p tcp --dport 80 -j ACCEPT", "-A INPUT -j f2b-sshd"}
	if got := acceptersAhead(lines); got != "INPUT_imunify360,ACCEPT" {
		t.Errorf("acceptersAhead = %q", got)
	}
}
