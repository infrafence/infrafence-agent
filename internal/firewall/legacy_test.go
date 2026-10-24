package firewall

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// legacyHost describes a host for removeStaleLegacy.
type legacyHost struct {
	v4, v6     string // "iptables -V" and "ip6tables -V"
	loaded     bool   // legacy filter tables loaded
	ours       bool   // the agent's chains in the legacy backend
	docker     bool   // the agent's DOCKER-USER jump in the legacy backend
	nftDocker  bool   // a DOCKER-USER chain in the nf_tables backend
	legacyCmds []string
}

const (
	nftV    = "iptables v1.8.10 (nf_tables)"
	legacyV = "iptables v1.8.10 (legacy)"
)

func fakeLegacy(t *testing.T, h *legacyHost) {
	t.Helper()
	dir := t.TempDir()
	names := ""
	if h.loaded {
		names = "mangle\nfilter\n"
	}
	for _, f := range []string{"ip_tables_names", "ip6_tables_names"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(names), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	old4, old6, oldRun := legacyTables4, legacyTables6, run
	legacyTables4, legacyTables6 = filepath.Join(dir, "ip_tables_names"), filepath.Join(dir, "ip6_tables_names")
	deleted := map[string]bool{}
	run = func(name string, args ...string) (string, error) {
		c := name + " " + strings.Join(args, " ")
		switch c {
		case "iptables -V":
			return h.v4, nil
		case "ip6tables -V":
			return h.v6, nil
		case "iptables -S " + dockerChain, "ip6tables -S " + dockerChain:
			if !h.nftDocker {
				return "iptables: No chain/target/match by that name.", errors.New("exit status 1")
			}
			return "-N DOCKER-USER", nil
		}
		if !strings.HasSuffix(name, "-legacy") {
			return "", nil
		}
		h.legacyCmds = append(h.legacyCmds, c)
		switch {
		case len(args) == 1 && args[0] == "-S":
			out := "-P INPUT ACCEPT\n-N f2b-sshd\n-A INPUT -j f2b-sshd"
			if h.ours {
				out += "\n-N INFRAFENCE\n-N INFRAFENCE-PORTS\n-A INPUT -m comment --comment infrafence -j INFRAFENCE"
			}
			if h.docker {
				out += "\n" + jumpLine(dockerChain, jumpComment, chainName) + "\n" + jumpLine(dockerChain, ports6Comment, portsChainName)
			}
			return out, nil
		case args[0] == "-D":
			if deleted[c] || !h.ours {
				return "", errNoRule
			}
			deleted[c] = true
		case !h.ours:
			return "", errNoRule
		}
		return "", nil
	}
	t.Cleanup(func() { legacyTables4, legacyTables6, run = old4, old6, oldRun })
}

// changes are the legacy commands that changed something (not listings).
func (h *legacyHost) changes() []string {
	var out []string
	for _, c := range h.legacyCmds {
		if f := strings.Fields(c); len(f) > 1 && f[1] != "-S" {
			out = append(out, c)
		}
	}
	return out
}

// iptables switched from legacy to nf_tables (CSF's installer over
// iptables-legacy on Fedora): the agent's legacy chains go, nothing else.
func TestRemoveStaleLegacyAfterSwitchToNft(t *testing.T) {
	h := &legacyHost{v4: nftV, v6: nftV, loaded: true, ours: true, nftDocker: true}
	fakeLegacy(t, h)
	if done := removeStaleLegacy(true, true, false); len(done) == 0 {
		t.Fatal("stale legacy chains not removed")
	}
	removed4, removed6 := false, false
	for _, c := range h.changes() {
		f := strings.Fields(c)
		switch {
		case strings.Contains(c, "f2b") || strings.Contains(c, " -P ") || strings.Contains(c, " -t "):
			t.Errorf("touched what is not the agent's: %q", c)
		case (f[1] == "-F" || f[1] == "-X") && (len(f) < 3 || !strings.HasPrefix(f[2], "INFRAFENCE")):
			t.Errorf("flushed or deleted a chain that is not the agent's: %q", c)
		case f[1] == "-D" && !strings.Contains(c, "--comment infrafence"):
			t.Errorf("deleted a rule that is not the agent's: %q", c)
		}
		removed4 = removed4 || c == "iptables-legacy -X INFRAFENCE"
		removed6 = removed6 || c == "ip6tables-legacy -X INFRAFENCE-PORTS"
	}
	if !removed4 || !removed6 {
		t.Errorf("legacy chains left (v4 removed %v, v6 removed %v): %v", removed4, removed6, h.changes())
	}
}

// The legacy copy stays wherever it may be the one that works.
func TestRemoveStaleLegacyKeepsLiveRules(t *testing.T) {
	for _, c := range []struct {
		name   string
		host   legacyHost
		v4, v6 bool
	}{
		{"legacy is live", legacyHost{v4: legacyV, v6: legacyV, loaded: true, ours: true, nftDocker: true}, true, true},
		{"legacy not loaded", legacyHost{v4: nftV, v6: nftV, ours: true, nftDocker: true}, true, true},
		{"none of ours", legacyHost{v4: nftV, v6: nftV, loaded: true, nftDocker: true}, true, true},
		{"refused in nf_tables", legacyHost{v4: nftV, v6: nftV, loaded: true, ours: true, nftDocker: true}, false, false},
		{"ip6tables still legacy", legacyHost{v4: legacyV, v6: legacyV, loaded: true, ours: true, nftDocker: true}, false, true},
		{"docker on legacy", legacyHost{v4: nftV, v6: nftV, loaded: true, ours: true, docker: true}, true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := c.host
			fakeLegacy(t, &h)
			if done := removeStaleLegacy(c.v4, c.v6, false); len(done) > 0 {
				t.Errorf("removed %v", done)
			}
			if ch := h.changes(); len(ch) > 0 {
				t.Errorf("ran %v", ch)
			}
			if !h.loaded && len(h.legacyCmds) > 0 {
				t.Errorf("listed a legacy table that was not loaded: %v", h.legacyCmds)
			}
		})
	}
}

// Only the v6 copy goes when only ip6tables-nft's rules are in force, and
// uninstall removes the legacy copy even while Docker uses it.
func TestRemoveStaleLegacyPerFamilyAndUninstall(t *testing.T) {
	h := &legacyHost{v4: nftV, v6: nftV, loaded: true, ours: true, nftDocker: true}
	fakeLegacy(t, h)
	removeStaleLegacy(false, true, false)
	for _, c := range h.changes() {
		if strings.HasPrefix(c, "iptables-legacy ") {
			t.Errorf("v4 legacy changed while its nf_tables rules are not in force: %q", c)
		}
	}
	h2 := &legacyHost{v4: nftV, v6: nftV, loaded: true, ours: true, docker: true}
	fakeLegacy(t, h2)
	if done := removeStaleLegacy(true, true, true); len(done) == 0 {
		t.Error("uninstall left the legacy copy")
	}
}
