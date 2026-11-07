package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/infrafence/infrafence-agent/internal/firewall"
)

// The agent's ipsets at boot (firewall.CreateBootSets): a ruleset saved
// while the agent runs references them, and its restore at boot fails as a
// whole when they don't exist yet. infrafence-ipsets.service creates them
// before any firewall service restores a saved ruleset; on a host without
// systemd an if-pre-up.d hook does it before ifupdown's own restore hooks
// (HestiaCP and VestaCP before 1.4.11 restored from
// /etc/network/if-pre-up.d/iptables). install.sh installs them with
// "boot-sets --install", the agent puts them in place at startup on hosts
// install.sh set up (once: what the administrator does to them afterwards,
// a disable, a mask, a removal, is respected), and "uninstall --clean"
// removes them.
var (
	bootSetsUnitPath   = "/etc/systemd/system/infrafence-ipsets.service"
	bootSetsHookPath   = "/etc/network/if-pre-up.d/infrafence-ipsets"
	systemdRunningPath = "/run/systemd/system"
	// bootSetsMarker records that the unit or hook was installed once.
	bootSetsMarker = "/var/lib/infrafence/boot-sets-installed"
	// bootSetsNoted is the last notice logged at startup, with the boot
	// and the agent version it was logged for.
	bootSetsNoted = "/var/lib/infrafence/boot-sets-notice"
	bootIDPath    = "/proc/sys/kernel/random/boot_id"
	// The agent's own service, written by install.sh (systemd, Upstart,
	// SysV): a host install.sh set up, not a container.
	agentServicePaths = []string{"/etc/systemd/system/infrafence-agent.service", "/etc/init/infrafence-agent.conf", "/etc/init.d/infrafence-agent"}
	systemctl         = runSystemctl
	systemctlTimeout  = 20 * time.Second
)

// runSystemctl runs systemctl with a timeout: a wedged systemd or D-Bus
// must not hold the caller.
func runSystemctl(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), systemctlTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "systemctl", args...)
	cmd.WaitDelay = 2 * time.Second
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

const bootSetsUnitName = "infrafence-ipsets.service"

const bootSetsUnit = `[Unit]
Description=InfraFence ipsets for saved firewall rules
Documentation=https://infrafence.com/docs
# Creates, empty, the ipsets a saved iptables ruleset references, before
# that ruleset is restored (the restore fails as a whole without them).
DefaultDependencies=no
After=systemd-modules-load.service local-fs.target
Before=network-pre.target netfilter-persistent.service iptables.service ip6tables.service hestia-iptables.service shutdown.target
Conflicts=shutdown.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/infrafence-agent boot-sets
TimeoutStartSec=30

[Install]
WantedBy=sysinit.target
`

const bootSetsHook = `#!/bin/sh
# InfraFence: creates, empty, the ipsets a saved iptables ruleset
# references, before it is restored (infrafence-agent boot-sets).
if [ -x /usr/local/bin/infrafence-agent ]; then
    if command -v timeout >/dev/null 2>&1; then
        timeout 20 /usr/local/bin/infrafence-agent boot-sets >/dev/null 2>&1
    else
        /usr/local/bin/infrafence-agent boot-sets >/dev/null 2>&1
    fi
fi
exit 0
`

// errMasked: the unit path is a symlink (systemctl mask links it to
// /dev/null), never replaced.
var errMasked = errors.New("is a symlink (masked?): left as it is")

// cmdBootSets: "boot-sets" creates the sets (run at boot), "boot-sets
// --install" installs the unit or hook that runs it.
func cmdBootSets(args []string) {
	if len(args) > 0 && args[0] == "--install" {
		what, err := installBootSets(true)
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not install %s: %v\n", what, err)
			os.Exit(1)
		}
		if what != "" {
			fmt.Println("installed", what)
		}
		return
	}
	if len(args) > 0 {
		fmt.Fprintln(os.Stderr, "usage: infrafence-agent boot-sets [--install]")
		os.Exit(1)
	}
	created, err := firewall.CreateBootSets()
	for _, n := range created {
		fmt.Println("created empty set", n, "(referenced by a saved ruleset)")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// installBootSets writes and enables the unit (systemd) or the hook (a host
// with ifupdown and no systemd), and names it; "" when nothing was done.
// explicit is install.sh (the administrator installing): the unit is
// written and enabled. Otherwise (agent start) it is put in place only
// the first time; afterwards an updated unit file is rewritten but never
// re-enabled, and a unit or hook the administrator removed, disabled or
// masked is left so (errAdmin says which). A symlink is never replaced.
func installBootSets(explicit bool) (string, error) {
	once := exists(bootSetsMarker)
	if exists(systemdRunningPath) {
		if st, err := os.Lstat(bootSetsUnitPath); err == nil && st.Mode()&os.ModeSymlink != 0 {
			return bootSetsUnitPath, errMasked
		} else if err != nil && once && !explicit {
			return bootSetsUnitPath, adminChoice("removed")
		}
		if once && !explicit {
			if state, _ := systemctl("is-enabled", bootSetsUnitName); state == "disabled" || strings.HasPrefix(state, "masked") {
				// An update of the file itself is still applied.
				if changed, err := writeIfChanged(bootSetsUnitPath, bootSetsUnit, 0o644); err != nil {
					return bootSetsUnitPath, err
				} else if changed {
					_, _ = systemctl("daemon-reload")
				}
				return bootSetsUnitPath, adminChoice(state)
			}
		}
		changed, err := writeIfChanged(bootSetsUnitPath, bootSetsUnit, 0o644)
		if err != nil {
			return bootSetsUnitPath, err
		}
		if changed {
			if out, err := systemctl("daemon-reload"); err != nil {
				return bootSetsUnitPath, fmt.Errorf("systemctl daemon-reload: %s (%w)", out, err)
			}
		}
		did := changed
		if state, _ := systemctl("is-enabled", bootSetsUnitName); state != "enabled" {
			if out, err := systemctl("enable", "--quiet", bootSetsUnitName); err != nil {
				return bootSetsUnitPath, fmt.Errorf("systemctl enable: %s (%w)", out, err)
			}
			did = true
		}
		markBootSets()
		if did {
			return bootSetsUnitPath, nil
		}
		return "", nil
	}
	if exists(filepath.Dir(bootSetsHookPath)) {
		if st, err := os.Lstat(bootSetsHookPath); err == nil && st.Mode()&os.ModeSymlink != 0 {
			return bootSetsHookPath, errMasked
		} else if err != nil && once && !explicit {
			return bootSetsHookPath, adminChoice("removed")
		}
		changed, err := writeIfChanged(bootSetsHookPath, bootSetsHook, 0o755)
		if err != nil {
			return bootSetsHookPath, err
		}
		markBootSets()
		if changed {
			return bootSetsHookPath, nil
		}
	}
	return "", nil
}

// errAdmin: the administrator removed, disabled or masked what was
// installed once; it is left so.
type errAdmin struct{ state string }

func (e errAdmin) Error() string {
	return e.state + " by the administrator after it was installed: left so. A ruleset saved while the agent runs " +
		"then fails to restore at boot; \"infrafence-agent boot-sets --install\" puts it back"
}

func adminChoice(state string) error { return errAdmin{state} }

func markBootSets() {
	if exists(bootSetsMarker) {
		return
	}
	_ = os.MkdirAll(filepath.Dir(bootSetsMarker), 0o755)
	_ = os.WriteFile(bootSetsMarker, []byte("infrafence-ipsets installed by the agent; removed by uninstall\n"), 0o644)
}

// deployBootSets puts the unit or hook in place at startup, on a host
// install.sh set up (an agent updated from a version without it gets it).
// Run in its own goroutine: it never holds up the agent's start.
func deployBootSets() {
	for _, p := range agentServicePaths {
		if !exists(p) {
			continue
		}
		what, err := installBootSets(false)
		switch {
		case err != nil:
			noteBootSets(fmt.Sprintf("[firewall] %s: %v", what, err))
		case what != "":
			log.Printf("[firewall] installed %s: saved iptables rulesets that reference the agent's ipsets restore at boot", what)
		}
		return
	}
}

// noteBootSets logs msg once per boot and agent version: a crash-looping
// agent, or a read-only /etc, must not repeat it at every start.
func noteBootSets(msg string) {
	bootID, _ := os.ReadFile(bootIDPath)
	key := strings.TrimSpace(string(bootID)) + " " + version + " " + msg
	if old, err := os.ReadFile(bootSetsNoted); err == nil && string(old) == key {
		return
	}
	log.Print(msg)
	_ = os.MkdirAll(filepath.Dir(bootSetsNoted), 0o755)
	_ = os.WriteFile(bootSetsNoted, []byte(key), 0o644)
}

// removeBootSets removes the unit, the hook and their markers (uninstall).
func removeBootSets() (removed []string) {
	if st, err := os.Lstat(bootSetsUnitPath); err == nil {
		_, _ = systemctl("disable", "--quiet", bootSetsUnitName)
		if st.Mode()&os.ModeSymlink == 0 {
			if err := os.Remove(bootSetsUnitPath); err == nil {
				removed = append(removed, bootSetsUnitPath)
				_, _ = systemctl("daemon-reload")
			}
		}
	}
	if err := os.Remove(bootSetsHookPath); err == nil {
		removed = append(removed, bootSetsHookPath)
	}
	_ = os.Remove(bootSetsMarker)
	_ = os.Remove(bootSetsNoted)
	return removed
}

// stopAgentService stops and disables the agent's systemd service before
// an uninstall (when it isn't the caller): a running or restarted agent
// would put its chains and the boot unit back.
func stopAgentService() []string {
	if !exists(systemdRunningPath) || !exists(agentServicePaths[0]) {
		return nil
	}
	var done []string
	if state, _ := systemctl("is-active", "infrafence-agent.service"); state == "active" || state == "activating" {
		if _, err := systemctl("stop", "infrafence-agent.service"); err == nil {
			done = append(done, "stopped infrafence-agent.service")
		}
	}
	if state, _ := systemctl("is-enabled", "infrafence-agent.service"); state == "enabled" {
		if _, err := systemctl("disable", "--quiet", "infrafence-agent.service"); err == nil {
			done = append(done, "disabled infrafence-agent.service")
		}
	}
	return done
}

// savedRulesetWarnings tells, after the agent's chains and sets are gone,
// which saved rulesets still hold them and how to save each one again.
func savedRulesetWarnings() []string {
	var out []string
	for _, f := range firewall.SavedRulesetsWithAgent() {
		out = append(out, fmt.Sprintf("WARNING: the saved ruleset %s still contains InfraFence's chains: restored at boot, it fails as a whole (its ipsets are gone) or brings InfraFence's rules back. Save the current rules again now: %s", f.Path, f.Save))
	}
	return out
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// writeIfChanged writes content to path (atomically) unless it already
// holds it, and reports whether it wrote.
func writeIfChanged(path, content string, mode os.FileMode) (bool, error) {
	if old, err := os.ReadFile(path); err == nil && string(old) == content {
		return false, nil
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), mode); err != nil {
		return false, err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return false, err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return false, err
	}
	return true, nil
}
