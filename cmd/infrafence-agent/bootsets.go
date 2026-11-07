package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/infrafence/infrafence-agent/internal/firewall"
)

// The agent's ipsets at boot (firewall.CreateBootSets): a ruleset saved
// while the agent runs references them, and its restore at boot fails as a
// whole when they don't exist yet. infrafence-ipsets.service creates them
// before any firewall service restores a saved ruleset; on a host without
// systemd an if-pre-up.d hook does it before ifupdown's own restore hooks
// (HestiaCP and VestaCP before 1.4.11 restored from
// /etc/network/if-pre-up.d/iptables). install.sh installs them with
// "boot-sets --install", the agent puts them back at startup on hosts
// install.sh set up, and "uninstall --clean" removes them.
var (
	bootSetsUnitPath   = "/etc/systemd/system/infrafence-ipsets.service"
	bootSetsHookPath   = "/etc/network/if-pre-up.d/infrafence-ipsets"
	systemdRunningPath = "/run/systemd/system"
	// The agent's own service, written by install.sh (systemd, Upstart,
	// SysV): a host install.sh set up, not a container.
	agentServicePaths = []string{"/etc/systemd/system/infrafence-agent.service", "/etc/init/infrafence-agent.conf", "/etc/init.d/infrafence-agent"}
	systemctl         = func(args ...string) error { return exec.Command("systemctl", args...).Run() }
)

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
[ -x /usr/local/bin/infrafence-agent ] && /usr/local/bin/infrafence-agent boot-sets >/dev/null 2>&1
exit 0
`

// cmdBootSets: "boot-sets" creates the sets (run at boot), "boot-sets
// --install" installs the unit or hook that runs it.
func cmdBootSets(args []string) {
	if len(args) > 0 && args[0] == "--install" {
		what, err := installBootSets()
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
// with ifupdown and no systemd), and names it; "" when neither applies.
func installBootSets() (string, error) {
	if exists(systemdRunningPath) {
		changed, err := writeIfChanged(bootSetsUnitPath, bootSetsUnit, 0o644)
		if err != nil {
			return bootSetsUnitPath, err
		}
		if changed {
			if err := systemctl("daemon-reload"); err != nil {
				return bootSetsUnitPath, fmt.Errorf("systemctl daemon-reload: %w", err)
			}
		}
		if changed || systemctl("is-enabled", "--quiet", bootSetsUnitName) != nil {
			if err := systemctl("enable", "--quiet", bootSetsUnitName); err != nil {
				return bootSetsUnitPath, fmt.Errorf("systemctl enable: %w", err)
			}
			return bootSetsUnitPath, nil
		}
		return "", nil
	}
	if exists(filepath.Dir(bootSetsHookPath)) {
		changed, err := writeIfChanged(bootSetsHookPath, bootSetsHook, 0o755)
		if err != nil || changed {
			return bootSetsHookPath, err
		}
	}
	return "", nil
}

// deployBootSets puts the unit or hook back at startup, on a host
// install.sh set up (an agent updated from a version without it gets it).
func deployBootSets() {
	for _, p := range agentServicePaths {
		if exists(p) {
			if what, err := installBootSets(); err != nil {
				log.Printf("[firewall] %s: %v", what, err)
			} else if what != "" {
				log.Printf("[firewall] installed %s: saved iptables rulesets that reference the agent's ipsets restore at boot", what)
			}
			return
		}
	}
}

// removeBootSets removes the unit and the hook (uninstall).
func removeBootSets() (removed []string) {
	if exists(bootSetsUnitPath) {
		_ = systemctl("disable", "--quiet", bootSetsUnitName)
		if err := os.Remove(bootSetsUnitPath); err == nil {
			removed = append(removed, bootSetsUnitPath)
			_ = systemctl("daemon-reload")
		}
	}
	if err := os.Remove(bootSetsHookPath); err == nil {
		removed = append(removed, bootSetsHookPath)
	}
	return removed
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
