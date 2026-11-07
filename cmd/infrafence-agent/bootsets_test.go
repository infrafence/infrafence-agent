package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// withBootSetsHost points the unit, the hook and the systemd marker into a
// temporary directory and records systemctl calls.
func withBootSetsHost(t *testing.T, systemd bool, enabled bool) (dir string, calls *[]string) {
	t.Helper()
	dir = t.TempDir()
	oldUnit, oldHook, oldRun, oldSvc, oldCtl := bootSetsUnitPath, bootSetsHookPath, systemdRunningPath, agentServicePaths, systemctl
	bootSetsUnitPath = filepath.Join(dir, "infrafence-ipsets.service")
	bootSetsHookPath = filepath.Join(dir, "if-pre-up.d", "infrafence-ipsets")
	systemdRunningPath = filepath.Join(dir, "systemd")
	agentServicePaths = []string{filepath.Join(dir, "infrafence-agent.service")}
	if systemd {
		_ = os.Mkdir(systemdRunningPath, 0o755)
	}
	var c []string
	systemctl = func(args ...string) error {
		c = append(c, strings.Join(args, " "))
		if args[0] == "is-enabled" && !enabled {
			return os.ErrNotExist
		}
		if args[0] == "enable" {
			enabled = true
		}
		return nil
	}
	t.Cleanup(func() {
		bootSetsUnitPath, bootSetsHookPath, systemdRunningPath, agentServicePaths, systemctl = oldUnit, oldHook, oldRun, oldSvc, oldCtl
	})
	return dir, &c
}

func TestInstallBootSetsSystemd(t *testing.T) {
	_, calls := withBootSetsHost(t, true, false)
	what, err := installBootSets()
	if err != nil || what != bootSetsUnitPath {
		t.Fatalf("installBootSets = %q, %v", what, err)
	}
	data, _ := os.ReadFile(bootSetsUnitPath)
	for _, want := range []string{
		"DefaultDependencies=no",
		"Before=network-pre.target netfilter-persistent.service iptables.service ip6tables.service hestia-iptables.service",
		"ExecStart=/usr/local/bin/infrafence-agent boot-sets",
		"WantedBy=sysinit.target",
	} {
		if !strings.Contains(string(data), want) {
			t.Errorf("unit lacks %q", want)
		}
	}
	if want := []string{"daemon-reload", "enable --quiet infrafence-ipsets.service"}; !reflect.DeepEqual(*calls, want) {
		t.Errorf("systemctl calls %v, want %v", *calls, want)
	}
	// Again (every agent start): nothing written, nothing enabled.
	*calls = nil
	if what, err := installBootSets(); err != nil || what != "" {
		t.Errorf("second installBootSets = %q, %v", what, err)
	}
	if want := []string{"is-enabled --quiet infrafence-ipsets.service"}; !reflect.DeepEqual(*calls, want) {
		t.Errorf("second run: systemctl calls %v", *calls)
	}
	if _, err := os.Stat(bootSetsHookPath); err == nil {
		t.Error("hook written on a systemd host")
	}
}

// Without systemd, with ifupdown: the if-pre-up.d hook.
func TestInstallBootSetsIfupdown(t *testing.T) {
	_, calls := withBootSetsHost(t, false, false)
	if err := os.MkdirAll(filepath.Dir(bootSetsHookPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if what, err := installBootSets(); err != nil || what != bootSetsHookPath {
		t.Fatalf("installBootSets = %q, %v", what, err)
	}
	st, err := os.Stat(bootSetsHookPath)
	if err != nil || st.Mode().Perm() != 0o755 {
		t.Errorf("hook: %v %v", st, err)
	}
	if len(*calls) != 0 || exists(bootSetsUnitPath) {
		t.Errorf("systemd touched: %v", *calls)
	}
	if removed := removeBootSets(); !reflect.DeepEqual(removed, []string{bootSetsHookPath}) {
		t.Errorf("removed %v", removed)
	}
}

// At startup only on a host install.sh set up (not in a container).
func TestDeployBootSetsNeedsInstall(t *testing.T) {
	dir, _ := withBootSetsHost(t, true, false)
	deployBootSets()
	if exists(bootSetsUnitPath) {
		t.Fatal("unit written without the agent's service")
	}
	if err := os.WriteFile(filepath.Join(dir, "infrafence-agent.service"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	deployBootSets()
	if !exists(bootSetsUnitPath) {
		t.Fatal("unit not written")
	}
	if removed := removeBootSets(); !reflect.DeepEqual(removed, []string{bootSetsUnitPath}) || exists(bootSetsUnitPath) {
		t.Errorf("removed %v", removed)
	}
}
