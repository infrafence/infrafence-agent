package main

import (
	"bytes"
	"errors"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// fakeHost is a host in a temporary directory: the unit, the hook, the
// markers and systemd's marker, with systemctl recorded and the unit's
// enablement state kept.
type fakeHost struct {
	dir   string
	calls []string
	state string // what "systemctl is-enabled" answers
}

func withBootSetsHost(t *testing.T, systemd bool) *fakeHost {
	t.Helper()
	h := &fakeHost{dir: t.TempDir(), state: "not-found"}
	oldUnit, oldHook, oldRun, oldSvc, oldCtl := bootSetsUnitPath, bootSetsHookPath, systemdRunningPath, agentServicePaths, systemctl
	oldMark, oldNoted, oldBoot := bootSetsMarker, bootSetsNoted, bootIDPath
	bootSetsUnitPath = filepath.Join(h.dir, "infrafence-ipsets.service")
	bootSetsHookPath = filepath.Join(h.dir, "if-pre-up.d", "infrafence-ipsets")
	systemdRunningPath = filepath.Join(h.dir, "systemd")
	agentServicePaths = []string{filepath.Join(h.dir, "infrafence-agent.service")}
	bootSetsMarker = filepath.Join(h.dir, "lib", "boot-sets-installed")
	bootSetsNoted = filepath.Join(h.dir, "lib", "boot-sets-notice")
	bootIDPath = filepath.Join(h.dir, "boot_id")
	_ = os.WriteFile(bootIDPath, []byte("boot-1\n"), 0o644)
	if systemd {
		_ = os.Mkdir(systemdRunningPath, 0o755)
	}
	systemctl = func(args ...string) (string, error) {
		h.calls = append(h.calls, strings.Join(args, " "))
		switch args[0] {
		case "is-enabled":
			if h.state != "enabled" {
				return h.state, errors.New("exit status 1")
			}
			return h.state, nil
		case "enable":
			h.state = "enabled"
		case "disable":
			h.state = "disabled"
		}
		return "", nil
	}
	t.Cleanup(func() {
		bootSetsUnitPath, bootSetsHookPath, systemdRunningPath, agentServicePaths, systemctl = oldUnit, oldHook, oldRun, oldSvc, oldCtl
		bootSetsMarker, bootSetsNoted, bootIDPath = oldMark, oldNoted, oldBoot
	})
	return h
}

func (h *fakeHost) installAgent(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(agentServicePaths[0], nil, 0o644); err != nil {
		t.Fatal(err)
	}
}

// captureLog returns what log printed while fn ran.
func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	var b bytes.Buffer
	old := log.Writer()
	log.SetOutput(&b)
	defer log.SetOutput(old)
	fn()
	return b.String()
}

func TestInstallBootSetsSystemd(t *testing.T) {
	h := withBootSetsHost(t, true)
	what, err := installBootSets(true)
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
	if want := []string{"daemon-reload", "is-enabled infrafence-ipsets.service", "enable --quiet infrafence-ipsets.service"}; !reflect.DeepEqual(h.calls, want) {
		t.Errorf("systemctl calls %v, want %v", h.calls, want)
	}
	if !exists(bootSetsMarker) {
		t.Error("no installed-once marker")
	}
	// Again (every agent start): nothing written, nothing enabled.
	h.calls = nil
	if what, err := installBootSets(false); err != nil || what != "" {
		t.Errorf("second installBootSets = %q, %v", what, err)
	}
	if want := []string{"is-enabled infrafence-ipsets.service", "is-enabled infrafence-ipsets.service"}; !reflect.DeepEqual(h.calls, want) {
		t.Errorf("second run: systemctl calls %v", h.calls)
	}
	if _, err := os.Stat(bootSetsHookPath); err == nil {
		t.Error("hook written on a systemd host")
	}
}

// A unit masked by the administrator (a symlink to /dev/null) is never
// replaced, not even by an explicit install.
func TestBootSetsMaskedNotReplaced(t *testing.T) {
	h := withBootSetsHost(t, true)
	target := filepath.Join(h.dir, "null")
	_ = os.WriteFile(target, nil, 0o644)
	if err := os.Symlink(target, bootSetsUnitPath); err != nil {
		t.Fatal(err)
	}
	for _, explicit := range []bool{false, true} {
		if _, err := installBootSets(explicit); !errors.Is(err, errMasked) {
			t.Errorf("explicit=%v: err = %v, want errMasked", explicit, err)
		}
	}
	if st, err := os.Lstat(bootSetsUnitPath); err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Error("symlink replaced")
	}
	if len(h.calls) != 0 {
		t.Errorf("systemctl called: %v", h.calls)
	}
	// Uninstall leaves the administrator's mask too.
	removeBootSets()
	if _, err := os.Lstat(bootSetsUnitPath); err != nil {
		t.Error("mask removed")
	}
}

// Disabled or removed after the first install: the agent's start leaves
// it so (an update of the file is still written, never re-enabled); an
// explicit install puts it back.
func TestBootSetsAdminChoiceRespected(t *testing.T) {
	h := withBootSetsHost(t, true)
	if _, err := installBootSets(false); err != nil {
		t.Fatal(err)
	}
	h.state = "disabled"
	_ = os.WriteFile(bootSetsUnitPath, []byte("old version"), 0o644)
	h.calls = nil
	_, err := installBootSets(false)
	var admin errAdmin
	if !errors.As(err, &admin) || admin.state != "disabled" {
		t.Fatalf("err = %v, want disabled by the administrator", err)
	}
	if data, _ := os.ReadFile(bootSetsUnitPath); string(data) != bootSetsUnit {
		t.Error("updated unit file not written")
	}
	for _, c := range h.calls {
		if strings.HasPrefix(c, "enable") {
			t.Errorf("re-enabled: %v", h.calls)
		}
	}
	// Removed: not recreated at start.
	_ = os.Remove(bootSetsUnitPath)
	if _, err := installBootSets(false); !errors.As(err, &admin) || admin.state != "removed" {
		t.Errorf("removed: err = %v", err)
	}
	if exists(bootSetsUnitPath) {
		t.Error("removed unit recreated")
	}
	if what, err := installBootSets(true); err != nil || what != bootSetsUnitPath || h.state != "enabled" {
		t.Errorf("explicit install: %q %v %s", what, err, h.state)
	}
}

// Without systemd, with ifupdown: the if-pre-up.d hook, not recreated
// once the administrator removed it.
func TestInstallBootSetsIfupdown(t *testing.T) {
	h := withBootSetsHost(t, false)
	if err := os.MkdirAll(filepath.Dir(bootSetsHookPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if what, err := installBootSets(false); err != nil || what != bootSetsHookPath {
		t.Fatalf("installBootSets = %q, %v", what, err)
	}
	st, err := os.Stat(bootSetsHookPath)
	if err != nil || st.Mode().Perm() != 0o755 {
		t.Errorf("hook: %v %v", st, err)
	}
	if data, _ := os.ReadFile(bootSetsHookPath); !strings.Contains(string(data), "timeout 20 ") || !strings.HasSuffix(string(data), "exit 0\n") {
		t.Errorf("hook:\n%s", data)
	}
	if len(h.calls) != 0 || exists(bootSetsUnitPath) {
		t.Errorf("systemd touched: %v", h.calls)
	}
	_ = os.Remove(bootSetsHookPath)
	if _, err := installBootSets(false); err == nil || exists(bootSetsHookPath) {
		t.Errorf("removed hook recreated (err %v)", err)
	}
	if removed := removeBootSets(); len(removed) != 0 || exists(bootSetsMarker) {
		t.Errorf("removed %v, marker left: %v", removed, exists(bootSetsMarker))
	}
}

// At startup only on a host install.sh set up: never in a container.
func TestDeployBootSetsNeedsInstall(t *testing.T) {
	h := withBootSetsHost(t, true)
	deployBootSets()
	if exists(bootSetsUnitPath) || len(h.calls) != 0 {
		t.Fatalf("installed without the agent's service: %v", h.calls)
	}
	h.installAgent(t)
	deployBootSets()
	if !exists(bootSetsUnitPath) || h.state != "enabled" {
		t.Fatal("unit not installed")
	}
	if removed := removeBootSets(); !reflect.DeepEqual(removed, []string{bootSetsUnitPath}) || exists(bootSetsUnitPath) {
		t.Errorf("removed %v", removed)
	}
}

// /etc read only: one log line per boot and version, however often the
// agent starts.
func TestDeployBootSetsReadOnlyLogsOnce(t *testing.T) {
	h := withBootSetsHost(t, true)
	h.installAgent(t)
	// The unit's directory is a file: every write fails, like a read-only /etc.
	bootSetsUnitPath = filepath.Join(agentServicePaths[0], "infrafence-ipsets.service")
	var logs string
	for i := 0; i < 3; i++ {
		logs += captureLog(t, deployBootSets)
	}
	if n := strings.Count(logs, "[firewall]"); n != 1 {
		t.Errorf("%d log lines, want 1:\n%s", n, logs)
	}
	// A new boot logs it again.
	_ = os.WriteFile(bootIDPath, []byte("boot-2\n"), 0o644)
	if logs := captureLog(t, deployBootSets); !strings.Contains(logs, "infrafence-ipsets.service") {
		t.Errorf("not logged after a new boot: %q", logs)
	}
}

// Uninstall stops and disables the agent first.
func TestStopAgentService(t *testing.T) {
	h := withBootSetsHost(t, true)
	if done := stopAgentService(); done != nil {
		t.Errorf("container: %v", done)
	}
	h.installAgent(t)
	systemctl = func(args ...string) (string, error) {
		h.calls = append(h.calls, strings.Join(args, " "))
		switch args[0] {
		case "is-active":
			return "active", nil
		case "is-enabled":
			return "enabled", nil
		}
		return "", nil
	}
	if done := stopAgentService(); !reflect.DeepEqual(done, []string{"stopped infrafence-agent.service", "disabled infrafence-agent.service"}) {
		t.Errorf("done %v (calls %v)", done, h.calls)
	}
}
