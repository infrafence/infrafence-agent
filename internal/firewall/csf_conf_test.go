package firewall

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const csfConfSample = `# CSF configuration
TESTING = "0"
# TCP_IN = "1,2,3"
TCP_IN = "20,21,22,25,80,443"
TCP_OUT = "20,21,22,25,53,80,443"
UDP_IN = "20,21,53"
`

// withCSFConf points the CSF edits at a copy of csf.conf (0640) and counts
// the restarts instead of running csf.
func withCSFConf(t *testing.T, conf string) (path string, restarts *int) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "csf.conf")
	if err := os.WriteFile(path, []byte(conf), 0o640); err != nil {
		t.Fatal(err)
	}
	restarts = new(int)
	savedPath, savedRestart := csfConfigPath, csfRestart
	t.Cleanup(func() { csfConfigPath, csfRestart = savedPath, savedRestart })
	csfConfigPath = path
	csfRestart = func() error { *restarts++; return nil }
	return path, restarts
}

func TestCSFPortActionEditsOnlyTheKey(t *testing.T) {
	path, restarts := withCSFConf(t, csfConfSample)
	if err := CSFPortAction(8080, "in", "add", false); err != nil {
		t.Fatal(err)
	}
	if err := CSFPortAction(25, "out", "remove", false); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	want := strings.NewReplacer(
		`TCP_IN = "20,21,22,25,80,443"`, `TCP_IN = "20,21,22,25,80,443,8080"`,
		`TCP_OUT = "20,21,22,25,53,80,443"`, `TCP_OUT = "20,21,22,53,80,443"`,
	).Replace(csfConfSample)
	if string(got) != want {
		t.Errorf("csf.conf:\n%s\nwant:\n%s", got, want)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o640 {
		t.Errorf("mode %v, want 0640", info.Mode().Perm())
	}
	if *restarts != 2 {
		t.Errorf("%d restarts, want 2", *restarts)
	}
	// Already as asked: nothing written, no restart.
	if err := CSFPortAction(8080, "in", "add", false); err != nil || *restarts != 2 {
		t.Errorf("repeated add: err=%v restarts=%d", err, *restarts)
	}
}

// In monitor mode nothing changes: csf.conf is untouched, CSF not restarted.
func TestCSFPortActionMonitorModeChangesNothing(t *testing.T) {
	path, restarts := withCSFConf(t, csfConfSample)
	before, _ := os.Stat(path)
	if err := CSFPortAction(8080, "in", "add", true); !errors.Is(err, ErrCSFMonitorMode) {
		t.Errorf("err = %v, want ErrCSFMonitorMode", err)
	}
	if got, _ := os.ReadFile(path); string(got) != csfConfSample {
		t.Errorf("csf.conf changed in monitor mode:\n%s", got)
	}
	if after, _ := os.Stat(path); !os.SameFile(before, after) || !after.ModTime().Equal(before.ModTime()) {
		t.Error("csf.conf replaced in monitor mode")
	}
	if *restarts != 0 {
		t.Errorf("CSF restarted in monitor mode")
	}
}

// A value that is not a strict port list is refused, never written (the
// old code passed it to sed -i, where "/" and "e" run commands).
func TestCSFRejectsInjection(t *testing.T) {
	path, restarts := withCSFConf(t, csfConfSample)
	for _, v := range []string{
		`22"/;s/.*/x/e;#`,
		"22\nTESTING = \"1\"",
		`22,$(reboot)`,
		`22 80`,
		`22,`,
		`-1`,
	} {
		if err := csfSetConfigValue("TCP_IN", v); err == nil {
			t.Errorf("value %q accepted", v)
		}
	}
	if err := csfSetConfigValue("TESTING", "1"); err == nil {
		t.Error("a key the agent does not change accepted")
	}
	for _, a := range []struct {
		port              int
		direction, action string
	}{
		{0, "in", "add"}, {65536, "in", "add"}, {-22, "in", "add"},
		{22, "sideways", "add"}, {22, "in", "flush"},
	} {
		if err := CSFPortAction(a.port, a.direction, a.action, false); err == nil {
			t.Errorf("%+v accepted", a)
		}
	}
	if got, _ := os.ReadFile(path); string(got) != csfConfSample || *restarts != 0 {
		t.Errorf("csf.conf changed (restarts %d):\n%s", *restarts, got)
	}
}

// A port list already in csf.conf that is not a strict one is left alone.
func TestCSFLeavesUnexpectedValueAlone(t *testing.T) {
	conf := strings.Replace(csfConfSample, `TCP_IN = "20,21,22,25,80,443"`, `TCP_IN = "22,$(id)"`, 1)
	path, restarts := withCSFConf(t, conf)
	if err := CSFPortAction(8080, "in", "add", false); err == nil {
		t.Error("rewrote an unexpected value")
	}
	if got, _ := os.ReadFile(path); string(got) != conf || *restarts != 0 {
		t.Errorf("csf.conf changed:\n%s", got)
	}
}
