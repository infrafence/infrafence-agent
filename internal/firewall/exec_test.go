package firewall

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeBins puts shell scripts named after the firewall tools first in PATH
// and forgets which of them support -w.
func fakeBins(t *testing.T, scripts map[string]string) {
	t.Helper()
	dir := t.TempDir()
	for name, body := range scripts {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	waitOK.Clear()
	t.Cleanup(waitOK.Clear)
}

func withExecTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	old := execTimeout
	execTimeout = d
	t.Cleanup(func() { execTimeout = old })
}

// iptables gets -w 5 when it accepts it.
func TestRunAddsWait(t *testing.T) {
	fakeBins(t, map[string]string{
		"iptables":         `echo "$@"`,
		"iptables-restore": `[ "$1" = -w ] && [ "$3" = -V ] && exit 0; echo "$@"; cat`,
	})
	if out, err := run("iptables", "-S", "INPUT"); err != nil || out != "-w 5 -S INPUT" {
		t.Errorf("run = %q, %v; want -w 5 first", out, err)
	}
	if out, err := runStdin("*filter", "iptables-restore", "--noflush"); err != nil || out != "-w 5 --noflush\n*filter" {
		t.Errorf("runStdin = %q, %v", out, err)
	}
	if out, _ := run("ipset", "-v"); strings.Contains(out, "-w 5") {
		t.Errorf("-w passed to ipset: %q", out)
	}
}

// An old iptables without "-w <seconds>" gets none.
func TestRunWithoutWaitSupport(t *testing.T) {
	fakeBins(t, map[string]string{"iptables": `[ "$1" = -w ] && { echo "unknown option" >&2; exit 2; }; echo "$@"`})
	if out, err := run("iptables", "-S", "INPUT"); err != nil || out != "-S INPUT" {
		t.Errorf("run = %q, %v; want no -w", out, err)
	}
}

// A hung iptables (one that sleeps) is killed at the timeout, and Ensure
// returns its error with fw unlocked.
func TestExecTimeout(t *testing.T) {
	hang := `[ "$1" = -w ] && [ "$3" = -V ] && exit 0; exec sleep 30`
	fakeBins(t, map[string]string{"iptables": hang, "iptables-restore": hang, "ipset": hang})
	withExecTimeout(t, 300*time.Millisecond)
	start := time.Now()
	_, err := run("iptables", "-S", "INPUT")
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err = %v, want a timeout", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("run took %v", d)
	}

	checkIpset()
	oldIpset := ipsetAvailable
	ipsetAvailable = false
	fw.Lock()
	oldInit, oldDesired, oldApplied := fw.initialized, fw.lastDesired, fw.applied
	fw.lastDesired, fw.applied = "", nil
	fw.Unlock()
	t.Cleanup(func() {
		ipsetAvailable = oldIpset
		fw.Lock()
		fw.initialized, fw.lastDesired, fw.applied = oldInit, oldDesired, oldApplied
		fw.Unlock()
	})
	done := make(chan error, 1)
	go func() { _, err := Ensure(); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("Ensure succeeded with every command hanging")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Ensure still running")
	}
	if !fw.TryLock() {
		t.Fatal("fw still locked after a timed-out Ensure")
	}
	fw.Unlock()
}
