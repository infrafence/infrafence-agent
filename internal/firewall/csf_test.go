package firewall

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// /proc/locks as a container showed it while "csf -r" ran: csf.lock is
// inode 12623540.
const csfLocks = `1: FLOCK  ADVISORY  WRITE 9437 00:272:12623540 0 EOF
2: FLOCK  ADVISORY  WRITE 9437 00:272:12623541 0 EOF
3: POSIX  ADVISORY  WRITE 812 fd:01:12623540 0 EOF
`

func TestLockHeld(t *testing.T) {
	for _, c := range []struct {
		name  string
		locks string
		ino   uint64
		want  bool
	}{
		{"csf restarting", csfLocks, 12623540, true},
		{"waiting for it counts", "1: FLOCK  ADVISORY  WRITE 9437 00:272:1 0 EOF\n1: -> FLOCK  ADVISORY  WRITE 9500 00:272:99 0 EOF\n", 99, true},
		// btrfs: the lock names the filesystem's device, stat a subvolume's.
		{"device other than stat's", "1: FLOCK  ADVISORY  WRITE 1 00:2d:7 0 EOF\n", 7, true},
		{"other inode", csfLocks, 1262354, false},
		{"inode only as a suffix of digits", csfLocks, 3540, false},
		{"pid or offset equal to the inode", "1: FLOCK  ADVISORY  WRITE 7 00:2d:9 7 EOF\n", 7, false},
		{"no locks", "", 12623540, false},
	} {
		if got := lockHeld(c.locks, c.ino); got != c.want {
			t.Errorf("%s: lockHeld = %v, want %v", c.name, got, c.want)
		}
	}
}

// withCSFLock points CSFRestarting at a lock file of the test's.
func withCSFLock(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "csf.lock")
	oldFile, oldLocks := csfLockFile, procLocks
	csfLockFile = path
	t.Cleanup(func() { csfLockFile, procLocks = oldFile, oldLocks })
	return path
}

func TestCSFRestartingWithoutCSF(t *testing.T) {
	withCSFLock(t) // never created
	if CSFRestarting() {
		t.Fatal("restarting without a lock file")
	}
}

// The kernel's own /proc/locks: true only while the file is flocked, the
// way csf locks it.
func TestCSFRestartingReadsKernelLocks(t *testing.T) {
	if _, err := os.Stat("/proc/locks"); err != nil {
		t.Skip("no /proc/locks")
	}
	path := withCSFLock(t)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if CSFRestarting() {
		t.Fatal("restarting while nobody holds the lock")
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if !CSFRestarting() {
		locks, _ := os.ReadFile("/proc/locks")
		t.Fatalf("lock not seen; /proc/locks:\n%s", locks)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if CSFRestarting() {
		t.Fatal("still restarting after the unlock")
	}
}

// fakeIptablesCheck makes "iptables -C" exit with code (0: the rule is
// there) and records the calls.
func fakeIptablesCheck(t *testing.T, code int) *[]string {
	t.Helper()
	var calls []string
	old := run
	run = func(name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if code == 0 {
			return "", nil
		}
		err := exec.Command("sh", "-c", "exit "+strconv.Itoa(code)).Run()
		return "", err
	}
	t.Cleanup(func() { run = old })
	return &calls
}

func withFwFlags(t *testing.T, initialized, disabled bool) {
	t.Helper()
	fw.Lock()
	oldInit, oldDis := fw.initialized, fw.disabled
	fw.initialized, fw.disabled = initialized, disabled
	fw.Unlock()
	t.Cleanup(func() {
		fw.Lock()
		fw.initialized, fw.disabled = oldInit, oldDis
		fw.Unlock()
	})
}

func TestNeedsRepair(t *testing.T) {
	for _, c := range []struct {
		name                  string
		initialized, disabled bool
		code                  int
		want, calls           bool
	}{
		{"jump in place", true, false, 0, false, true},
		{"jump gone (INPUT flushed)", true, false, 1, true, true},
		{"chain gone too (csf -r deletes every chain)", true, false, 2, true, true},
		{"xtables lock held by another tool", true, false, 4, false, true},
		{"before the first Ensure", false, false, 1, false, false},
		{"protection switched off", true, true, 1, false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			withFwFlags(t, c.initialized, c.disabled)
			calls := fakeIptablesCheck(t, c.code)
			if got := NeedsRepair(); got != c.want {
				t.Errorf("NeedsRepair = %v, want %v", got, c.want)
			}
			if (len(*calls) > 0) != c.calls {
				t.Errorf("iptables calls %q, want any: %v", *calls, c.calls)
			}
			want := "iptables -C INPUT -m comment --comment infrafence -j INFRAFENCE"
			if len(*calls) > 0 && (*calls)[0] != want {
				t.Errorf("checked %q, want %q", (*calls)[0], want)
			}
		})
	}
}
