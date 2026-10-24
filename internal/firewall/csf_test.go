package firewall

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// /proc/locks as a container showed it while "csf -r" ran: csf.lock is
// 00:272:12623540 (stat: device 0x200072), held by pid 9437.
const csfLocks = `1: FLOCK  ADVISORY  WRITE 9437 00:272:12623540 0 EOF
2: FLOCK  ADVISORY  WRITE 9437 00:272:12623541 0 EOF
3: POSIX  ADVISORY  WRITE 812 fd:01:12623540 0 EOF
`

func TestLockHolder(t *testing.T) {
	for _, c := range []struct {
		name      string
		locks     string
		dev, ino  uint64
		inodeOnly bool
		pid       int
		held      bool
	}{
		{"csf restarting", csfLocks, 0x200072, 12623540, false, 9437, true},
		{"waiting for it counts", "1: FLOCK  ADVISORY  WRITE 9437 00:272:1 0 EOF\n1: -> FLOCK  ADVISORY  WRITE 9500 00:272:99 0 EOF\n", 0x200072, 99, false, 9500, true},
		{"same inode, other device", csfLocks, 0x803, 12623541, false, 0, false},
		{"same inode, other device, btrfs/overlayfs", csfLocks, 0x803, 12623541, true, 9437, true},
		{"other inode", csfLocks, 0x200072, 1262354, false, 0, false},
		{"inode only as a suffix of digits", csfLocks, 0x200072, 3540, true, 0, false},
		{"pid or offset equal to the inode", "1: FLOCK  ADVISORY  WRITE 7 00:2d:9 7 EOF\n", 0x2d, 7, true, 0, false},
		{"large device numbers", "1: FLOCK  ADVISORY  WRITE 1 103:1f4:7 0 EOF\n", 0x1103f4, 7, false, 1, true},
		{"no locks", "", 0x200072, 12623540, false, 0, false},
	} {
		pid, held := lockHolder(c.locks, c.dev, c.ino, c.inodeOnly)
		if pid != c.pid || held != c.held {
			t.Errorf("%s: lockHolder = %d, %v; want %d, %v", c.name, pid, held, c.pid, c.held)
		}
	}
}

// withCSF points CSFLockHolder at files of the test's: csf.conf (created
// when installed) and the lock file (not created).
func withCSF(t *testing.T, installed bool) string {
	t.Helper()
	dir := t.TempDir()
	oldConf, oldFile, oldLocks := csfConfFile, csfLockFile, procLocks
	csfConfFile, csfLockFile = filepath.Join(dir, "csf.conf"), filepath.Join(dir, "csf.lock")
	t.Cleanup(func() { csfConfFile, csfLockFile, procLocks = oldConf, oldFile, oldLocks })
	if installed {
		if err := os.WriteFile(csfConfFile, []byte("TESTING = \"0\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return csfLockFile
}

func TestCSFLockHolderWithoutLockFile(t *testing.T) {
	withCSF(t, true)
	if _, held := CSFLockHolder(); held {
		t.Fatal("held without a lock file")
	}
}

// flockFile holds an exclusive flock on path until the test ends or the
// returned func is called.
func flockFile(t *testing.T, path string) func() {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
}

// The kernel's own /proc/locks: held only while the file is flocked, the
// way csf locks it, and only where CSF is installed.
func TestCSFLockHolderReadsKernelLocks(t *testing.T) {
	if _, err := os.Stat("/proc/locks"); err != nil {
		t.Skip("no /proc/locks")
	}
	path := withCSF(t, true)
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, held := CSFLockHolder(); held {
		t.Fatal("held while nobody holds the lock")
	}
	unlock := flockFile(t, path)
	pid, held := CSFLockHolder()
	if !held || pid != os.Getpid() {
		locks, _ := os.ReadFile("/proc/locks")
		t.Fatalf("lock not seen (pid %d, held %v); /proc/locks:\n%s", pid, held, locks)
	}
	unlock()
	if _, held := CSFLockHolder(); held {
		t.Fatal("still held after the unlock")
	}
}

// Without csf.conf the lock file is not looked at: no CSF, no wait.
func TestCSFLockHolderOnlyWithCSF(t *testing.T) {
	if _, err := os.Stat("/proc/locks"); err != nil {
		t.Skip("no /proc/locks")
	}
	path := withCSF(t, false)
	flockFile(t, path)
	if _, held := CSFLockHolder(); held {
		t.Fatal("waiting for a csf lock on a host without CSF")
	}
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

const ourJump = "-A INPUT -m comment --comment infrafence -j INFRAFENCE"

func TestNeedsRepair(t *testing.T) {
	for _, c := range []struct {
		name                  string
		initialized, disabled bool
		input                 []string // iptables -S INPUT
		err                   error
		want, wantErr, calls  bool
	}{
		{"jump first", true, false, []string{ourJump, "-A INPUT -j LOCALINPUT", "-A INPUT -i lo -j ACCEPT"}, nil, false, false, true},
		{"jump after DROP-only rules", true, false, []string{"-A INPUT -j f2b-sshd", "-A INPUT -s 192.0.2.9/32 -j DROP", ourJump, "-A INPUT -j LOCALINPUT"}, nil, false, false, true},
		{"jump gone (csf -r)", true, false, []string{"-A INPUT -j LOCALINPUT", "-A INPUT -i lo -j ACCEPT"}, nil, true, false, true},
		{"jump behind an ACCEPT", true, false, []string{"-A INPUT -i lo -j ACCEPT", ourJump}, nil, true, false, true},
		{"jump behind CSF's chain (it can ACCEPT)", true, false, []string{"-A INPUT -j LOCALINPUT", ourJump}, nil, true, false, true},
		{"iptables fails or times out", true, false, nil, errors.New("exit status 4"), false, true, true},
		{"before the first Ensure", false, false, nil, nil, false, false, false},
		{"protection switched off", true, true, nil, nil, false, false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			withFwFlags(t, c.initialized, c.disabled)
			var calls []string
			old := run
			run = func(name string, args ...string) (string, error) {
				calls = append(calls, name+" "+strings.Join(args, " "))
				return strings.Join(append([]string{"-P INPUT DROP"}, c.input...), "\n"), c.err
			}
			t.Cleanup(func() { run = old })
			got, err := NeedsRepair()
			if got != c.want || (err != nil) != c.wantErr {
				t.Errorf("NeedsRepair = %v, %v; want %v, error %v", got, err, c.want, c.wantErr)
			}
			if (len(calls) > 0) != c.calls {
				t.Errorf("iptables calls %q, want any: %v", calls, c.calls)
			}
			if len(calls) > 0 && calls[0] != "iptables -S INPUT" {
				t.Errorf("ran %q", calls[0])
			}
		})
	}
}
