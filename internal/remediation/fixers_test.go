package remediation

import (
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"
)

// fakeHost is an in-memory host: files, modes, symlinks and scripted
// command results.
type fakeHost struct {
	files map[string]string
	modes map[string]os.FileMode
	dirs  map[string]bool
	links map[string]string
	bins  map[string]bool
	run   func(name string, args ...string) (string, error)
	calls []string
	// removeErr, when set, makes every Remove fail (a stuck rollback).
	removeErr error
}

func newHost() *fakeHost {
	return &fakeHost{
		files: map[string]string{}, modes: map[string]os.FileMode{},
		dirs: map[string]bool{}, links: map[string]string{}, bins: map[string]bool{},
		run: func(string, ...string) (string, error) { return "", nil },
	}
}

func (h *fakeHost) Run(name string, args ...string) (string, error) {
	h.calls = append(h.calls, strings.TrimSpace(name+" "+strings.Join(args, " ")))
	return h.run(name, args...)
}
func (h *fakeHost) LookPath(n string) (string, error) {
	if h.bins[n] {
		return n, nil
	}
	return "", errors.New("not found")
}
func (h *fakeHost) ReadFile(p string) ([]byte, error) {
	if c, ok := h.files[p]; ok {
		return []byte(c), nil
	}
	return nil, fs.ErrNotExist
}
func (h *fakeHost) WriteFile(p string, d []byte, m os.FileMode) error {
	h.files[p] = string(d)
	h.modes[p] = m
	return nil
}
func (h *fakeHost) Remove(p string) error {
	if h.removeErr != nil {
		return h.removeErr
	}
	if _, ok := h.files[p]; ok {
		delete(h.files, p)
		return nil
	}
	if _, ok := h.links[p]; ok {
		delete(h.links, p)
		return nil
	}
	return fs.ErrNotExist
}
func (h *fakeHost) Stat(p string) (os.FileInfo, error) {
	if _, ok := h.files[p]; ok {
		return fakeInfo{mode: h.modes[p]}, nil
	}
	if h.dirs[p] {
		return fakeInfo{mode: fs.ModeDir | 0o755}, nil
	}
	if _, ok := h.links[p]; ok {
		return fakeInfo{}, nil
	}
	return nil, fs.ErrNotExist
}
func (h *fakeHost) Lstat(p string) (os.FileInfo, error) {
	if _, ok := h.links[p]; ok {
		return fakeInfo{}, nil
	}
	return h.Stat(p)
}
func (h *fakeHost) Chmod(p string, m os.FileMode) error { h.modes[p] = m; return nil }
func (h *fakeHost) Symlink(o, n string) error           { h.links[n] = o; return nil }
func (h *fakeHost) MkdirAll(p string, m os.FileMode) error {
	h.dirs[p] = true
	return nil
}

type fakeInfo struct{ mode os.FileMode }

func (f fakeInfo) Name() string       { return "" }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() os.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeInfo) Sys() any           { return nil }

var safe = Policy{ConfigChangesSafe: true}

func sshHost() *fakeHost {
	h := newHost()
	h.bins["sshd"] = true
	h.files["/etc/ssh/sshd_config"] = "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\n"
	return h
}

func TestSSHFixWritesDropInAndReloads(t *testing.T) {
	h := sshHost()
	h.run = func(name string, args ...string) (string, error) {
		if name == "sshd" && args[0] == "-T" {
			return "port 22\nx11forwarding no\n", nil
		}
		return "", nil
	}
	msg, err := Apply(h, "SSH_X11_FORWARDING", safe)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !strings.Contains(h.files[SSHDropIn], "X11Forwarding no") {
		t.Fatalf("drop-in = %q", h.files[SSHDropIn])
	}
	if h.files["/etc/ssh/sshd_config"] != "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\n" {
		t.Fatal("main sshd_config must never be edited")
	}
	if !contains(h.calls, "systemctl reload ssh") || contains(h.calls, "systemctl restart ssh") {
		t.Fatalf("expected a reload, never a restart: %v", h.calls)
	}
	if !strings.Contains(msg, "reloaded") {
		t.Fatalf("msg = %q", msg)
	}
}

func TestSSHFixRolledBackWhenConfigTestFails(t *testing.T) {
	h := sshHost()
	h.files[SSHDropIn] = header + "MaxAuthTries 4\n"
	before := h.files[SSHDropIn]
	h.run = func(name string, args ...string) (string, error) {
		if name == "sshd" && args[0] == "-t" {
			return "bad configuration option", errors.New("exit 255")
		}
		return "", nil
	}
	if _, err := Apply(h, "SSH_X11_FORWARDING", safe); err == nil {
		t.Fatal("expected an error")
	}
	if h.files[SSHDropIn] != before {
		t.Fatalf("drop-in not restored: %q", h.files[SSHDropIn])
	}
	if contains(h.calls, "systemctl reload ssh") {
		t.Fatal("must not reload after a failed config test")
	}
}

func TestFailedRollbackIsReported(t *testing.T) {
	h := sshHost()
	h.run = func(name string, args ...string) (string, error) {
		if name == "sshd" && args[0] == "-t" {
			h.removeErr = errors.New("read-only file system")
			return "bad configuration option", errors.New("exit 255")
		}
		return "", nil
	}
	_, err := Apply(h, "SSH_X11_FORWARDING", safe)
	if err == nil || !strings.Contains(err.Error(), "FAILED (read-only file system)") || strings.Contains(err.Error(), "change undone") {
		t.Fatalf("err = %v", err)
	}
}

func TestSSHFixRolledBackWhenOverridden(t *testing.T) {
	h := sshHost()
	h.run = func(name string, args ...string) (string, error) {
		if name == "sshd" && args[0] == "-T" {
			return "x11forwarding yes\n", nil // a Match block or earlier file wins
		}
		return "", nil
	}
	_, err := Apply(h, "SSH_X11_FORWARDING", safe)
	if err == nil || !strings.Contains(err.Error(), "overrides") {
		t.Fatalf("err = %v", err)
	}
	if _, ok := h.files[SSHDropIn]; ok {
		t.Fatal("new drop-in must be removed on rollback")
	}
}

func TestSSHWithoutIncludeIsUnsupported(t *testing.T) {
	h := sshHost()
	h.files["/etc/ssh/sshd_config"] = "PermitRootLogin yes\n"
	_, err := Apply(h, "SSH_MAX_AUTH_TRIES", safe)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v", err)
	}
	if len(h.calls) != 0 {
		t.Fatalf("nothing should run: %v", h.calls)
	}
}

func TestRevertRemovesOnlyThatKey(t *testing.T) {
	h := sshHost()
	h.files[SSHDropIn] = header + "MaxAuthTries 4\nX11Forwarding no\n"
	if _, err := Revert(h, "SSH_X11_FORWARDING"); err != nil {
		t.Fatal(err)
	}
	if got := h.files[SSHDropIn]; strings.Contains(got, "X11Forwarding") || !strings.Contains(got, "MaxAuthTries 4") {
		t.Fatalf("drop-in = %q", got)
	}
	if _, err := Revert(h, "SSH_MAX_AUTH_TRIES"); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.files[SSHDropIn]; ok {
		t.Fatal("empty drop-in should be deleted")
	}
}

func TestLockoutRisksAreNeverAutomatic(t *testing.T) {
	for _, id := range []string{"SSH_ROOT_LOGIN", "SSH_PASSWORD_AUTH", "SSH_DEFAULT_PORT"} {
		ok, reason := Availability(id, safe)
		if ok || reason != ReasonLockoutRisk {
			t.Errorf("%s: ok=%v reason=%q", id, ok, reason)
		}
		if _, err := Apply(sshHost(), id, safe); !errors.Is(err, ErrNotFixable) {
			t.Errorf("%s: Apply err = %v", id, err)
		}
	}
	if ok, reason := Availability("WS_DIRECTORY_LISTING", safe); ok || reason != ReasonSiteRisk {
		t.Errorf("directory listing: ok=%v reason=%q", ok, reason)
	}
	if ok, reason := Availability("PORT_3306", safe); ok || reason != ReasonNoAutomation {
		t.Errorf("unknown check: ok=%v reason=%q", ok, reason)
	}
}

func TestManagedHostOnlyAllowsPermissions(t *testing.T) {
	managed := Policy{ConfigChangesSafe: false}
	if ok, reason := Availability("SSH_X11_FORWARDING", managed); ok || reason != ReasonManaged {
		t.Errorf("ssh on managed host: ok=%v reason=%q", ok, reason)
	}
	if ok, _ := Availability("PERM_SHADOW", managed); !ok {
		t.Error("permission fixes don't touch managed configuration")
	}
}

func TestPermissionsOnlyTightened(t *testing.T) {
	h := newHost()
	h.files["/etc/shadow"] = "x"
	h.modes["/etc/shadow"] = 0o644
	if _, err := Apply(h, "PERM_SHADOW", safe); err != nil {
		t.Fatal(err)
	}
	if h.modes["/etc/shadow"] != 0o640 {
		t.Fatalf("mode = %04o", h.modes["/etc/shadow"])
	}
	// Stricter than required: left alone, never loosened.
	h.modes["/etc/shadow"] = 0o600
	if _, err := Apply(h, "PERM_SHADOW", safe); err != nil {
		t.Fatal(err)
	}
	if h.modes["/etc/shadow"] != 0o600 {
		t.Fatalf("mode loosened to %04o", h.modes["/etc/shadow"])
	}
}

func nginxHost() *fakeHost {
	h := newHost()
	h.bins["nginx"] = true
	h.dirs["/etc/nginx/conf.d"] = true
	return h
}

func TestNginxFix(t *testing.T) {
	h := nginxHost()
	h.run = func(name string, args ...string) (string, error) {
		if name == "nginx" && args[0] == "-T" {
			return "# configuration file " + NginxDropIn + ":\nserver_tokens off;\n", nil
		}
		return "", nil
	}
	if _, err := Apply(h, "WS_SERVER_TOKENS", safe); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.files[NginxDropIn], "server_tokens off;") {
		t.Fatalf("drop-in = %q", h.files[NginxDropIn])
	}
	if !contains(h.calls, "systemctl reload nginx") {
		t.Fatalf("calls = %v", h.calls)
	}
}

func TestNginxDuplicateRolledBack(t *testing.T) {
	h := nginxHost()
	h.run = func(name string, args ...string) (string, error) {
		if name == "nginx" {
			return `nginx: [emerg] "server_tokens" directive is duplicate`, errors.New("exit 1")
		}
		return "", nil
	}
	_, err := Apply(h, "WS_SERVER_TOKENS", safe)
	if err == nil || !strings.Contains(err.Error(), "already set elsewhere") {
		t.Fatalf("err = %v", err)
	}
	if _, ok := h.files[NginxDropIn]; ok {
		t.Fatal("drop-in must be removed")
	}
}

func apacheDebHost() *fakeHost {
	h := newHost()
	h.bins["apache2ctl"] = true
	h.dirs["/etc/apache2/conf-available"] = true
	h.dirs["/etc/apache2/conf-enabled"] = true
	return h
}

func TestApacheFixEnablesConfAndRollsBack(t *testing.T) {
	h := apacheDebHost()
	if _, err := Apply(h, "WS_SERVER_TOKENS_APACHE", safe); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.files[ApacheDebAvail], "ServerTokens Prod") {
		t.Fatalf("conf = %q", h.files[ApacheDebAvail])
	}
	if h.links[ApacheDebLink] != "../conf-available/zz-infrafence-hardening.conf" {
		t.Fatalf("links = %v", h.links)
	}
	if !contains(h.calls, "apache2ctl graceful") {
		t.Fatalf("calls = %v", h.calls)
	}

	// A second fix whose config test fails leaves the first one intact.
	h.run = func(name string, args ...string) (string, error) {
		if len(args) > 0 && args[0] == "configtest" {
			return "Syntax error", errors.New("exit 1")
		}
		return "", nil
	}
	before := h.files[ApacheDebAvail]
	if _, err := Apply(h, "WS_TRACE_METHOD", safe); err == nil {
		t.Fatal("expected error")
	}
	if h.files[ApacheDebAvail] != before || h.links[ApacheDebLink] == "" {
		t.Fatalf("not restored: %q %v", h.files[ApacheDebAvail], h.links)
	}
}

func TestRemoveAll(t *testing.T) {
	h := apacheDebHost()
	h.bins["nginx"] = true
	h.files[SSHDropIn] = header + "MaxAuthTries 4\n"
	h.files[NginxDropIn] = header + "server_tokens off;\n"
	h.files[ApacheDebAvail] = header + "ServerTokens Prod\n"
	h.links[ApacheDebLink] = "../conf-available/zz-infrafence-hardening.conf"
	done, err := RemoveAll(h)
	if err != nil || len(done) != 4 {
		t.Fatalf("removed %v, err %v", done, err)
	}
	if len(h.files) != 0 || len(h.links) != 0 {
		t.Fatalf("left behind: %v %v", h.files, h.links)
	}
}

func TestRemoveAllReportsFailedReload(t *testing.T) {
	h := sshHost()
	h.files[SSHDropIn] = header + "MaxAuthTries 4\n"
	h.run = func(name string, args ...string) (string, error) {
		if name == "systemctl" || name == "service" {
			return "", errors.New("unit not found")
		}
		return "", nil
	}
	done, err := RemoveAll(h)
	if len(done) != 1 || err == nil || !strings.Contains(err.Error(), "reload sshd") {
		t.Fatalf("done %v, err %v", done, err)
	}
	if _, ok := h.files[SSHDropIn]; ok {
		t.Fatal("drop-in must be removed even when the reload fails")
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
