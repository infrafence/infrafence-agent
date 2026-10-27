package scanner

import (
	"errors"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/infrafence/infrafence-agent/internal/sshdconfig"
)

type mapFS map[string]string

func (m mapFS) ReadFile(p string) ([]byte, error) {
	if s, ok := m[p]; ok {
		return []byte(s), nil
	}
	return nil, errors.New("not found")
}

func (m mapFS) Glob(pattern string) ([]string, error) {
	var out []string
	for p := range m {
		if ok, _ := filepath.Match(pattern, p); ok {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out, nil
}

func withSSH(t *testing.T, dump string, fs mapFS) {
	t.Helper()
	oldDump, oldFS := sshdDump, sshFS
	sshdDump = func() string { return dump }
	sshFS = fs
	t.Cleanup(func() { sshdDump, sshFS = oldDump, oldFS })
}

func sshFinding(t *testing.T, id string) Finding {
	t.Helper()
	for _, f := range checkSSHConfig() {
		if f.CheckID == id {
			return f
		}
	}
	t.Fatalf("no %s finding", id)
	return Finding{}
}

// A fresh Ubuntu 26.04 VPS: sshd_config says no, the cloud-init drop-in
// (read first) says yes, and yes is what sshd uses.
var cloudInit = mapFS{
	sshdconfig.MainFile:                         "Include /etc/ssh/sshd_config.d/*.conf\nKbdInteractiveAuthentication no\nPasswordAuthentication no\nX11Forwarding yes\n",
	"/etc/ssh/sshd_config.d/50-cloud-init.conf": "PasswordAuthentication yes\n",
}

func TestSSHPasswordAuthFromCloudInitDropIn(t *testing.T) {
	for name, dump := range map[string]string{
		"sshd -T":     "port 22\npermitrootlogin without-password\npasswordauthentication yes\nx11forwarding yes\nmaxauthtries 6\n",
		"files alone": "", // sshd -T cannot run (socket activation, no /run/sshd)
	} {
		t.Run(name, func(t *testing.T) {
			withSSH(t, dump, cloudInit)
			f := sshFinding(t, "SSH_PASSWORD_AUTH")
			if f.Passed || f.Details["value"] != "yes" {
				t.Fatalf("passed=%v details=%v", f.Passed, f.Details)
			}
			if f.Details["source"] != "/etc/ssh/sshd_config.d/50-cloud-init.conf:1" ||
				!strings.Contains(f.Description, "50-cloud-init.conf:1") {
				t.Fatalf("source not named: %q %v", f.Description, f.Details)
			}
			if !strings.Contains(f.Recommendation, "/etc/ssh/sshd_config.d/50-cloud-init.conf (line 1)") ||
				!strings.Contains(f.Recommendation, "wins over sshd_config") {
				t.Fatalf("recommendation: %q", f.Recommendation)
			}
			// Unset everywhere: sshd's default, said so.
			r := sshFinding(t, "SSH_ROOT_LOGIN")
			if !r.Passed || r.Details["value"] != map[string]string{"sshd -T": "without-password", "files alone": "prohibit-password"}[name] ||
				!strings.Contains(r.Description, "sshd's default") || r.Details["source"] != "" {
				t.Fatalf("root login: %+v", r)
			}
			x := sshFinding(t, "SSH_X11_FORWARDING")
			if x.Passed || x.Details["source"] != sshdconfig.MainFile+":4" {
				t.Fatalf("x11: %+v", x)
			}
		})
	}
}

// When sshd -T disagrees with the files (a Match default, a value the
// parser cannot see), no file is named.
func TestSSHSourceOnlyWhenFilesAgree(t *testing.T) {
	withSSH(t, "passwordauthentication no\n", cloudInit)
	f := sshFinding(t, "SSH_PASSWORD_AUTH")
	if !f.Passed || f.Details["source"] != "" || strings.Contains(f.Description, "set in") {
		t.Fatalf("%+v", f)
	}
}

func TestSSHConfigUnreadable(t *testing.T) {
	withSSH(t, "", mapFS{})
	if f := checkSSHConfig(); len(f) != 1 || f[0].CheckID != "SSH_CONFIG_READ" {
		t.Fatalf("%+v", f)
	}
}
