//go:build integration

package remediation_test

import (
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/infrafence/infrafence-agent/internal/remediation"
	"github.com/infrafence/infrafence-agent/internal/scanner"
)

// Runs against a real Debian/Ubuntu host with sshd, nginx (:80) and Apache
// (:8080) running — see scripts/remediation-integration.sh. Never run it on a
// machine you care about.

var safe = remediation.Policy{ConfigChangesSafe: true}

func sshdT(t *testing.T) string {
	out, err := exec.Command("sshd", "-T").CombinedOutput()
	if err != nil {
		t.Fatalf("sshd -T: %v %s", err, out)
	}
	return string(out)
}

func serverHeader(t *testing.T, url string) string {
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	resp.Body.Close()
	return resp.Header.Get("Server")
}

func checkPassed(id string) (bool, bool) {
	for _, f := range scanner.Run() {
		if f.CheckID == id {
			return f.Passed, true
		}
	}
	return false, false
}

func TestRealHost(t *testing.T) {
	if os.Getenv("REMEDIATION_INTEGRATION") != "1" {
		t.Skip("set REMEDIATION_INTEGRATION=1 inside the throwaway container")
	}
	mainSSH, _ := os.ReadFile("/etc/ssh/sshd_config")

	// Debian ships "X11Forwarding yes" in the main file; the drop-in must win.
	if !strings.Contains(sshdT(t), "x11forwarding yes") {
		t.Fatal("precondition: x11forwarding should start as yes")
	}
	if p, ok := checkPassed("SSH_X11_FORWARDING"); !ok || p {
		t.Fatalf("scanner should report X11 forwarding: passed=%v found=%v", p, ok)
	}
	for _, id := range []string{"SSH_X11_FORWARDING", "SSH_MAX_AUTH_TRIES", "WS_SERVER_TOKENS", "WS_SERVER_TOKENS_APACHE", "WS_SERVER_SIGNATURE", "WS_TRACE_METHOD"} {
		msg, err := remediation.Apply(remediation.System, id, safe)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		t.Logf("%s: %s", id, msg)
	}
	dump := sshdT(t)
	if !strings.Contains(dump, "x11forwarding no") || !strings.Contains(dump, "maxauthtries 4") {
		t.Fatalf("sshd -T after fix:\n%s", dump)
	}
	if got, _ := os.ReadFile("/etc/ssh/sshd_config"); string(got) != string(mainSSH) {
		t.Fatal("main sshd_config was modified")
	}
	if h := serverHeader(t, "http://127.0.0.1:80/"); h != "nginx" {
		t.Fatalf("nginx Server header = %q", h)
	}
	if h := serverHeader(t, "http://127.0.0.1:8080/"); h != "Apache" {
		t.Fatalf("Apache Server header = %q", h)
	}
	for _, id := range []string{"SSH_X11_FORWARDING", "SSH_MAX_AUTH_TRIES", "WS_SERVER_TOKENS_APACHE", "WS_SERVER_SIGNATURE", "WS_TRACE_METHOD"} {
		if p, ok := checkPassed(id); !ok || !p {
			t.Errorf("scanner still reports %s (found=%v)", id, ok)
		}
	}

	// A fix that would break the config is rolled back and nothing reloads
	// into a broken state: put a conflicting directive in nginx.conf.
	os.WriteFile("/etc/nginx/conf.d/00-conflict.conf", []byte("server_tokens on;\n"), 0o644)
	remediation.Revert(remediation.System, "WS_SERVER_TOKENS")
	if _, err := remediation.Apply(remediation.System, "WS_SERVER_TOKENS", safe); err == nil {
		t.Fatal("duplicate server_tokens should be refused")
	} else {
		t.Logf("refused as expected: %v", err)
	}
	if _, err := os.Stat(remediation.NginxDropIn); err == nil {
		t.Fatal("refused fix left its file behind")
	}
	os.Remove("/etc/nginx/conf.d/00-conflict.conf")
	if out, err := exec.Command("nginx", "-t").CombinedOutput(); err != nil {
		t.Fatalf("nginx config broken after rollback: %s", out)
	}

	// Undo everything, services still answer.
	removed := remediation.RemoveAll(remediation.System)
	t.Logf("removed: %v", removed)
	if !strings.Contains(sshdT(t), "x11forwarding yes") {
		t.Fatal("sshd not back to its own settings")
	}
	if h := serverHeader(t, "http://127.0.0.1:8080/"); h == "Apache" {
		t.Fatalf("Apache still has ServerTokens Prod after removal: %q", h)
	}
	serverHeader(t, "http://127.0.0.1:80/")
}
