package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/infrafence/infrafence-agent/internal/loginhistory"
)

func TestSSHCounter(t *testing.T) {
	lines := []string{
		// Password server: one Invalid user line, then its Failed line.
		"2026-11-13T09:00:00+0000 h sshd[100]: Invalid user admin from 203.0.113.5 port 4000",
		"2026-11-13T09:00:01+0000 h sshd[100]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.5",
		"2026-11-13T09:00:02+0000 h sshd[100]: Failed password for invalid user admin from 203.0.113.5 port 4000 ssh2",
		"2026-11-13T09:00:04+0000 h sshd[100]: Failed password for invalid user admin from 203.0.113.5 port 4000 ssh2",
		"2026-11-13T09:00:05+0000 h sshd[101]: Failed password for root from 203.0.113.6 port 4001 ssh2",
		// Key-only server: refused before any password.
		"2026-11-13T09:01:00+0000 h sshd[200]: Invalid user oracle from 203.0.113.7 port 5000",
		"2026-11-13T09:01:00+0000 h sshd[200]: Connection closed by invalid user oracle 203.0.113.7 port 5000 [preauth]",
		// A port scanner only (preauth): not a login attempt.
		"2026-11-13T09:02:00+0000 h sshd[300]: Did not receive identification string from 203.0.113.8 port 6000",
		// Not sshd's message.
		"2026-11-13T09:03:00+0000 h sudo[400]: root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/ls",
		"2026-11-13T09:04:00+0000 h sshd[500]: Accepted publickey for root from 198.51.100.1 port 7000 ssh2",
	}
	lines = append(lines,
		// The admin mistypes a password, then logs in: not an attacker.
		"2026-11-13T09:05:00+0000 h sshd[600]: Failed password for root from 198.51.100.50 port 7001 ssh2",
		"2026-11-13T09:05:09+0000 h sshd[601]: Accepted password for root from 198.51.100.50 port 7002 ssh2")
	s := newSSHCounter()
	for _, l := range lines {
		s.line(l)
	}
	s.finish()
	if s.total != 4 {
		t.Errorf("failed logins %d, want 4", s.total)
	}
	if len(s.ips) != 3 {
		t.Errorf("unique addresses %d, want 3: %v", len(s.ips), s.ips)
	}
	if !reflect.DeepEqual(s.byIP, map[string]int{"203.0.113.5": 2, "203.0.113.6": 1, "203.0.113.7": 1}) {
		t.Errorf("by address %v", s.byIP)
	}
}

func TestScanLinesWindowAndBounds(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "auth.log")
	var b strings.Builder
	b.WriteString("Nov 11 09:00:00 h sshd[1]: Failed password for root from 203.0.113.1 port 1 ssh2\n") // older than 24 h
	for i := 0; i < 50; i++ {
		b.WriteString("Nov 13 09:00:00 h sshd[2]: Failed password for root from 203.0.113.2 port 1 ssh2\n")
	}
	must(t, os.WriteFile(p, []byte(b.String()), 0o600))
	now := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	ref := now

	s := newSSHCounter()
	rc, _, err := openTail(p, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	scanLines(context.Background(), rc, now.Add(-Window), ref, loginhistory.LineTime, s.line)
	_ = rc.Close()
	if s.total != 50 || s.byIP["203.0.113.1"] != 0 {
		t.Errorf("window: %d attempts %v", s.total, s.byIP)
	}

	// Only the newest bytes are read, from a line boundary.
	line := len("Nov 13 09:00:00 h sshd[2]: Failed password for root from 203.0.113.2 port 1 ssh2\n")
	s = newSSHCounter()
	rc, _, _ = openTail(p, int64(10*line+5))
	scanLines(context.Background(), rc, now.Add(-Window), ref, loginhistory.LineTime, s.line)
	_ = rc.Close()
	if s.total != 10 {
		t.Errorf("tail read %d lines, want 10", s.total)
	}
	// A line too long to count is skipped, the rest is still read.
	long := filepath.Join(dir, "long.log")
	must(t, os.WriteFile(long, []byte("Nov 13 09:00:00 h sshd[3]: Invalid user "+strings.Repeat("A", 200<<10)+" from 203.0.113.3 port 1\n"+
		"Nov 13 09:00:01 h sshd[4]: Failed password for root from 203.0.113.4 port 1 ssh2\n"), 0o600))
	s = newSSHCounter()
	rc, _, _ = openTail(long, 1<<20)
	scanLines(context.Background(), rc, now.Add(-Window), ref, loginhistory.LineTime, s.line)
	_ = rc.Close()
	if s.total != 1 || s.byIP["203.0.113.4"] != 1 {
		t.Errorf("after a long line: %d %v", s.total, s.byIP)
	}
	// A FIFO with no writer is refused at once, never waited on.
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err == nil {
		done := make(chan error, 1)
		go func() { _, _, err := openTail(fifo, 100); done <- err }()
		select {
		case err := <-done:
			if err == nil {
				t.Errorf("a FIFO was opened")
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("opening a FIFO blocked")
		}
	}
	// A directory is never opened for reading.
	if _, _, err := openTail(dir, 100); err == nil {
		t.Errorf("a directory was opened")
	}
}

func TestTopIPs(t *testing.T) {
	ssh, web := newCounter(), newCounter()
	for i := 0; i < 5; i++ {
		ssh.add("203.0.113.1")
	}
	web.add("203.0.113.2")
	web.add("203.0.113.2")
	ssh.byIP["203.0.113.9"] = 0 // seen only in a PAM line
	got := topIPs(ssh, web)
	want := []TopIP{{IP: "203.0.113.1", Count: 5, Kind: "ssh"}, {IP: "203.0.113.2", Count: 2, Kind: "web"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%+v", got)
	}
	if got := topIPs(newCounter(), newCounter()); got == nil || len(got) != 0 {
		t.Errorf("empty top ips must be [], got %#v", got)
	}
}

func TestPackageOutputs(t *testing.T) {
	apt := `Reading package lists...
Inst libssl3t64 [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Inst tzdata [2024a-3ubuntu1.1] (2025b-0ubuntu0.24.04 Ubuntu:24.04/noble-updates [all])
Inst openssl [3.0.11-1~deb12u1] (3.0.11-1~deb12u2 Debian-Security:12/stable-security [arm64])
Conf libssl3t64 (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
`
	if total, sec := aptCounts(apt); total != 3 || sec != 2 {
		t.Errorf("apt: %d total %d security", total, sec)
	}
	dnf := `
openssl.x86_64                1:3.0.7-28.el9_4          baseos
kernel.x86_64                 5.14.0-503.el9            baseos
Obsoleting Packages
grub2-tools.x86_64            1:2.06-80.el9             baseos
`
	if n := rpmUpdateLines(dnf); n != 2 {
		t.Errorf("dnf check-update: %d", n)
	}
	dnf4 := `RLSA-2024:1234 Important/Sec. openssl-1:3.0.7-28.el9_4.x86_64
RLSA-2024:1234 Important/Sec. openssl-libs-1:3.0.7-28.el9_4.x86_64
RLBA-2024:1000 bugfix          tzdata-2024b-1.el9.noarch
RLSA-2024:2000 Moderate/Sec.  openssl-1:3.0.7-28.el9_4.x86_64
`
	if got := rpmName("openssl-libs-1:3.0.7-28.el9_4.x86_64"); got != "openssl-libs" {
		t.Errorf("rpm name %q", got)
	}
	dnf4 += "RLSA-2023:9999 Important/Sec. openssl-1:3.0.7-20.el9.x86_64\n" // an older fix of the same package
	if n := securityLines(dnf4); n != 2 {
		t.Errorf("dnf4 security: %d", n)
	}
	dnf5 := `Name             Type     Severity  Package                         Issued
FEDORA-2025-1    security Important openssl-1:3.2.4-1.fc42.x86_64   2025-05-01 00:00:00
FEDORA-2025-2    bugfix   None      tzdata-2025b-1.fc42.noarch      2025-05-01 00:00:00
`
	if n := securityLines(dnf5); n != 1 {
		t.Errorf("dnf5 security: %d", n)
	}
}

func TestFirewallParsers(t *testing.T) {
	for out, want := range map[string]bool{
		"-P INPUT ACCEPT\n":                       false,
		"-P INPUT DROP\n":                         true,
		"-P INPUT ACCEPT\n-A INPUT -j INFRAFENCE": true,
		"": false,
	} {
		if got := iptablesFilters(out); got != want {
			t.Errorf("iptables %q: %v", out, got)
		}
	}
	empty := "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n\t}\n}\n"
	rule := "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n\t\ttcp dport 22 accept\n\t}\n}\n"
	drop := "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t}\n}\n"
	fwd := "table inet filter {\n\tchain forward {\n\t\ttype filter hook forward priority filter; policy accept;\n\t\tct state established accept\n\t}\n}\n"
	for out, want := range map[string]bool{empty: false, rule: true, drop: true, fwd: false, "": false} {
		if got := nftFilters(out); got != want {
			t.Errorf("nft %q: %v", out, got)
		}
	}
}

func TestWorldWritable(t *testing.T) {
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "ok"), nil, 0o644))
	must(t, os.WriteFile(filepath.Join(dir, "bad"), nil, 0o644))
	must(t, os.Chmod(filepath.Join(dir, "bad"), 0o666))
	must(t, os.Mkdir(filepath.Join(dir, "tmp"), 0o755))
	must(t, os.Chmod(filepath.Join(dir, "tmp"), os.ModeSticky|0o777)) // sticky: fine
	must(t, os.Mkdir(filepath.Join(dir, "open"), 0o755))
	must(t, os.Chmod(filepath.Join(dir, "open"), 0o777))
	must(t, os.Symlink("/etc/passwd", filepath.Join(dir, "link"))) // a symlink is always 0777
	found, scanned, complete := worldWritable(context.Background(), []string{dir}, 1000)
	want := []string{filepath.Join(dir, "bad"), filepath.Join(dir, "open")}
	if !reflect.DeepEqual(found, want) || !complete || scanned < 5 {
		t.Errorf("found %v scanned %d complete %v", found, scanned, complete)
	}
	if _, _, complete := worldWritable(context.Background(), []string{dir}, 2); complete {
		t.Errorf("a bounded walk says it is complete")
	}
}

func TestWebServer(t *testing.T) {
	if got := webServer(nil, nil); got != "none" {
		t.Errorf("%q", got)
	}
}

// ── upload ──

func TestUpload(t *testing.T) {
	token := strings.Repeat("aB3", 12)
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "bad", 400)
			return
		}
		got, _ = io.ReadAll(r.Body)
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(UploadResult{Token: token, URL: "http://" + r.Host + "/tools/server-audit/r#" + token, ExpiresAt: "2026-11-21T10:00:00Z"})
	}))
	defer srv.Close()
	body, _ := json.Marshal(validReport())
	res, err := Upload(context.Background(), srv.URL+"/api/v1/audit/report", body, "1.0.44")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) || res.Token != token || !strings.HasSuffix(res.URL, "#"+token) {
		t.Errorf("result %+v", res)
	}
}

func TestUploadRefusals(t *testing.T) {
	token := strings.Repeat("x", 40)
	for name, h := range map[string]http.HandlerFunc{
		"rate limit": func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(429) },
		"redirect": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://evil.example/", http.StatusFound)
		},
		"other host": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(UploadResult{Token: token, URL: "https://evil.example/r#" + token})
		},
		"short token": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(UploadResult{Token: "abc", URL: "http://" + r.Host + "/r#abc"})
		},
		"token in path": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(UploadResult{Token: token, URL: "http://" + r.Host + "/r/" + token})
		},
	} {
		srv := httptest.NewServer(h)
		_, err := Upload(context.Background(), srv.URL, []byte("{}"), "t")
		srv.Close()
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, u := range []string{"http://infrafence.com/api", "ftp://x/", "https://user:pw@infrafence.com/", "https://infrafence.com/#frag", "not a url"} {
		if _, err := CheckUploadURL(u); err == nil {
			t.Errorf("%s: accepted", u)
		}
	}
	for _, u := range []string{DefaultUploadURL, "http://127.0.0.1:8080/api/v1/audit/report", "http://localhost/x"} {
		if _, err := CheckUploadURL(u); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	if _, err := Upload(context.Background(), DefaultUploadURL, make([]byte, maxReportBytes+1), "t"); err == nil {
		t.Errorf("an oversized body was sent")
	}
}

func TestSummary(t *testing.T) {
	r := validReport()
	r.Checks = append(r.Checks,
		Check{ID: IDOSEOL, Status: StatusPass, Severity: SevCritical, Facts: map[string]string{}},
		Check{ID: IDUsersUID0Extra, Status: StatusFail, Severity: SevCritical, Facts: map[string]string{"count": "1"}})
	var b bytes.Buffer
	WriteSummary(&b, r)
	out := b.String()
	for _, want := range []string{"3412 failed logins from 187 addresses", "220 suspicious requests from 41 addresses",
		"203.0.113.5", "3306 (mysqld)", "1 other checks passed", "security: 12, total: 40, reboot required: yes"} {
		if !strings.Contains(out, want) {
			t.Errorf("summary lacks %q:\n%s", want, out)
		}
	}
	if strings.Index(out, IDUsersUID0Extra) > strings.Index(out, IDSSHPasswordAuth) {
		t.Errorf("not worst first:\n%s", out)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// TestPinPath: after PinPath a bare command name is found only in the
// system directories, never in a directory of the caller's PATH.
func TestPinPath(t *testing.T) {
	dir := t.TempDir()
	planted := filepath.Join(dir, "infrafence-planted-tool")
	must(t, os.WriteFile(planted, []byte("#!/bin/sh\nexit 0\n"), 0o755))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	if _, err := exec.LookPath("infrafence-planted-tool"); err != nil {
		t.Fatalf("setup: %v", err)
	}
	must(t, PinPath())
	if os.Getenv("PATH") != SystemPath {
		t.Fatalf("PATH %q", os.Getenv("PATH"))
	}
	if p, err := exec.LookPath("infrafence-planted-tool"); err == nil {
		t.Errorf("planted program found at %s", p)
	}
	p, err := exec.LookPath("sh")
	if err != nil {
		t.Fatalf("sh: %v", err)
	}
	if d := filepath.Dir(p); !strings.Contains(":"+SystemPath+":", ":"+d+":") {
		t.Errorf("sh resolved to %s, outside %s", p, SystemPath)
	}
}
