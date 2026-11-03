package main

import (
	"bytes"
	"context"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/loginhistory"
)

func withLoginStore(t *testing.T) *bytes.Buffer {
	t.Helper()
	old, oldState := sshLoginStore, fwStatePath
	sshLoginStore = loginhistory.NewStore(filepath.Join(t.TempDir(), "ssh-logins.json"))
	fwStatePath = filepath.Join(t.TempDir(), "firewall-state.json")
	memoMu.Lock()
	oldMemo := sshLogins
	sshLogins = map[string]int64{}
	memoMu.Unlock()
	guardLogMu.Lock()
	guardLogLast = map[string]time.Time{}
	guardLogMu.Unlock()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() {
		sshLoginStore, fwStatePath = old, oldState
		memoMu.Lock()
		sshLogins = oldMemo
		memoMu.Unlock()
		log.SetOutput(os.Stderr)
	})
	return &buf
}

func TestLoginGuard(t *testing.T) {
	logs := withLoginStore(t)
	when := time.Now().Add(-72 * time.Hour).Truncate(time.Second)
	sshLoginStore.Apply(loginhistory.Result{Logins: []loginhistory.Login{
		{IP: "198.51.100.7", User: "root", Time: when},
	}}, time.Now())
	noteLoginLine("Nov  3 10:00:00 web1 sshd[1]: Accepted password for ops from 203.0.113.44 port 1 ssh2")

	if !guarded("198.51.100.7", "banning") || !guarded("203.0.113.44", "banning") || guarded("203.0.113.8", "banning") {
		t.Fatal("guard decisions")
	}
	if guardReason("::ffff:198.51.100.7") != "ssh_login" || guardReason("203.0.113.8") != "" {
		t.Error("guardReason")
	}
	want := "[guard] not banning 198.51.100.7: SSH login on " + when.UTC().Format("2006-01-02 15:04 UTC")
	if !strings.Contains(logs.String(), want) {
		t.Errorf("log %q misses %q", logs.String(), want)
	}
	// Once an hour per address.
	guarded("198.51.100.7", "banning")
	if n := strings.Count(logs.String(), "not banning 198.51.100.7"); n != 1 {
		t.Errorf("logged %d times", n)
	}

	bans := guardBans([]api.Ban{{ID: 1, IPAddress: "198.51.100.7"}, {ID: 0, IPAddress: "203.0.113.8"}, {ID: 2, IPAddress: "203.0.113.44"}})
	if len(bans) != 1 || bans[0].IPAddress != "203.0.113.8" {
		t.Errorf("dashboard bans kept: %+v", bans)
	}
	if !strings.Contains(logs.String(), "[guard] not applying the dashboard's ban of 203.0.113.44") {
		t.Errorf("log: %s", logs.String())
	}
	// The egress checks read the history too.
	if !fwSSHLoginSeen("198.51.100.7") {
		t.Error("egress check misses the imported login")
	}
	if ips := sshLoginExempt(); strings.Join(ips, ",") != "198.51.100.7,203.0.113.44" {
		t.Errorf("exempt: %v", ips)
	}
}

// A session event (session tracker) is a live login.
func TestLoginGuardSessionEvent(t *testing.T) {
	withLoginStore(t)
	noteEgressEvent(api.EventRequest{Type: "system_audit", Details: map[string]string{"operation": "ssh_login", "ip": "192.0.2.77", "user": "deploy"}})
	e := sshLoginStore.Entries(0)
	if len(e) != 1 || e[0].IP != "192.0.2.77" || !e[0].Live || e[0].Imported || e[0].Users[0] != "deploy" {
		t.Errorf("entries %+v", e)
	}
}

func TestSSHLoginsPayload(t *testing.T) {
	withLoginStore(t)
	now := time.Now()
	var logins []loginhistory.Login
	for i := 0; i < sshLoginReportMax+20; i++ {
		ip := "198.18." + strconv.Itoa(i/250) + "." + strconv.Itoa(i%250+1)
		logins = append(logins, loginhistory.Login{IP: ip, User: "u", Time: now.Add(-time.Duration(i) * time.Minute)})
	}
	sshLoginStore.Apply(loginhistory.Result{Logins: logins}, now)
	p := sshLoginsPayload()
	if len(p.Logins) != sshLoginReportMax || p.Total != sshLoginReportMax+20 || p.Logins[0].IP != "198.18.0.1" ||
		!p.Logins[0].Imported || p.Logins[0].Live || p.ScannedAt == "" {
		t.Errorf("payload: %d logins, total %d, first %+v", len(p.Logins), p.Total, p.Logins[0])
	}
}

// The startup scan fills the store and saves it; the daily scan does not
// count a login twice.
func TestScanSSHLogins(t *testing.T) {
	logs := withLoginStore(t)
	old := sshLoginScan
	t.Cleanup(func() { sshLoginScan = old })
	sshLoginScan = func(_ context.Context, now time.Time) loginhistory.Result {
		return loginhistory.Result{Logins: []loginhistory.Login{{IP: "198.51.100.9", User: "root", Time: now.Add(-time.Hour), Source: "auth_log"}},
			Sources: []string{"auth_log"}, Files: 2, Bytes: 4096}
	}
	scanSSHLogins()
	scanSSHLogins()
	e := sshLoginStore.Entries(0)
	if len(e) != 1 || e[0].Count != 1 || sshLoginStore.ScannedAt().IsZero() {
		t.Errorf("entries %+v", e)
	}
	if !strings.Contains(logs.String(), "1 address(es) with an SSH login in the last 30 days, never banned") {
		t.Errorf("log: %s", logs.String())
	}
}
