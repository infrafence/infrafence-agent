package main

import (
	"context"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/firewall"
	"github.com/infrafence/infrafence-agent/internal/loginhistory"
)

// The login guard: nothing the agent does by itself locks out the people
// who administer this server.
//
// At startup and once a day the agent reads the successful SSH logins of
// the last 30 days from the logs, the journal and the login records
// (internal/loginhistory); every live login seen afterwards is added. An
// address with an SSH login in the last 30 days is never:
//
//   - banned by a local detector (SSH, web/WAF, mail, database and FTP
//     brute force, port scan, a country seen on an attack): banAndReport;
//   - in a ban the dashboard sends (AutoMode, bans propagated from the
//     organization's other servers, Network shared bans): the ban is not
//     applied here, and a ban already in force is lifted;
//   - in a threat-feed set or a country set (left out of both).
//
// A firewall rule a person adds in the dashboard for that exact address
// (Firewall rules, "block") is still applied: that is a person's explicit
// decision, not an automatic one. The whitelist stays the guarantee for
// logins older than what the logs keep.
//
// Each refusal is logged ("[guard] not banning X: SSH login on <date>"), at
// most once an hour per address. The history is saved in
// /var/lib/infrafence/ssh-logins.json (0600) and sent to the dashboard
// (POST /api/v1/agent/ssh-logins, at most reportMax addresses), marked as
// imported or live; an older dashboard that does not know the endpoint is
// ignored.

var sshLoginPath = "/var/lib/infrafence/ssh-logins.json"

const (
	sshLoginRescan = 24 * time.Hour
	// sshLoginFirstWait: on the first run (no saved history) startup waits
	// this long for the scan before the detectors start; a longer scan
	// goes on in the background.
	sshLoginFirstWait = 20 * time.Second
	sshLoginScanMax   = 10 * time.Minute
	sshLoginReportMax = 500
	// sshLoginReportGap: live logins are sent at most this often.
	sshLoginReportGap = 10 * time.Minute
	guardLogEvery     = time.Hour
)

var (
	sshLoginStore = loginhistory.NewStore(sshLoginPath)
	// sshLoginGen changes whenever an address is added, so the threat-feed
	// and country sets are rebuilt without it.
	sshLoginGen atomic.Int64
	// onSSHLoginsAdded is set by main: rebuild what depends on the list.
	onSSHLoginsAdded atomic.Pointer[func()]
	sshLoginReport   = make(chan struct{}, 1)
	// Replaced in tests.
	sshLoginScan = func(ctx context.Context, now time.Time) loginhistory.Result {
		return loginhistory.Scan(ctx, now, loginhistory.Default())
	}
)

// loadSSHLoginHistory reads the saved history (before the firewall setup,
// so the guard knows the addresses from the first second).
func loadSSHLoginHistory() {
	if sshLoginStore == nil {
		return
	}
	if err := sshLoginStore.Load(); err != nil {
		log.Printf("[ssh-logins] %s is not valid, read again from the logs: %v", sshLoginPath, err)
	}
	if n := len(sshLoginStore.IPs()); n > 0 {
		log.Printf("[ssh-logins] %d address(es) with an SSH login in the last 30 days (saved)", n)
	}
}

// startSSHLoginHistory scans the logs now (waiting for it on the first run),
// then once a day, and sends the history to the dashboard.
func startSSHLoginHistory(client *api.Client) {
	go reportSSHLoginsLoop(client)
	first := sshLoginStore.ScannedAt().IsZero()
	done := make(chan struct{})
	go func() {
		defer close(done)
		if first || time.Since(sshLoginStore.ScannedAt()) >= sshLoginRescan {
			scanSSHLogins()
		}
	}()
	if first {
		select {
		case <-done:
		case <-time.After(sshLoginFirstWait):
			log.Printf("[ssh-logins] reading the logs takes longer than %s: going on in the background", sshLoginFirstWait)
		}
	}
	go func() {
		<-done
		requestSSHLoginReport()
		for {
			wait := sshLoginRescan - time.Since(sshLoginStore.ScannedAt())
			if wait < time.Minute {
				wait = time.Minute
			}
			time.Sleep(wait)
			scanSSHLogins()
			requestSSHLoginReport()
		}
	}()
}

func scanSSHLogins() {
	ctx, cancel := context.WithTimeout(context.Background(), sshLoginScanMax)
	defer cancel()
	start := time.Now()
	r := sshLoginScan(ctx, start)
	added := sshLoginStore.Apply(r, start)
	if err := sshLoginStore.Save(); err != nil {
		log.Printf("[ssh-logins] save %s: %v", sshLoginPath, err)
	}
	log.Printf("[ssh-logins] read %d file(s), %d KiB (%v%s) in %s: %d login(s), %d address(es) with an SSH login in the last 30 days, never banned",
		r.Files, r.Bytes>>10, r.Sources, map[bool]string{true: ", cut at the size limits", false: ""}[r.Truncated],
		time.Since(start).Round(time.Millisecond), len(r.Logins), len(sshLoginStore.IPs()))
	if len(added) > 0 {
		loginsAdded()
	} else {
		liftGuardedBans()
	}
}

// noteLiveLogin records a login seen as it happened (the auth watcher's
// "Accepted" lines, the session tracker's events).
func noteLiveLogin(ip, user string, at time.Time) {
	if sshLoginStore == nil {
		return
	}
	if sshLoginStore.Note(ip, user, at) {
		log.Printf("[ssh-logins] %s logged in over SSH: never banned for 30 days", ip)
		if err := sshLoginStore.Save(); err != nil {
			log.Printf("[ssh-logins] save %s: %v", sshLoginPath, err)
		}
		loginsAdded()
	}
	requestSSHLoginReport()
}

// noteLoginLine is the auth watcher's hook for "Accepted ..." lines.
func noteLoginLine(line string) {
	if l, ok := loginhistory.ParseLine(line, time.Now()); ok {
		// The line was just written: its time is now (a traditional
		// timestamp has no time zone).
		noteLiveLogin(l.IP, l.User, time.Time{})
	}
}

// loginsAdded runs, in the background, what depends on the list: the bans
// in force lifted, the country and threat-feed sets rebuilt.
func loginsAdded() {
	sshLoginGen.Add(1)
	go func() {
		liftGuardedBans()
		if fn := onSSHLoginsAdded.Load(); fn != nil {
			(*fn)()
		}
	}()
}

// sshLoginGuard returns the last SSH login of ip in the last 30 days.
func sshLoginGuard(ip string) (time.Time, bool) {
	p := net.ParseIP(ip)
	if p == nil {
		return time.Time{}, false
	}
	s := p.String()
	if v4 := p.To4(); v4 != nil {
		s = v4.String()
	}
	var last time.Time
	ok := false
	if sshLoginStore != nil {
		last, ok = sshLoginStore.LastLogin(s)
	}
	memoMu.Lock()
	if t, seen := sshLogins[s]; seen && fwNow().Sub(time.Unix(t, 0)) < sshLoginFor {
		if lt := time.Unix(t, 0); !ok || lt.After(last) {
			last, ok = lt, true
		}
	}
	memoMu.Unlock()
	return last, ok
}

var (
	guardLogMu   sync.Mutex
	guardLogLast = map[string]time.Time{}
)

// guarded reports whether ip must not be banned, and logs it (once an hour
// per address and action).
func guarded(ip, what string) bool {
	last, ok := sshLoginGuard(ip)
	if !ok {
		return false
	}
	key := what + " " + ip
	guardLogMu.Lock()
	if t, seen := guardLogLast[key]; !seen || time.Since(t) >= guardLogEvery {
		guardLogLast[key] = time.Now()
		if len(guardLogLast) > 5000 {
			guardLogLast = map[string]time.Time{key: time.Now()}
		}
		guardLogMu.Unlock()
		log.Printf("[guard] not %s %s: SSH login on %s", what, ip, last.UTC().Format("2006-01-02 15:04 UTC"))
	} else {
		guardLogMu.Unlock()
	}
	return true
}

// guardReason is the auth watcher's guard: "ssh_login" for an address it
// must not ban.
func guardReason(ip string) string {
	if guarded(ip, "banning") {
		return "ssh_login"
	}
	return ""
}

// guardBans leaves out the dashboard's bans of addresses with an SSH login.
func guardBans(bans []api.Ban) []api.Ban {
	out := bans[:0:0]
	for _, b := range bans {
		if guarded(b.IPAddress, "applying the dashboard's ban of") {
			continue
		}
		out = append(out, b)
	}
	return out
}

// liftGuardedBans lifts the bans in force of addresses with an SSH login
// (banned before their login was known).
func liftGuardedBans() {
	for _, ip := range sshLoginStore.IPs() {
		if !firewall.IsBanned(ip) {
			continue
		}
		last, _ := sshLoginGuard(ip)
		if err := firewall.UnbanIP(ip); err != nil {
			log.Printf("[guard] lift the ban of %s: %v", ip, err)
			continue
		}
		log.Printf("[guard] lifted the ban of %s: SSH login on %s", ip, last.UTC().Format("2006-01-02 15:04 UTC"))
	}
}

// sshLoginExempt: the addresses left out of the country and threat-feed sets.
func sshLoginExempt() []string {
	if sshLoginStore == nil {
		return nil
	}
	return sshLoginStore.IPs()
}

func requestSSHLoginReport() {
	select {
	case sshLoginReport <- struct{}{}:
	default:
	}
}

func sshLoginsPayload() api.SSHLoginsRequest {
	all := sshLoginStore.Entries(0)
	req := api.SSHLoginsRequest{Logins: []api.SSHLogin{}, Total: len(all)}
	if t := sshLoginStore.ScannedAt(); !t.IsZero() {
		req.ScannedAt = t.UTC().Format(time.RFC3339)
	}
	if len(all) > sshLoginReportMax {
		all = all[:sshLoginReportMax]
	}
	for _, e := range all {
		req.Logins = append(req.Logins, api.SSHLogin{
			IP: e.IP, Users: e.Users, Count: e.Count, Imported: e.Imported, Live: e.Live,
			FirstAt: e.First.UTC().Format(time.RFC3339), LastAt: e.Last.UTC().Format(time.RFC3339),
		})
	}
	return req
}

// reportSSHLoginsLoop sends the history when asked, at most every
// sshLoginReportGap; a failure is retried at the next request.
func reportSSHLoginsLoop(client *api.Client) {
	var last time.Time
	unsupported := false
	for range sshLoginReport {
		if wait := sshLoginReportGap - time.Since(last); !last.IsZero() && wait > 0 {
			time.Sleep(wait)
		}
		last = time.Now()
		c := currentAPIClient.Load()
		if c == nil {
			c = client
		}
		err := c.ReportSSHLogins(sshLoginsPayload())
		switch {
		case err == nil:
			unsupported = false
		case api.IsNotFound(err):
			if !unsupported {
				log.Printf("[ssh-logins] the dashboard does not take the login history yet: kept on this server")
			}
			unsupported = true
		default:
			if !api.IsHeld(err) {
				log.Printf("[ssh-logins] report: %v (sent again later)", err)
			}
			go func() { time.Sleep(sshLoginReportGap); requestSSHLoginReport() }()
		}
	}
}
