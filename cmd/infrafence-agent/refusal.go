package main

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/backoff"
	"github.com/infrafence/infrafence-agent/internal/firewall"
	"github.com/infrafence/infrafence-agent/internal/verify"
	"github.com/infrafence/infrafence-agent/internal/webserver"
)

// After 24 hours of explicit refusal (every answer of the dashboard a 401,
// or a 403 on the agent endpoints such as {"error":"suspended"}) the agent
// switches its protection off cleanly: the account is suspended or the
// subscription ended, and protection the customer no longer has must not
// keep blocking traffic. An unreachable dashboard (network errors,
// timeouts, 5xx, DNS) is never a refusal: protection stays on indefinitely
// (backoff.Gate.RefusedFor).
//
// Switched off means: InfraFence's own chains, jumps and ipsets removed
// (bans, allow list, country blocks, threat feeds, closed ports, egress
// blocks; other tools' rules and the tables are never touched), its
// ModSecurity rules (virtual patches included) and user-agent blocking out
// of the web server, the realtime malware watcher stopped, the watchers
// only monitoring. SSH is checked afterwards as for a closed port. The
// agent keeps running and asks the dashboard every 30 minutes; the first
// successful sync switches protection back on. The start of the refusal
// and the switch-off are kept in the protection state, so a restart
// neither resets the clock nor turns protection back on.

const (
	// refusalLimit is how long the dashboard must refuse the agent.
	refusalLimit = 24 * time.Hour
	// refusalFresh: the latest refusal must be this recent for the clock to
	// count (the agent asks at least every 30 minutes while refused).
	refusalFresh = time.Hour
	// motdText is shown at login and logged once when protection is off.
	motdText = "InfraFence no longer protects this server: the account is suspended or the subscription ended. Reactivate it at https://infrafence.com/billing"
)

// Replaced in tests.
var (
	motdDir         = "/etc/motd.d"
	pamDir          = "/etc/pam.d"
	refusalNow      = time.Now
	disableFirewall = firewall.Disable
	enableFirewall  = func() error { _, err := firewall.Enable(); return err }
	detachWebserver = func() {
		if modsecEngine != nil && modsecEngine.IsAvailable() {
			if err := modsecEngine.Detach(); err != nil {
				log.Printf("[protection] ModSecurity rules not removed: %v", err)
			}
		}
		for name, fn := range map[string]func() error{"nginx": webserver.RemoveNginxUABlock, "apache": webserver.RemoveApacheUABlock} {
			if err := fn(); err != nil {
				log.Printf("[protection] %s user-agent blocking not removed: %v", name, err)
			}
		}
	}
	stopRealtimeMalware = func() {
		if malwareRTWatcher != nil {
			malwareRTWatcher.Stop()
		}
	}
	sshSnapshot = func() verify.State { return fwSnapshot() }
	sshCheck    = func(before verify.State) verify.Result { return fwCheck(before) }
)

// refusalLimitFor is refusalLimit, or for test builds (version "...-test")
// INFRAFENCE_TEST_REFUSAL_LIMIT (a Go duration), so the distro test does
// not wait a day.
func refusalLimitFor(ver string) time.Duration {
	if strings.HasSuffix(ver, "-test") {
		if d, err := time.ParseDuration(os.Getenv("INFRAFENCE_TEST_REFUSAL_LIMIT")); err == nil && d > 0 {
			return d
		}
	}
	return refusalLimit
}

// protCtl is the switch-off state, saved with the protection state.
var protCtl = struct {
	// op is held for a whole switch-off or switch-on, so they never
	// interleave (a sync succeeding while protection is being switched off).
	op sync.Mutex
	sync.Mutex
	disabledAt  time.Time
	motdCreated bool // /etc/motd.d was created by the agent
	watchers    banWatchers
	gate        *backoff.Gate
}{}

// protectionStatus is for panel status: active, refused (the dashboard
// refuses the agent, protection still on) or disabled.
func protectionStatus() (status string, refusedSince, disabledAt time.Time) {
	protCtl.Lock()
	disabledAt, g := protCtl.disabledAt, protCtl.gate
	protCtl.Unlock()
	if g != nil {
		refusedSince = g.RefusedSince()
	}
	switch {
	case !disabledAt.IsZero():
		return "disabled", refusedSince, disabledAt
	case !refusedSince.IsZero():
		return "refused", refusedSince, disabledAt
	}
	return "active", refusedSince, disabledAt
}

// protectionDisabled reports whether protection is switched off.
func protectionDisabled() bool {
	protCtl.Lock()
	defer protCtl.Unlock()
	return !protCtl.disabledAt.IsZero()
}

// restoreRefusal puts back, at startup and before firewall.Init, the
// refusal clock and the switch-off saved before the restart.
func restoreRefusal(st *protPersisted, g *backoff.Gate) {
	protCtl.Lock()
	protCtl.gate = g
	if st != nil {
		protCtl.motdCreated = st.MotdDirCreated
		if st.DisabledAt > 0 {
			protCtl.disabledAt = time.Unix(st.DisabledAt, 0)
		}
	}
	off := !protCtl.disabledAt.IsZero()
	protCtl.Unlock()
	if st != nil && st.RefusedSince > 0 && st.RefusedLast > 0 {
		g.RestoreClock(time.Unix(st.RefusedSince, 0), time.Unix(st.RefusedLast, 0))
	}
	g.OnClockChange(scheduleProtectionSave)
	if off {
		// Off before the restart: whatever a reboot or a firewall restore
		// brought back of InfraFence's own chains and sets goes again
		// (only ours, as at the switch-off), and stays out.
		if removed := disableFirewall(); len(removed) > 0 {
			log.Printf("[protection] protection is switched off: removed again %v", removed)
		}
		g.SetIdle(true)
		writeMotd()
		log.Printf("[protection] WARNING: %s (switched off %s; checking the dashboard every 30 minutes)", motdText, time.Unix(st.DisabledAt, 0).UTC().Format(time.RFC3339))
	}
}

// watchRefusal checks every minute whether the dashboard has refused the
// agent for limit, and switches protection off when it has.
func watchRefusal(g *backoff.Gate, limit time.Duration, report func([]api.EventRequest) error) {
	for range time.Tick(time.Minute) {
		checkRefusal(g, limit, report)
	}
}

func checkRefusal(g *backoff.Gate, limit time.Duration, report func([]api.EventRequest) error) {
	if protectionDisabled() {
		return
	}
	if d := g.RefusedFor(refusalFresh); d >= limit {
		disableProtection(g, d, report)
	}
}

// disableProtection switches protection off (see the top of this file).
func disableProtection(g *backoff.Gate, refusedFor time.Duration, report func([]api.EventRequest) error) {
	protCtl.op.Lock()
	defer protCtl.op.Unlock()
	// Again under op: a sync may have succeeded meanwhile.
	if protectionDisabled() || g.RefusedFor(refusalFresh) == 0 {
		return
	}
	now := refusalNow()
	protCtl.Lock()
	ws := protCtl.watchers
	protCtl.Unlock()

	log.Printf("[protection] the dashboard has refused the agent for %s: switching InfraFence protection off", refusedFor.Round(time.Minute))
	before := sshSnapshot()
	ws.setMonitorMode(true)
	intelState.Lock()
	intelState.monitorMode = true // port-scan bans too
	intelState.appliedKey = ""
	intelState.Unlock()
	removed := disableFirewall()
	detachWebserver()
	stopRealtimeMalware()
	g.SetIdle(true)
	// Saved as off only once everything is removed: a restart meanwhile
	// finds protection on and the clock still running.
	protCtl.Lock()
	protCtl.disabledAt = now
	protCtl.Unlock()
	res := sshCheck(before)
	if res.SSHOK {
		log.Printf("[protection] removed %v; SSH still answers", removed)
	} else {
		log.Printf("[protection] WARNING: removed %v; SSH does not answer as before: %s", removed, res.Details)
	}
	writeMotd()
	log.Printf("[protection] WARNING: %s", motdText)
	saveProtectionState()
	if report != nil {
		// Delivered once the dashboard accepts the agent again.
		_ = report([]api.EventRequest{{
			Type:     "protection_disabled",
			Severity: "critical",
			Details: map[string]string{
				"refused_since": g.RefusedSince().UTC().Format(time.RFC3339),
				"removed":       strings.Join(removed, ", "),
				"ssh_ok":        boolString(res.SSHOK),
			},
			OccurredAt: now.UTC().Format(time.RFC3339),
		}})
	}
}

// enableProtection switches protection back on after a successful sync,
// before the sync is applied (which brings the dashboard's state). It
// reports whether protection was off.
func enableProtection(report func([]api.EventRequest) error) bool {
	protCtl.op.Lock()
	defer protCtl.op.Unlock()
	protCtl.Lock()
	if protCtl.disabledAt.IsZero() {
		protCtl.Unlock()
		return false
	}
	since := protCtl.disabledAt
	protCtl.disabledAt = time.Time{}
	g := protCtl.gate
	protCtl.Unlock()

	if err := enableFirewall(); err != nil {
		log.Printf("[protection] firewall setup after the switch-off: %v (the guard retries)", err)
	}
	if g != nil {
		g.SetIdle(false)
	}
	// ModSecurity is set up again by the sync (its rules were kept), user
	// agents and the realtime watcher too; threat feeds are re-applied.
	webserverMu.Lock()
	modsecSetupAt = time.Time{}
	webserverMu.Unlock()
	intelState.Lock()
	intelState.appliedKey = ""
	intelState.Unlock()
	removeMotd()
	log.Printf("[protection] the dashboard accepts the agent again: InfraFence protection is back on (it was off since %s)", since.UTC().Format(time.RFC3339))
	saveProtectionState()
	if report != nil {
		_ = report([]api.EventRequest{{
			Type: "protection_restored", Severity: "info",
			Details:    map[string]string{"disabled_at": since.UTC().Format(time.RFC3339)},
			OccurredAt: refusalNow().UTC().Format(time.RFC3339),
		}})
	}
	return true
}

func (ws banWatchers) setMonitorMode(on bool) {
	if ws.auth != nil {
		ws.auth.SetMonitorMode(on)
	}
	if ws.web != nil {
		ws.web.SetMonitorMode(on)
	}
	if ws.mail != nil {
		ws.mail.SetMonitorMode(on)
	}
	if ws.db != nil {
		ws.db.SetMonitorMode(on)
	}
	if ws.ftp != nil {
		ws.ftp.SetMonitorMode(on)
	}
}

// motdUsed reports whether login messages are read from /etc/motd.d: the
// directory exists, or a PAM service loads pam_motd (which reads it).
func motdUsed() (exists, used bool) {
	if fi, err := os.Stat(motdDir); err == nil && fi.IsDir() {
		return true, true
	}
	entries, err := os.ReadDir(pamDir)
	if err != nil {
		return false, false
	}
	for _, e := range entries {
		if b, err := os.ReadFile(filepath.Join(pamDir, e.Name())); err == nil && strings.Contains(string(b), "pam_motd") {
			return false, true
		}
	}
	return false, false
}

// writeMotd writes the switch-off notice to /etc/motd.d/infrafence.
func writeMotd() {
	exists, used := motdUsed()
	if !used {
		log.Printf("[protection] %s is not used on this server: no login notice written", motdDir)
		return
	}
	if !exists {
		if err := os.Mkdir(motdDir, 0o755); err != nil {
			log.Printf("[protection] create %s: %v", motdDir, err)
			return
		}
		protCtl.Lock()
		protCtl.motdCreated = true
		protCtl.Unlock()
	}
	path := filepath.Join(motdDir, "infrafence")
	tmp, err := os.CreateTemp(motdDir, ".infrafence.*") // new file, never followed
	if err == nil {
		_, err = tmp.WriteString(motdText + "\n")
		if err == nil {
			err = tmp.Chmod(0o644)
		}
		if cerr := tmp.Close(); err == nil {
			err = cerr
		}
		if err == nil {
			err = os.Rename(tmp.Name(), path)
		}
		if err != nil {
			os.Remove(tmp.Name())
		}
	}
	if err != nil {
		log.Printf("[protection] write %s: %v", path, err)
	}
}

// removeMotd removes the notice, and /etc/motd.d if the agent created it
// and nothing else is in it.
func removeMotd() {
	if err := os.Remove(filepath.Join(motdDir, "infrafence")); err != nil && !os.IsNotExist(err) {
		log.Printf("[protection] remove the login notice: %v", err)
	}
	protCtl.Lock()
	created := protCtl.motdCreated
	protCtl.motdCreated = false
	protCtl.Unlock()
	if created {
		_ = os.Remove(motdDir) // fails, harmlessly, when not empty
	}
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
