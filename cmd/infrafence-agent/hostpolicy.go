package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/firewall"
	"github.com/infrafence/infrafence-agent/internal/preflight"
	"github.com/infrafence/infrafence-agent/internal/updater"
	"github.com/infrafence/infrafence-agent/internal/webserver"
)

// Host policy: what the agent may change on this server. Settings come from
// the dashboard (monitor_config) and default to the conservative choice;
// the preflight scan can veto a setting (e.g. a hosting panel owns the web
// server config). Changes the agent already made are never silently undone.
var (
	hostReport          atomic.Pointer[preflight.Report]
	allowWebserverEdits atomic.Bool
	autoUpdateNotify    atomic.Bool

	webserverMu        sync.Mutex
	modsecSetupAt      time.Time
	webserverLastState string

	notifiedUpdate sync.Map // version -> struct{}
)

func currentReport() preflight.Report {
	if r := hostReport.Load(); r != nil {
		return *r
	}
	return preflight.Report{}
}

// applyHostSettings reads the dashboard settings from monitor_config.
func applyHostSettings(cfg *api.MonitorConfig) {
	webserverEdits, blockFeeds, notify := false, false, false
	if cfg != nil {
		webserverEdits = cfg.WebserverChanges
		blockFeeds = cfg.BlockThreatFeeds
		notify = cfg.AutoUpdate == "notify"
	}
	allowWebserverEdits.Store(webserverEdits)
	autoUpdateNotify.Store(notify)
	intelState.Lock()
	intelState.blockInbound = blockFeeds
	intelState.Unlock()
}

// webserverEditsAllowed: the dashboard enabled it and preflight found no
// hosting panel / configuration management owning the web server config.
func webserverEditsAllowed() (bool, string) {
	if !allowWebserverEdits.Load() {
		return false, "disabled in dashboard settings"
	}
	d := currentReport().Decisions
	if !d.WebserverChangesSafe {
		return false, d.WebserverChangesReason
	}
	return true, ""
}

// applyWebserverChanges sets up ModSecurity rules and web-server level UA
// blocking only when allowed. Bots with a "block" action are still banned at
// the firewall when web server edits are off.
func applyWebserverChanges(client *api.Client, wsType string, blockFps []webserver.UAFingerprint) {
	webserverMu.Lock()
	defer webserverMu.Unlock()

	ok, reason := webserverEditsAllowed()
	state := "on"
	if !ok {
		state = "off: " + reason
	}
	if state != webserverLastState {
		webserverLastState = state
		log.Printf("[host] web server config changes %s", state)
	}
	if !ok {
		return
	}

	report := func(eventType, severity string, details map[string]string) {
		if err := client.ReportEvents([]api.EventRequest{{
			Type: eventType, Severity: severity, Details: details,
			OccurredAt: time.Now().UTC().Format(time.RFC3339),
		}}); err != nil {
			log.Printf("[host] failed to report %s: %v", eventType, err)
		}
	}

	// ModSecurity: Apache only (not LiteSpeed, which reads Apache's config
	// but must not have Apache reloaded under it); one attempt a day at most.
	if wsType == "apache" && modsecEngine != nil && modsecEngine.IsAvailable() && time.Since(modsecSetupAt) > 24*time.Hour {
		modsecSetupAt = time.Now()
		if err := modsecEngine.Setup(); err != nil {
			log.Printf("[modsec] setup failed: %v", err)
			report("webserver_config_error", "warning", map[string]string{"webserver": "apache", "action": "modsec_setup_failed", "error": err.Error()})
		} else {
			modsecSetupAt = time.Now().Add(100 * 365 * 24 * time.Hour) // done
			report("modsecurity_enabled", "info", map[string]string{"status": "active"})
		}
	}

	// UA blocking needs at least one bot with a "block" action; otherwise
	// there is nothing to enforce and no reason to edit the config.
	if len(blockFps) == 0 {
		return
	}
	switch wsType {
	case "nginx":
		if err := webserver.UpdateNginxUABlocklist(blockFps, report); err != nil {
			log.Printf("[ua-block] nginx update error: %v", err)
		}
		if err := webserver.SetupNginxUABlock(report); err != nil {
			log.Printf("[ua-block] nginx setup error: %v", err)
		}
	case "apache":
		if err := webserver.UpdateApacheUABlock(blockFps, report); err != nil {
			log.Printf("[ua-block] apache update error: %v", err)
		}
		if err := webserver.SetupApacheUABlock(report); err != nil {
			log.Printf("[ua-block] apache setup error: %v", err)
		}
	}
}

// maybeUpdate installs a new agent version, or only reports it when the
// dashboard is set to "notify" (customers who schedule their own changes).
func maybeUpdate(client *api.Client, latest, baseURL string, report updater.EventReporter) {
	if latest == "" || latest == version {
		return
	}
	if autoUpdateNotify.Load() {
		if _, seen := notifiedUpdate.LoadOrStore(latest, struct{}{}); !seen {
			log.Printf("[updater] v%s available — auto-update is off (notify only)", latest)
			report("update_available", "info", map[string]string{"current": version, "latest": latest})
		}
		return
	}
	updater.CheckAndUpdate(version, latest, baseURL, report)
}

// runPreflightScan scans the host, keeps the result for policy decisions and
// reports it to the dashboard; repeated daily.
func runPreflightScan(client *api.Client) {
	for {
		time.Sleep(24 * time.Hour)
		r := preflight.Scan()
		hostReport.Store(&r)
		logReport(r)
		if client != nil {
			if err := client.ReportEvents([]api.EventRequest{{
				Type:       "host_preflight",
				Severity:   "info",
				Details:    reportDetails(r),
				OccurredAt: time.Now().UTC().Format(time.RFC3339),
			}}); err != nil {
				log.Printf("[preflight] failed to report: %v", err)
			}
		}
	}
}

// startupPreflight scans before the first sync so policy decisions exist
// from the start, and reports the result.
func startupPreflight(client *api.Client) {
	r := preflight.Scan()
	hostReport.Store(&r)
	logReport(r)
	if err := client.ReportEvents([]api.EventRequest{{
		Type:       "host_preflight",
		Severity:   "info",
		Details:    reportDetails(r),
		OccurredAt: time.Now().UTC().Format(time.RFC3339),
	}}); err != nil {
		log.Printf("[preflight] failed to report: %v", err)
	}
	go runPreflightScan(client)
}

func logReport(r preflight.Report) {
	for _, f := range r.Findings {
		if f.Level != preflight.OK {
			log.Printf("[preflight] %s: %s", f.Level, f.Title)
		}
	}
	d := r.Decisions
	log.Printf("[preflight] firewall=%v ipset=%v docker=%v webserver_edits_safe=%v managers=%q",
		d.FirewallEnforcement, d.Ipset, d.Docker, d.WebserverChangesSafe, r.Facts["firewall_managers"])
}

// reportDetails flattens a report into event details (string map).
func reportDetails(r preflight.Report) map[string]string {
	det := map[string]string{"worst": string(r.Worst())}
	for k, v := range r.Facts {
		if v != "" {
			det["fact."+k] = v
		}
	}
	d := r.Decisions
	det["decision.firewall_enforcement"] = fmt.Sprint(d.FirewallEnforcement)
	det["decision.ipset"] = fmt.Sprint(d.Ipset)
	det["decision.docker"] = fmt.Sprint(d.Docker)
	det["decision.webserver_changes_safe"] = fmt.Sprint(d.WebserverChangesSafe)
	if d.WebserverChangesReason != "" {
		det["decision.webserver_changes_reason"] = d.WebserverChangesReason
	}
	for _, f := range r.Findings {
		if f.Level != preflight.OK {
			det["finding."+f.ID] = string(f.Level) + ": " + f.Title
		}
	}
	return det
}

// ── Subcommands ─────────────────────────────────────────────────────────────

func cmdPreflight(args []string) {
	r := preflight.Scan()
	if len(args) > 0 && args[0] == "--json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(r)
		return
	}
	fmt.Println("InfraFence preflight (read-only — nothing was changed)")
	keys := make([]string, 0, len(r.Facts))
	for k := range r.Facts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if r.Facts[k] != "" {
			fmt.Printf("  %-20s %s\n", k, r.Facts[k])
		}
	}
	fmt.Println()
	for _, f := range r.Findings {
		fmt.Printf("  [%-5s] %s\n", strings.ToUpper(string(f.Level)), f.Title)
		if f.Detail != "" {
			fmt.Printf("          %s\n", f.Detail)
		}
	}
	if r.Worst() == preflight.Block {
		os.Exit(2)
	}
}

// cmdUninstall removes what the agent changed on the host: firewall chains,
// jumps and ipsets, web-server UA blocking and ModSecurity includes. Each
// step restores its files if the web server's config test fails.
func cmdUninstall(args []string) {
	if len(args) == 0 || args[0] != "--clean" {
		fmt.Fprintln(os.Stderr, "usage: infrafence-agent uninstall --clean")
		os.Exit(1)
	}
	failed := false
	for _, s := range firewall.RemoveAll() {
		fmt.Println("removed", s)
	}
	for name, fn := range map[string]func() error{
		"nginx UA blocking":  webserver.RemoveNginxUABlock,
		"apache UA blocking": webserver.RemoveApacheUABlock,
	} {
		if err := fn(); err != nil {
			fmt.Fprintf(os.Stderr, "could not remove %s: %v\n", name, err)
			failed = true
		}
	}
	if err := modsecurityRemove(); err != nil {
		fmt.Fprintf(os.Stderr, "could not remove ModSecurity rules: %v\n", err)
		failed = true
	}
	if failed {
		os.Exit(1)
	}
	fmt.Println("InfraFence changes removed from this host.")
}
