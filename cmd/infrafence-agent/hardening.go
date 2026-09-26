package main

import (
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/collector"
	"github.com/infrafence/infrafence-agent/internal/remediation"
	"github.com/infrafence/infrafence-agent/internal/scanner"
)

// Hardening checks, software audits (the package list the dashboard checks
// against vulnerability databases) and the fixes an admin applies from the
// dashboard. Each runs one at a time; requests arriving meanwhile are
// dropped, since the running one reports the same state.

var (
	hardeningRunning atomic.Bool
	auditRunning     atomic.Bool
	fixMu            sync.Mutex
	// Fix IDs already handled, so a sync that arrives before the dashboard
	// records the result doesn't apply the same fix twice.
	fixesDone   = map[int64]bool{}
	fixesDoneMu sync.Mutex
)

func remediationPolicy() remediation.Policy {
	if r := hostReport.Load(); r != nil {
		return remediation.Policy{ConfigChangesSafe: r.Decisions.WebserverChangesSafe}
	}
	// No preflight yet: only permission fixes.
	return remediation.Policy{ConfigChangesSafe: false}
}

func reportEvent(client *api.Client, typ, severity string, details map[string]string) {
	if client == nil {
		return
	}
	if err := client.ReportEvents([]api.EventRequest{{
		Type: typ, Severity: severity, Details: details,
		OccurredAt: time.Now().UTC().Format(time.RFC3339),
	}}); err != nil {
		log.Printf("[api] failed to report %s: %v", typ, err)
	}
}

// runScan runs the hardening checks and submits the results.
func runScan(client *api.Client, scanID int64) {
	if !hardeningRunning.CompareAndSwap(false, true) {
		log.Printf("[scanner] hardening check already running")
		return
	}
	defer hardeningRunning.Store(false)

	log.Printf("[scanner] starting hardening check")
	reportEvent(client, "hardening_scan_started", "info", nil)

	policy := remediationPolicy()
	results := scanner.Run()
	findings := make([]api.ScanFinding, len(results))
	failed := 0
	for i, r := range results {
		f := api.ScanFinding{
			Category:       r.Category,
			Severity:       r.Severity,
			CheckID:        r.CheckID,
			Title:          r.Title,
			Description:    r.Description,
			Recommendation: r.Recommendation,
			Details:        r.Details,
			Passed:         r.Passed,
		}
		if !r.Passed {
			failed++
			f.Fixable, f.FixBlockedReason = remediation.Availability(r.CheckID, policy)
		}
		findings[i] = f
	}

	if err := client.SubmitScanResults(api.ScanResultRequest{ScanID: scanID, Findings: findings}); err != nil {
		log.Printf("[scanner] failed to submit results: %v", err)
		return
	}
	log.Printf("[scanner] hardening check done — %d checks, %d to fix", len(findings), failed)
}

// runSoftwareAudit collects the software inventory and submits it.
func runSoftwareAudit(client *api.Client, auditID int64) {
	if !auditRunning.CompareAndSwap(false, true) {
		log.Printf("[collector] software audit already running")
		return
	}
	defer auditRunning.Store(false)

	log.Printf("[collector] starting software audit")
	reportEvent(client, "software_audit_started", "info", nil)

	result := collector.Collect()
	if err := client.SubmitSoftwareAudit(api.SoftwareAuditRequest{
		AuditID:     auditID,
		OSID:        result.OSID,
		OSVersionID: result.OSVersionID,
		Summary:     result.Summary,
		KeySoftware: result.KeySoftware,
		Packages:    result.Packages,
	}); err != nil {
		log.Printf("[collector] failed to submit audit: %v", err)
		return
	}
	log.Printf("[collector] audit complete — %d packages, %d key software items",
		result.Summary.TotalPackages, len(result.KeySoftware))
}

// applyHardeningFixes applies (or reverts) the requested fixes one by one,
// reports each result, then re-runs the checks so the dashboard shows the
// new state.
func applyHardeningFixes(client *api.Client, fixes []api.HardeningFix) {
	fixMu.Lock()
	defer fixMu.Unlock()

	var todo []api.HardeningFix
	fixesDoneMu.Lock()
	for _, f := range fixes {
		if !fixesDone[f.ID] {
			fixesDone[f.ID] = true
			todo = append(todo, f)
		}
	}
	fixesDoneMu.Unlock()
	if len(todo) == 0 {
		return
	}

	policy := remediationPolicy()
	for _, f := range todo {
		action := f.Action
		if action == "" {
			action = "apply"
		}
		var msg string
		var err error
		if action == "revert" {
			msg, err = remediation.Revert(remediation.System, f.CheckID)
		} else {
			msg, err = remediation.Apply(remediation.System, f.CheckID, policy)
		}
		details := map[string]string{
			"fix_id":   fmt.Sprint(f.ID),
			"check_id": f.CheckID,
			"action":   action,
		}
		if err != nil {
			log.Printf("[remediation] %s %s failed: %v", action, f.CheckID, err)
			details["status"] = "failed"
			details["message"] = err.Error()
			reportEvent(client, "hardening_fix_failed", "warning", details)
			continue
		}
		log.Printf("[remediation] %s %s: %s", action, f.CheckID, msg)
		details["status"] = "applied"
		details["message"] = msg
		reportEvent(client, "hardening_fix_applied", "info", details)
	}
	runScan(client, 0)
}

// runDailyAudits runs the hardening check and the software audit shortly
// after start and then once a day, so the dashboard always has recent
// results without anyone asking.
func runDailyAudits(client func() *api.Client) {
	time.Sleep(10 * time.Minute)
	for {
		if c := client(); c != nil {
			runScan(c, 0)
			runSoftwareAudit(c, 0)
		}
		time.Sleep(24 * time.Hour)
	}
}
