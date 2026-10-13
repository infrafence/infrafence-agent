package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/malware"
	"github.com/infrafence/infrafence-agent/internal/modsecurity"
	"github.com/infrafence/infrafence-agent/internal/verify"
)

// Virtual patches and quarantine restores requested from the dashboard. Each
// request is handled once (dedup by id, in memory) and reported back.

var (
	vpatchMu       sync.Mutex
	vpatchesDone   = map[int64]bool{}
	restoreMu      sync.Mutex
	restoresDone   = map[int64]bool{}
	verifySnapshot = verify.Snapshot
	verifyCheck    = verify.CheckAfterReload
	vpatchEditsOK  = webserverEditsAllowed
)

// vpatchEngine is the part of the ModSecurity engine a patch needs.
type vpatchEngine interface {
	AppliedVirtualPatches() []string
	SetVirtualPatches(ruleIDs []string) (func() error, bool, error)
	VirtualPatchesEnforced() (bool, string)
}

// applyVirtualPatches handles the requests one at a time. It runs after
// applyWebserverChanges, so ModSecurity setup has been tried first.
func applyVirtualPatches(client *api.Client, wsType string, monitorMode bool, reqs []api.VirtualPatchRequest) {
	vpatchMu.Lock()
	defer vpatchMu.Unlock()
	webserverMu.Lock()
	defer webserverMu.Unlock()

	var eng vpatchEngine
	if modsecEngine != nil && modsecEngine.IsAvailable() {
		eng = modsecEngine
	}
	for _, r := range reqs {
		if vpatchesDone[r.ID] {
			continue
		}
		vpatchesDone[r.ID] = true
		typ, severity, details := handleVirtualPatch(eng, wsType, monitorMode, r)
		log.Printf("[vpatch] %s %s: %s %s", details["action"], r.RuleID, details["status"], details["message"])
		reportEvent(client, typ, severity, details)
	}
}

// handleVirtualPatch applies or removes one patch: preflight checks, write
// + config test + graceful reload, verify, roll back if verification fails.
// An applied patch must also be enforced (rule engine On, the probe rule
// blocks locally); otherwise it is rolled back and reported ineffective,
// since a patch ModSecurity only logs protects nothing. Removals are never
// rolled back for that. It returns the result event.
func handleVirtualPatch(eng vpatchEngine, wsType string, monitorMode bool, r api.VirtualPatchRequest) (string, string, map[string]string) {
	details := map[string]string{
		"patch_id": fmt.Sprint(r.ID),
		"rule_id":  r.RuleID,
		"action":   r.Action,
	}
	fail := func(status, reason, msg string) (string, string, map[string]string) {
		details["status"], details["reason"], details["message"] = status, reason, msg
		return "virtual_patch_failed", "warning", details
	}

	if r.Action != "apply" && r.Action != "remove" {
		return fail("failed", "invalid_action", "unknown action "+strconv.Quote(r.Action))
	}
	patch, ok := modsecurity.LookupVirtualPatch(r.RuleID)
	if !ok {
		return fail("failed", "unknown_rule", "rule not in this agent's catalog (update the agent)")
	}
	details["cve"] = patch.CVE
	apply := r.Action == "apply"
	if apply && monitorMode {
		return fail("skipped", "monitor_mode", "server is in monitor mode: nothing is blocked")
	}
	if eng == nil || wsType != "apache" || !patch.Supports(wsType) {
		return fail("failed", "unsupported_webserver", "virtual patches need Apache with ModSecurity (found: "+webserverLabel(wsType, eng != nil)+")")
	}
	if apply {
		if ok, why := vpatchEditsOK(); !ok {
			return fail("failed", "webserver_changes_off", "web server changes are not allowed: "+why)
		}
	}

	current := eng.AppliedVirtualPatches()
	want := slices.DeleteFunc(slices.Clone(current), func(id string) bool { return id == r.RuleID })
	if apply {
		want = append(want, r.RuleID)
	}

	ports, domains := verifyTargets()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	before := verifySnapshot(ctx, ports, domains)

	undo, changed, err := eng.SetVirtualPatches(want)
	if errors.Is(err, modsecurity.ErrNotActive) {
		return fail("failed", "modsecurity_not_active", err.Error())
	}
	if err != nil {
		reason := "apply_failed"
		if strings.Contains(err.Error(), "config test failed") {
			reason = "configtest_failed"
		}
		return fail("failed", reason, err.Error())
	}
	if !changed {
		if apply {
			// Already in the file: still only reported done when enforced.
			if ok, why := eng.VirtualPatchesEnforced(); !ok {
				return fail("failed", "ineffective", why)
			}
		}
		details["status"] = "done"
		if apply {
			details["message"] = "already applied"
		} else {
			details["message"] = "not applied"
		}
		return "virtual_patch_done", "info", details
	}

	res := verifyCheck(ctx, before)
	details["verify"] = verifyJSON(res)
	if !res.SSHOK || !res.SitesOK {
		if uerr := undo(); uerr != nil {
			details["status"], details["reason"] = "failed", "rollback_failed"
			details["message"] = "verification failed (" + res.Details + ") and the rollback failed: " + uerr.Error()
			return "virtual_patch_failed", "critical", details
		}
		details["status"], details["reason"] = "rolled_back", "verify_failed"
		details["message"] = "verification failed, previous rules restored: " + res.Details
		return "virtual_patch_rolled_back", "warning", details
	}
	if apply {
		if ok, why := eng.VirtualPatchesEnforced(); !ok {
			if uerr := undo(); uerr != nil {
				details["status"], details["reason"] = "failed", "rollback_failed"
				details["message"] = why + "; the rollback failed: " + uerr.Error()
				return "virtual_patch_failed", "critical", details
			}
			return fail("failed", "ineffective", why)
		}
	}
	details["status"] = "done"
	if apply {
		details["message"] = patch.CVE + " virtual patch applied"
	} else {
		details["message"] = patch.CVE + " virtual patch removed"
	}
	return "virtual_patch_done", "info", details
}

func webserverLabel(wsType string, modsec bool) string {
	if wsType == "" {
		wsType = "no web server"
	}
	if !modsec {
		return wsType + ", no ModSecurity"
	}
	return wsType
}

// restoreQuarantinedFiles puts quarantined files back (see
// malware.RestoreQuarantined for the checks) and reports each result.
// Restoring blocks nothing, so it is done in monitor mode too.
func restoreQuarantinedFiles(client *api.Client, customPaths []string, reqs []api.QuarantineRestore) {
	restoreMu.Lock()
	defer restoreMu.Unlock()

	var webRoots []malware.WebRoot
	for _, r := range reqs {
		if restoresDone[r.ID] {
			continue
		}
		restoresDone[r.ID] = true
		if webRoots == nil {
			webRoots = malware.DetectWebRoots(customPaths)
		}
		details := map[string]string{"restore_id": fmt.Sprint(r.ID), "file": r.File}
		if err := malware.RestoreQuarantined(r.File, webRoots); err != nil {
			log.Printf("[quarantine] restore %s failed: %v", r.File, err)
			details["message"] = err.Error()
			reportEvent(client, "quarantine_restore_failed", "warning", details)
			continue
		}
		details["message"] = "restored"
		reportEvent(client, "quarantine_restored", "info", details)
	}
}
