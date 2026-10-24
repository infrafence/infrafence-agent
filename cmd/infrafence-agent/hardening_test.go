package main

import (
	"testing"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/remediation"
	"github.com/infrafence/infrafence-agent/internal/verify"
)

// A PHP fix after which a site stops answering is reverted (the drop-in
// removed, PHP reloaded) and reported as rolled_back.
func TestPHPFixRolledBackWhenSiteBreaks(t *testing.T) {
	saved := []any{fixApply, fixRevert, rescanAfterFixes, hardeningSnapshot, hardeningCheck, reportEvent}
	t.Cleanup(func() {
		fixApply = saved[0].(func(remediation.Host, string, remediation.Policy) (string, error))
		fixRevert = saved[1].(func(remediation.Host, string) (string, error))
		rescanAfterFixes = saved[2].(func(*api.Client))
		hardeningSnapshot = saved[3].(func() verify.State)
		hardeningCheck = saved[4].(func(verify.State) verify.Result)
		reportEvent = saved[5].(func(*api.Client, string, string, map[string]string))
	})
	var applied, reverted []string
	fixApply = func(_ remediation.Host, id string, _ remediation.Policy) (string, error) {
		applied = append(applied, id)
		return "set allow_url_include = Off", nil
	}
	fixRevert = func(_ remediation.Host, id string) (string, error) {
		reverted = append(reverted, id)
		return "removed allow_url_include", nil
	}
	rescanAfterFixes = func(*api.Client) {}
	hardeningSnapshot = func() verify.State { return verify.State{} }
	hardeningCheck = func(verify.State) verify.Result {
		return verify.Result{SSHOK: true, SitesOK: false, Details: "a.example 502 (was 200)"}
	}
	type ev struct {
		typ     string
		details map[string]string
	}
	var events []ev
	reportEvent = func(_ *api.Client, typ, _ string, d map[string]string) { events = append(events, ev{typ, d}) }

	id := "PHP_ALLOW_URL_INCLUDE@debian-8.2-fpm/www"
	applyHardeningFixes(nil, []api.HardeningFix{{ID: 9001, CheckID: id}})
	if len(events) == 1 {
		// A fix that changed nothing is never rolled back: the setting
		// may belong to another pool's fix.
		fixApply = func(remediation.Host, string, remediation.Policy) (string, error) {
			return remediation.PHPNoChange + "already set", nil
		}
		applyHardeningFixes(nil, []api.HardeningFix{{ID: 9002, CheckID: id}})
		if len(reverted) != 1 || len(events) != 2 || events[1].typ != "hardening_fix_applied" {
			t.Fatalf("no-op fix: reverted %v events %+v", reverted, events)
		}
		events = events[:1]
	}

	if len(applied) != 1 || len(reverted) != 1 || reverted[0] != id {
		t.Fatalf("applied %v reverted %v", applied, reverted)
	}
	if len(events) != 1 || events[0].typ != "hardening_fix_rolled_back" || events[0].details["status"] != "rolled_back" ||
		events[0].details["reason"] != "verify_failed" {
		t.Fatalf("events = %+v", events)
	}
}
