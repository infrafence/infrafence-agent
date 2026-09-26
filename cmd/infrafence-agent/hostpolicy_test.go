package main

import (
	"testing"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/preflight"
)

func setReport(safe bool, reason string) {
	r := preflight.Report{Decisions: preflight.Decisions{WebserverChangesSafe: safe, WebserverChangesReason: reason}}
	hostReport.Store(&r)
}

func TestWebserverEditsNeedSettingAndSafeHost(t *testing.T) {
	setReport(true, "")
	applyHostSettings(nil)
	if ok, why := webserverEditsAllowed(); ok || why != "disabled in dashboard settings" {
		t.Errorf("default must be off: ok=%v why=%q", ok, why)
	}
	applyHostSettings(&api.MonitorConfig{WebserverChanges: true})
	if ok, _ := webserverEditsAllowed(); !ok {
		t.Error("enabled setting on a safe host should allow edits")
	}
	setReport(false, "cPanel manages the web server configuration")
	if ok, why := webserverEditsAllowed(); ok || why == "" {
		t.Errorf("preflight must veto the setting: ok=%v why=%q", ok, why)
	}
}

func TestThreatFeedBlockingDefaultsOff(t *testing.T) {
	applyHostSettings(nil)
	intelState.Lock()
	on := intelState.blockInbound
	intelState.Unlock()
	if on {
		t.Error("inbound threat-feed blocking must be off by default")
	}
	applyHostSettings(&api.MonitorConfig{BlockThreatFeeds: true})
	intelState.Lock()
	on = intelState.blockInbound
	intelState.Unlock()
	if !on {
		t.Error("setting should enable it")
	}
}

func TestNotifyOnlyUpdateReportsOnceAndDoesNotInstall(t *testing.T) {
	applyHostSettings(&api.MonitorConfig{AutoUpdate: "notify"})
	var reports int
	report := func(eventType, severity string, details map[string]string) {
		if eventType == "update_available" {
			reports++
		}
	}
	maybeUpdate(nil, "99.0.0", "https://example.invalid", report)
	maybeUpdate(nil, "99.0.0", "https://example.invalid", report)
	if reports != 1 {
		t.Errorf("update_available reported %d times, want 1", reports)
	}
}

func TestReportDetailsFlattening(t *testing.T) {
	r := preflight.Report{
		Facts:     map[string]string{"os": "Ubuntu", "empty": ""},
		Findings:  []preflight.Finding{{ID: "ipset", Level: preflight.Warn, Title: "ipset not installed"}, {ID: "iptables", Level: preflight.OK, Title: "ok"}},
		Decisions: preflight.Decisions{FirewallEnforcement: true},
	}
	d := reportDetails(r)
	if d["fact.os"] != "Ubuntu" || d["finding.ipset"] != "warn: ipset not installed" || d["worst"] != "warn" || d["decision.firewall_enforcement"] != "true" {
		t.Errorf("details: %v", d)
	}
	if _, ok := d["fact.empty"]; ok {
		t.Error("empty facts should be dropped")
	}
	if _, ok := d["finding.iptables"]; ok {
		t.Error("OK findings should not be reported")
	}
}
