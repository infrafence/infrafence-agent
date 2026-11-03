package modsecurity

import "testing"

func TestComodoAttackCategory(t *testing.T) {
	cases := map[string]string{
		`COMODO WAF: SQLi Attack Detected||www.example.com|F|2`:             "attack-sqli",
		`COMODO WAF: Blind SQL Injection Attack||www.example.com|F|2`:       "attack-sqli",
		`COMODO WAF: XSS Attack Detected||www.example.com|F|2`:              "attack-xss",
		`COMODO WAF: Directory Traversal Attack||www.example.com|F|2`:       "attack-lfi",
		`COMODO WAF: Remote File Inclusion Attack||www.example.com|F|2`:     "attack-rfi",
		`COMODO WAF: OS Command Injection Attack||www.example.com|F|2`:      "attack-rce",
		`COMODO WAF: PHP Injection Attack||www.example.com|F|2`:             "attack-injection-php",
		`COMODO WAF: Possible Session Fixation Attack||www.example.com|F|2`: "attack-fixation",
		`COMODO WAF: Inbound Points Exceeded||www.example.com|F|2`:          "unknown",
		// The host after "||" is not read: a site called sqli-test.example must not classify.
		`COMODO WAF: Request content type is not allowed by policy||sqli-test.example|F|2`: "unknown",
	}
	for msg, want := range cases {
		e := AuditEntry{Rules: []RuleMatch{{ID: "218500", Msg: msg, Tags: []string{"CWAF", "Generic"}}}}
		if got := e.AttackCategory(); got != want {
			t.Errorf("%q: %q, want %q", msg, got, want)
		}
		if e.Ruleset() != "comodo" {
			t.Errorf("%q: ruleset %q", msg, e.Ruleset())
		}
	}
	if got := MapAttackToEventType("attack-sqli"); got != "sql_injection" {
		t.Errorf("mapping: %s", got)
	}
}

func TestCRSTagsWinOverComodo(t *testing.T) {
	e := AuditEntry{Rules: []RuleMatch{
		{ID: "942100", Msg: "SQL Injection Attack Detected via libinjection", Tags: []string{"OWASP_CRS", "attack-sqli"}},
	}}
	if e.AttackCategory() != "attack-sqli" || e.Ruleset() != "" {
		t.Errorf("CRS: %q %q", e.AttackCategory(), e.Ruleset())
	}
	// Not Comodo, no tag: unknown even if the message names an attack.
	e = AuditEntry{Rules: []RuleMatch{{ID: "1000", Msg: "custom XSS rule"}}}
	if e.AttackCategory() != "unknown" {
		t.Errorf("custom: %q", e.AttackCategory())
	}
}
