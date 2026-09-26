package webserver

import "testing"

func TestInjectedLineRoundTrip(t *testing.T) {
	orig := "server {\n    listen 80;\n}\n\n  server {\n    listen 443;\n  }\n"
	injected := injectIfIntoServerBlock(orig)
	if injected == orig || !injectedLine.MatchString(injected) {
		t.Fatalf("injection did not happen:\n%s", injected)
	}
	if got := injectedLine.ReplaceAllString(injected, ""); got != orig {
		t.Errorf("removal is not the exact inverse:\n--- got\n%q\n--- want\n%q", got, orig)
	}
}

func TestRemovalLeavesSimilarCustomerLinesAlone(t *testing.T) {
	cust := "server {\n    if ($bad_ua) { return 444; } # customer\n}\n"
	if injectedLine.MatchString(cust) {
		t.Error("removal would touch a customer's own line")
	}
}
