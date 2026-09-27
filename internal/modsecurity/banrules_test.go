package modsecurity

import (
	"strconv"
	"strings"
	"testing"
)

func TestBanRulesValidatesAndGroups(t *testing.T) {
	ips := []string{"203.0.113.5", "203.0.113.5", "198.51.100.0/24", "2001:db8::1",
		`1.2.3.4" "id:1,pass`, "not-an-ip", ""}
	got := banRules(ips)
	if strings.Contains(got, "not-an-ip") || strings.Contains(got, "pass") {
		t.Fatalf("invalid input reached the config:\n%s", got)
	}
	if n := strings.Count(got, "SecRule"); n != 1 {
		t.Fatalf("want 1 rule, got %d:\n%s", n, got)
	}
	if !strings.Contains(got, "@ipMatch 198.51.100.0/24,2001:db8::1,203.0.113.5") {
		t.Fatalf("got:\n%s", got)
	}
}

func TestBanRulesChunksAndEmpty(t *testing.T) {
	var ips []string
	for i := 0; i < 250; i++ {
		ips = append(ips, "10.0."+strconv.Itoa(i/256)+"."+strconv.Itoa(i%256))
	}
	got := banRules(ips)
	if n := strings.Count(got, "SecRule"); n != 3 {
		t.Fatalf("want 3 rules, got %d", n)
	}
	for _, id := range []string{"id:9900001", "id:9900002", "id:9900003"} {
		if !strings.Contains(got, id) {
			t.Fatalf("missing %s", id)
		}
	}
	if empty := banRules(nil); strings.Contains(empty, "SecRule") {
		t.Fatalf("empty list must clear the rules: %q", empty)
	}
}
