package watcher

import "testing"

func TestCustomPatternsAddToBuiltIn(t *testing.T) {
	w := &Watcher{}
	defer w.SetCustomPatterns(nil)

	builtin := "Failed password for root from 203.0.113.9 port 4242 ssh2"
	custom := "myapp: rejected login from 198.51.100.7"

	if ip, _ := matchSSH(custom); ip != "" {
		t.Fatalf("custom line matched before any custom pattern: %s", ip)
	}
	p := ParsePattern(`rejected login from ([\d.]+)`, "")
	if p == nil {
		t.Fatal("valid pattern rejected")
	}
	w.SetCustomPatterns([]SSHPattern{*p})

	if ip, reason := matchSSH(custom); ip != "198.51.100.7" || reason != "brute_force_ssh" {
		t.Fatalf("custom: ip=%q reason=%q", ip, reason)
	}
	if ip, _ := matchSSH(builtin); ip != "203.0.113.9" {
		t.Fatalf("built-in patterns must keep working, got %q", ip)
	}

	w.SetCustomPatterns(nil)
	if ip, _ := matchSSH(custom); ip != "" {
		t.Fatal("empty list must remove custom patterns")
	}
	if ip, _ := matchSSH(builtin); ip != "203.0.113.9" {
		t.Fatal("built-in lost after clearing")
	}
}

func TestParsePatternRequiresIPGroup(t *testing.T) {
	if ParsePattern(`rejected login`, "x") != nil {
		t.Fatal("pattern without capture group must be refused")
	}
	if ParsePattern(`(`, "x") != nil {
		t.Fatal("invalid regex must be refused")
	}
}
