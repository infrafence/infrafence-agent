package sshdconfig

import (
	"errors"
	"path/filepath"
	"sort"
	"testing"
)

type mapFS map[string]string

func (m mapFS) ReadFile(p string) ([]byte, error) {
	if s, ok := m[p]; ok {
		return []byte(s), nil
	}
	return nil, errors.New("not found")
}

func (m mapFS) Glob(pattern string) ([]string, error) {
	var out []string
	for p := range m {
		if ok, _ := filepath.Match(pattern, p); ok {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out, nil
}

// A fresh Ubuntu cloud image: the cloud-init drop-in turns password logins
// back on although sshd_config says no, because sshd_config includes the
// drop-ins first and the first value wins.
func TestCloudInitDropInWins(t *testing.T) {
	fs := mapFS{
		MainFile: "# comment\nInclude /etc/ssh/sshd_config.d/*.conf\n\nPasswordAuthentication no\nPermitRootLogin=no\nX11Forwarding yes\n",
		"/etc/ssh/sshd_config.d/50-cloud-init.conf": "PasswordAuthentication yes\n",
		"/etc/ssh/sshd_config.d/60-other.conf":      "PasswordAuthentication no\nMaxAuthTries 3\n",
		"/etc/ssh/sshd_config.d/README":             "PasswordAuthentication no\n",
	}
	cfg, ok := Parse(fs)
	if !ok {
		t.Fatal("not parsed")
	}
	pa, _ := cfg.Get("PasswordAuthentication")
	if pa.Value != "yes" || pa.Where() != "/etc/ssh/sshd_config.d/50-cloud-init.conf:1" || !pa.DropIn() {
		t.Fatalf("PasswordAuthentication: %+v", pa)
	}
	if s, _ := cfg.Get("permitrootlogin"); s.Value != "no" || s.Where() != MainFile+":5" || s.DropIn() {
		t.Fatalf("PermitRootLogin: %+v", s)
	}
	if s, _ := cfg.Get("MaxAuthTries"); s.Value != "3" || s.Line != 2 {
		t.Fatalf("MaxAuthTries: %+v", s)
	}
}

// An Include at the end (older layouts): sshd_config's own value wins.
func TestIncludeAtTheEnd(t *testing.T) {
	fs := mapFS{
		MainFile: "PasswordAuthentication no\nInclude sshd_config.d/*.conf\n",
		"/etc/ssh/sshd_config.d/50-cloud-init.conf": "PasswordAuthentication yes\n",
	}
	cfg, _ := Parse(fs)
	if s, _ := cfg.Get("PasswordAuthentication"); s.Value != "no" || s.Where() != MainFile+":1" {
		t.Fatalf("got %+v", s)
	}
}

// Match blocks are not the global value; an Include loop ends.
func TestMatchAndLoops(t *testing.T) {
	fs := mapFS{
		MainFile:              "Include /etc/ssh/loop.conf\nMatch User backup\n  PasswordAuthentication yes\nInclude /etc/ssh/never.conf\n",
		"/etc/ssh/loop.conf":  "Include /etc/ssh/loop.conf\nX11Forwarding no\n",
		"/etc/ssh/never.conf": "PermitRootLogin yes\n",
	}
	cfg, _ := Parse(fs)
	if _, ok := cfg.Get("PasswordAuthentication"); ok {
		t.Fatal("value inside Match taken as global")
	}
	if _, ok := cfg.Get("PermitRootLogin"); ok {
		t.Fatal("Include inside Match read")
	}
	if s, _ := cfg.Get("X11Forwarding"); s.Value != "no" || s.File != "/etc/ssh/loop.conf" {
		t.Fatalf("got %+v", s)
	}
	if _, ok := Parse(mapFS{}); ok {
		t.Fatal("parsed without sshd_config")
	}
}

func TestFields(t *testing.T) {
	for line, want := range map[string][2]string{
		"  Port 2222":           {"port", "2222"},
		"PermitRootLogin=no":    {"permitrootlogin", "no"},
		"Banner = \"/etc/a b\"": {"banner", "/etc/a b"},
		"# PermitRootLogin no":  {"", ""},
	} {
		k, a := fields(line)
		got := [2]string{k, ""}
		if len(a) > 0 {
			got[1] = a[0]
		}
		if got != want {
			t.Errorf("%q: %v, want %v", line, got, want)
		}
	}
	if !Same("PermitRootLogin", "without-password", "prohibit-password") || Same("PasswordAuthentication", "yes", "no") {
		t.Fatal("Same")
	}
}
