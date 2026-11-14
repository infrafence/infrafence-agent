package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// validReport is a complete report as Collect builds it.
func validReport() *Report {
	return &Report{
		Schema:       Schema,
		AgentVersion: "1.0.44",
		GeneratedAt:  time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC).Format(time.RFC3339),
		OS:           OS{ID: "ubuntu", Version: "24.04", Kernel: "6.8.0-48-generic", Arch: "amd64"},
		Environment:  Environment{Panel: "none", WebServer: "nginx", Containers: true},
		Checks: []Check{
			{ID: IDSSHPasswordAuth, Status: StatusFail, Severity: SevHigh, Facts: map[string]string{"value": "yes"}},
		},
		Listening: []Listener{{Port: 3306, Proto: "tcp", Process: "mysqld", Public: true}},
		Updates:   Updates{Security: intp(12), Total: intp(40), RebootRequired: true},
		Attacks: Attacks{WindowHours: 24, SSHFailedLogins: 3412, SSHUniqueIPs: 187, WebSuspiciousRequests: 220, WebUniqueIPs: 41,
			TopIPs: []TopIP{{IP: "203.0.113.5", Count: 820, Kind: "ssh"}}},
		Protection: Protection{Firewall: "nftables"},
	}
}

var private = Private{
	Hostnames: []string{"web01.shop-rossi.it", "web01"},
	IPs:       []string{"198.51.100.23", "2001:db8:42::23", "10.0.0.5", "127.0.0.1"},
	Users:     []string{"mrossi", "deploy"},
}

// TestPrivacyFilter puts every kind of private value the contract forbids
// in every string field of a report and checks that none survives.
func TestPrivacyFilter(t *testing.T) {
	r := validReport()
	leaks := []string{
		"web01.shop-rossi.it", "web01", "198.51.100.23", "2001:db8:42::23", "10.0.0.5",
		"mrossi", "deploy", "/home/", "hunter2", "BEGIN OPENSSH PRIVATE KEY", "AKIAIOSFODNN7EXAMPLE",
		"ghp_abcdefghijklmnopqrstuvwxyz0123456789", "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHNlY3JldCB0b2tlbg",
		"admin@shop-rossi.it", "s3cr3t",
	}
	r.Checks = append(r.Checks, Check{ID: "x.privacy", Status: StatusInfo, Severity: SevInfo, Facts: map[string]string{
		"host":     "served by web01.shop-rossi.it",
		"short":    "WEB01 ready",
		"ip":       "bound to 198.51.100.23:3306",
		"ip6":      "[2001:db8:42::23]:22",
		"private":  "10.0.0.5",
		"user":     "owned by mrossi",
		"user2":    "deploy",
		"home":     "/home/site/public_html/.env",
		"pw":       "password=hunter2",
		"key":      "-----BEGIN OPENSSH PRIVATE KEY-----",
		"aws":      "AKIAIOSFODNN7EXAMPLE",
		"gh":       "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
		"b64":      "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHNlY3JldCB0b2tlbg",
		"mail":     "admin@shop-rossi.it",
		"url":      "mysql://app:s3cr3t@db/x",
		"Bad-Key!": "dropped",
	}})
	r.Listening = append(r.Listening, Listener{Port: 8080, Proto: "tcp", Process: "web01-app"})
	r.OS.Kernel = "6.8.0-web01"
	r.Environment.WebServer = "nginx (198.51.100.23)"
	r.Attacks.TopIPs = append(r.Attacks.TopIPs,
		TopIP{IP: "198.51.100.23", Count: 5, Kind: "web"}, // the server itself
		TopIP{IP: "10.0.0.9", Count: 4, Kind: "ssh"},      // private
		TopIP{IP: "127.0.0.1", Count: 3, Kind: "ssh"},     // loopback
		TopIP{IP: "2001:db8:42::23", Count: 2, Kind: "web"},
	)

	Sanitize(r, private)
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	out := strings.ToLower(string(b))
	for _, l := range leaks {
		if strings.Contains(out, strings.ToLower(l)) {
			t.Errorf("%q survived the privacy filter: %s", l, b)
		}
	}
	// What is allowed stays: the attacker, ordinary facts, root.
	if len(r.Attacks.TopIPs) != 1 || r.Attacks.TopIPs[0].IP != "203.0.113.5" {
		t.Errorf("top ips %+v", r.Attacks.TopIPs)
	}
	if r.Checks[0].Facts["value"] != "yes" || r.OS.ID != "ubuntu" || r.Listening[0].Process != "mysqld" {
		t.Errorf("an ordinary value was removed: %s", b)
	}
	if _, ok := r.Checks[1].Facts["Bad-Key!"]; ok {
		t.Errorf("an invalid fact key was kept")
	}
	if err := r.Validate(); err != nil {
		t.Errorf("sanitized report invalid: %v", err)
	}
}

func TestPrivacyKeepsOrdinaryValues(t *testing.T) {
	f := newFilter(Private{Hostnames: []string{"srv", "localhost"}, Users: []string{"ubuntu-admin"}, IPs: []string{"203.0.113.1"}})
	for _, v := range []string{"yes", "prohibit-password", "MySQL/MariaDB", "all_addresses", "/etc/ssh/sshd_config.d/50-cloud-init.conf:2",
		"allow_url_include,display_errors", "/usr/lib/x86_64-linux-gnu/some-long-library-name.so", "sshd -T", "root"} {
		if got := f.text(v); got != v {
			t.Errorf("%q became %q", v, got)
		}
	}
	long := strings.Repeat("é", 150)
	if got := f.text(long); len(got) > maxFactValue || !strings.HasPrefix(long, got) {
		t.Errorf("not cut at %d bytes on a character boundary: %d bytes", maxFactValue, len(got))
	}
	if got := f.text("a\x1b[31mb\nc"); got != "a[31mbc" {
		t.Errorf("control characters kept: %q", got)
	}
}

func TestHostPrivateReadsLoginUsers(t *testing.T) {
	dir := t.TempDir()
	passwd := filepath.Join(dir, "passwd")
	must(t, os.WriteFile(passwd, []byte("root:x:0:0:root:/root:/bin/bash\n"+
		"daemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n"+
		"toor:x:0:0::/root:/bin/sh\n"+
		"nginx:x:998:996::/var/lib/nginx:/sbin/nologin\n"+
		"mrossi:x:1000:1000::/home/mrossi:/bin/bash\n"+
		"nobody:x:65534:65534::/:/usr/sbin/nologin\n"), 0o600))
	got := loginUsers(passwd, 1000)
	sort.Strings(got)
	if !reflect.DeepEqual(got, []string{"mrossi", "toor"}) {
		t.Errorf("login users %v", got)
	}
}

// TestSchemaFields: the JSON names are the contract's, exactly.
func TestSchemaFields(t *testing.T) {
	b, err := json.Marshal(validReport())
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	keys := func(v any) []string {
		var out []string
		for k := range v.(map[string]any) {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	check := func(name string, got, want []string) {
		t.Helper()
		sort.Strings(want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: %v, want %v", name, got, want)
		}
	}
	check("report", keys(m), []string{"schema", "agent_version", "generated_at", "os", "environment", "checks", "listening", "updates", "attacks", "protection"})
	check("os", keys(m["os"]), []string{"id", "version", "kernel", "arch"})
	check("environment", keys(m["environment"]), []string{"panel", "web_server", "containers"})
	check("check", keys(m["checks"].([]any)[0]), []string{"id", "status", "severity", "facts"})
	check("listening", keys(m["listening"].([]any)[0]), []string{"port", "proto", "process", "public"})
	check("updates", keys(m["updates"]), []string{"security", "total", "reboot_required"})
	check("attacks", keys(m["attacks"]), []string{"window_hours", "ssh_failed_logins", "ssh_unique_ips", "web_suspicious_requests", "web_unique_ips", "top_ips"})
	check("top_ip", keys(m["attacks"].(map[string]any)["top_ips"].([]any)[0]), []string{"ip", "count", "kind"})
	check("protection", keys(m["protection"]), []string{"firewall", "fail2ban", "csf", "infrafence"})
	if m["schema"].(float64) != 1 {
		t.Errorf("schema %v", m["schema"])
	}
}

func TestValidate(t *testing.T) {
	if err := validReport().Validate(); err != nil {
		t.Fatalf("valid report: %v", err)
	}
	// Unknown updates are null, not a number.
	r := validReport()
	r.Updates = Updates{}
	if err := r.Validate(); err != nil {
		t.Errorf("unknown updates: %v", err)
	}
	b, _ := json.Marshal(r.Updates)
	if string(b) != `{"security":null,"total":null,"reboot_required":false}` {
		t.Errorf("unknown updates encode as %s", b)
	}
	for name, mutate := range map[string]func(*Report){
		"schema":        func(r *Report) { r.Schema = 2 },
		"version":       func(r *Report) { r.AgentVersion = "" },
		"time":          func(r *Report) { r.GeneratedAt = "yesterday" },
		"check id":      func(r *Report) { r.Checks[0].ID = "SSH_PASSWORD_AUTH" },
		"status":        func(r *Report) { r.Checks[0].Status = "bad" },
		"severity":      func(r *Report) { r.Checks[0].Severity = "urgent" },
		"nil facts":     func(r *Report) { r.Checks[0].Facts = nil },
		"long fact":     func(r *Report) { r.Checks[0].Facts["value"] = strings.Repeat("x", 201) },
		"fact key":      func(r *Report) { r.Checks[0].Facts["Value"] = "x" },
		"port":          func(r *Report) { r.Listening[0].Port = 0 },
		"proto":         func(r *Report) { r.Listening[0].Proto = "udp" },
		"window":        func(r *Report) { r.Attacks.WindowHours = 48 },
		"top ip":        func(r *Report) { r.Attacks.TopIPs[0].IP = "host.example" },
		"kind":          func(r *Report) { r.Attacks.TopIPs[0].Kind = "ftp" },
		"firewall":      func(r *Report) { r.Protection.Firewall = "pf" },
		"null checks":   func(r *Report) { r.Checks = nil },
		"negative":      func(r *Report) { r.Updates.Total = intp(-1) },
		"too many ips":  func(r *Report) { r.Attacks.TopIPs = make([]TopIP, 11) },
		"too large":     func(r *Report) { r.Listening = make([]Listener, 101) },
		"no arch":       func(r *Report) { r.OS.Arch = "" },
		"null top ips":  func(r *Report) { r.Attacks.TopIPs = nil },
		"null listen":   func(r *Report) { r.Listening = nil },
		"many facts":    func(r *Report) { manyFacts(r.Checks[0].Facts) },
		"check id case": func(r *Report) { r.Checks[0].ID = "ssh" },
	} {
		r := validReport()
		mutate(r)
		if err := r.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func manyFacts(m map[string]string) {
	for i := 0; i < 13; i++ {
		m["k"+string(rune('a'+i))] = "v"
	}
}

func TestOSTokens(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"24.04", "24.04"},
		{"2023", "2023"},
		{"", ""},
		{"6.8.0-48-generic", "6.8.0-48-generic"},
		{"4.18.0-553.el8_10.x86_64", "4.18.0-553.el8_10.x86_64"},
		{"6.1.0-28-cloud-amd64", "6.1.0-28-cloud-amd64"},
		{"5.15.0+rpt-rpi-v8", "5.15.0+rpt-rpi-v8"},
		{"7.2.12-orbstack-00394-gbecdd6130068", "7.2.12-orbstack-00394-gbecdd6130068"},
		{"6.8.0 generic", Redacted},
		{"6.8.0/../../etc", Redacted},
		{`6.8.0"<script>`, Redacted},
		{"24.04; rm -rf", Redacted},
		{strings.Repeat("a", 65), Redacted},
		{"6.8.0-é", Redacted},
	} {
		r := validReport()
		r.OS.Version, r.OS.Kernel = tc.in, tc.in
		Sanitize(r, Private{})
		if r.OS.Version != tc.want || r.OS.Kernel != tc.want {
			t.Errorf("%q: version %q kernel %q, want %q", tc.in, r.OS.Version, r.OS.Kernel, tc.want)
		}
	}
	// A token that names the host is still redacted.
	r := validReport()
	r.OS.Kernel = "6.8.0-web01"
	Sanitize(r, Private{Hostnames: []string{"web01"}})
	if r.OS.Kernel != Redacted {
		t.Errorf("kernel with the host name: %q", r.OS.Kernel)
	}
}
