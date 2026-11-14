package audit

import (
	"strings"
	"testing"

	"github.com/infrafence/infrafence-agent/internal/phpconf"
	"github.com/infrafence/infrafence-agent/internal/scanner"
	"github.com/infrafence/infrafence-agent/internal/watcher"
)

func byID(cs []Check, id string) []Check {
	var out []Check
	for _, c := range cs {
		if c.ID == id {
			out = append(out, c)
		}
	}
	return out
}

func one(t *testing.T, cs []Check, id string) Check {
	t.Helper()
	got := byID(cs, id)
	if len(got) != 1 {
		t.Fatalf("%s: %d checks, want 1 (%+v)", id, len(got), cs)
	}
	return got[0]
}

func want(t *testing.T, c Check, status, sev string) {
	t.Helper()
	if c.Status != status || c.Severity != sev {
		t.Errorf("%s: %s/%s, want %s/%s (facts %v)", c.ID, c.Status, c.Severity, status, sev, c.Facts)
	}
}

func sshFinding(id, sev, value string, passed bool, extra map[string]string) scanner.Finding {
	d := map[string]string{"value": value, "effective_from": "sshd -T"}
	for k, v := range extra {
		d[k] = v
	}
	return scanner.Finding{CheckID: id, Severity: sev, Passed: passed, Details: d}
}

func TestMapSSH(t *testing.T) {
	fs := []scanner.Finding{
		sshFinding("SSH_ROOT_LOGIN", "critical", "yes", false, map[string]string{"source": "/etc/ssh/sshd_config.d/50-cloud-init.conf:2"}),
		sshFinding("SSH_PASSWORD_AUTH", "high", "yes", false, map[string]string{"source": "/home/bob/sshd.conf:1"}),
		sshFinding("SSH_DEFAULT_PORT", "low", "22", false, map[string]string{"port": "22"}),
	}
	cs := MapSSH(fs, true)
	root := one(t, cs, IDSSHRootLogin)
	want(t, root, StatusFail, SevCritical)
	if root.Facts["value"] != "yes" || root.Facts["source"] != "/etc/ssh/sshd_config.d/50-cloud-init.conf:2" {
		t.Errorf("root facts %v", root.Facts)
	}
	pw := one(t, cs, IDSSHPasswordAuth)
	want(t, pw, StatusFail, SevHigh)
	if _, ok := pw.Facts["source"]; ok {
		t.Errorf("a source outside /etc/ssh is not reported: %v", pw.Facts)
	}
	want(t, one(t, cs, IDSSHDefaultPortOpen), StatusWarn, SevLow)

	// Hardened: keys only, root by key, port 22 not reachable.
	fs = []scanner.Finding{
		sshFinding("SSH_ROOT_LOGIN", "critical", "prohibit-password", true, nil),
		sshFinding("SSH_PASSWORD_AUTH", "high", "no", true, nil),
		sshFinding("SSH_DEFAULT_PORT", "low", "2222", true, map[string]string{"port": "2222"}),
	}
	cs = MapSSH(fs, false)
	want(t, one(t, cs, IDSSHRootLogin), StatusPass, SevCritical)
	want(t, one(t, cs, IDSSHPasswordAuth), StatusPass, SevHigh)
	p := one(t, cs, IDSSHDefaultPortOpen)
	want(t, p, StatusPass, SevLow)
	if p.Facts["configured_port"] != "2222" || p.Facts["port_22_public"] != "false" {
		t.Errorf("port facts %v", p.Facts)
	}

	// Unreadable configuration: unknown, not a pass.
	cs = MapSSH([]scanner.Finding{{CheckID: "SSH_CONFIG_READ", Severity: "info", Passed: true}}, false)
	want(t, one(t, cs, IDSSHPasswordAuth), StatusInfo, SevInfo)
	want(t, one(t, cs, IDSSHRootLogin), StatusInfo, SevInfo)
}

func TestMapExposed(t *testing.T) {
	db := []watcher.ExposedDBPort{{Port: 3306, Service: "MySQL/MariaDB", BindAddress: "0.0.0.0:3306"}, {Port: 5432, Service: "PostgreSQL", BindAddress: "198.51.100.7:5432"}}
	admin := []watcher.ExposedDBPort{{Port: 6379, Service: "Redis", BindAddress: "[::]:6379"}, {Port: 15672, Service: "RabbitMQ management", BindAddress: "0.0.0.0:15672"}}
	cs := MapExposed(db, admin)
	dbs := byID(cs, IDDBPublic)
	if len(dbs) != 2 {
		t.Fatalf("one db check per port: %+v", dbs)
	}
	want(t, dbs[0], StatusFail, SevHigh)
	if dbs[0].Facts["port"] != "3306" || dbs[0].Facts["bind"] != "all_addresses" || dbs[1].Facts["bind"] != "public_address" {
		t.Errorf("db facts %v %v", dbs[0].Facts, dbs[1].Facts)
	}
	for _, c := range cs {
		for _, v := range c.Facts {
			if strings.Contains(v, "198.51.100.7") {
				t.Errorf("a server address in the facts: %v", c.Facts)
			}
		}
	}
	admins := byID(cs, IDAdminPublic)
	want(t, admins[0], StatusFail, SevCritical) // Redis
	want(t, admins[1], StatusFail, SevHigh)     // RabbitMQ

	cs = MapExposed(nil, nil)
	want(t, one(t, cs, IDDBPublic), StatusPass, SevHigh)
	want(t, one(t, cs, IDAdminPublic), StatusPass, SevHigh)
}

func intp(n int) *int { return &n }

func TestMapUpdates(t *testing.T) {
	cs := MapUpdates(Updates{Security: intp(12), Total: intp(40), RebootRequired: true}, "apt", "ubuntu", "20.04", true)
	sec := one(t, cs, IDUpdatesSecurity)
	want(t, sec, StatusFail, SevCritical)
	if sec.Facts["count"] != "12" || sec.Facts["total"] != "40" {
		t.Errorf("facts %v", sec.Facts)
	}
	want(t, one(t, cs, IDRebootRequired), StatusWarn, SevMedium)
	want(t, one(t, cs, IDOSEOL), StatusFail, SevCritical)

	cs = MapUpdates(Updates{Security: intp(3), Total: intp(3)}, "dnf", "rocky", "9.4", false)
	want(t, one(t, cs, IDUpdatesSecurity), StatusFail, SevHigh)
	want(t, one(t, cs, IDRebootRequired), StatusPass, SevMedium)
	want(t, one(t, cs, IDOSEOL), StatusPass, SevCritical)

	cs = MapUpdates(Updates{Security: intp(0), Total: intp(5)}, "apt", "debian", "12", false)
	want(t, one(t, cs, IDUpdatesSecurity), StatusPass, SevHigh)

	cs = MapUpdates(Updates{}, "dnf", "fedora", "42", true)
	c := one(t, cs, IDUpdatesSecurity)
	want(t, c, StatusInfo, SevInfo)
	if c.Facts["reason"] != "package_cache_unavailable" {
		t.Errorf("facts %v", c.Facts)
	}
}

func TestOSEndOfLife(t *testing.T) {
	for _, tc := range []struct {
		id, v string
		eol   bool
	}{
		{"ubuntu", "20.04", true}, {"ubuntu", "22.04", false}, {"ubuntu", "24.04", false},
		{"debian", "11", true}, {"debian", "12", false}, {"centos", "7", true},
		{"rocky", "8.10", false}, {"fedora", "41", true}, {"fedora", "43", false},
		{"amzn", "2023", false}, {"amzn", "2", true},
	} {
		if got := scanner.OSEndOfLife(tc.id, tc.v); got != tc.eol {
			t.Errorf("%s %s: eol %v, want %v", tc.id, tc.v, got, tc.eol)
		}
	}
}

func TestMapProtection(t *testing.T) {
	cs := MapProtection(Protection{Firewall: "none"}, false)
	want(t, one(t, cs, IDFirewallNone), StatusFail, SevHigh)
	want(t, one(t, cs, IDBruteforceNoProtect), StatusFail, SevHigh)

	cs = MapProtection(Protection{Firewall: "ufw", Fail2ban: true}, false)
	want(t, one(t, cs, IDFirewallNone), StatusPass, SevHigh)
	b := one(t, cs, IDBruteforceNoProtect)
	want(t, b, StatusPass, SevHigh)
	if b.Facts["tools"] != "fail2ban" {
		t.Errorf("tools %v", b.Facts)
	}
	for _, p := range []Protection{{Firewall: "iptables", CSF: true}, {Firewall: "nftables", InfraFence: true}} {
		want(t, one(t, MapProtection(p, false), IDBruteforceNoProtect), StatusPass, SevHigh)
	}
	want(t, one(t, MapProtection(Protection{Firewall: "nftables"}, true), IDBruteforceNoProtect), StatusPass, SevHigh)
}

func TestMapUsers(t *testing.T) {
	cs := MapUsers([]scanner.Finding{
		{CheckID: "USERS_UID0", Severity: "critical", Passed: false, Details: map[string]string{"count": "1"}},
		{CheckID: "USERS_EMPTY_PW", Severity: "critical", Passed: true, Details: map[string]string{"count": "0"}},
	})
	u := one(t, cs, IDUsersUID0Extra)
	want(t, u, StatusFail, SevCritical)
	if u.Facts["count"] != "1" {
		t.Errorf("facts %v", u.Facts)
	}
	want(t, one(t, cs, IDUsersEmptyPassword), StatusPass, SevCritical)
	// /etc/shadow unreadable: no USERS_EMPTY_PW finding.
	cs = MapUsers([]scanner.Finding{{CheckID: "USERS_UID0", Passed: true, Details: map[string]string{"count": "0"}}})
	want(t, one(t, cs, IDUsersEmptyPassword), StatusInfo, SevInfo)
}

func TestMapFiles(t *testing.T) {
	sshdFail := []scanner.Finding{{CheckID: "PERM_SSHD_CONFIG", Severity: "high", Passed: false}}
	c := MapFilePermissions(append([]scanner.Finding{
		{CheckID: "PERM_SHADOW", Severity: "critical", Passed: false},
		{CheckID: "PERM_PASSWD", Severity: "high", Passed: true},
	}, sshdFail...), FileMeta{Exists: true, Perm: 0o664})
	want(t, c, StatusFail, SevCritical)
	if c.Facts["files"] != "shadow,sshd_config" {
		t.Errorf("facts %v", c.Facts)
	}
	want(t, MapFilePermissions(nil, FileMeta{}), StatusPass, SevHigh)
	// sshd_config: the scanner's 0600 is not the audit's rule. World-readable
	// (Ubuntu's 0644) passes; group or other writable, or not root's, fails.
	for _, tc := range []struct {
		m    FileMeta
		fail bool
	}{
		{FileMeta{Exists: true, Perm: 0o644}, false},
		{FileMeta{Exists: true, Perm: 0o600}, false},
		{FileMeta{Exists: true, Perm: 0o604}, false},
		{FileMeta{Exists: true, Perm: 0o664}, true},
		{FileMeta{Exists: true, Perm: 0o646}, true},
		{FileMeta{Exists: true, Perm: 0o600, UID: 1000}, true},
		{FileMeta{Exists: true, Perm: 0o600, UID: -1}, true},
		{FileMeta{}, false},
	} {
		c := MapFilePermissions(sshdFail, tc.m)
		if got := c.Status == StatusFail; got != tc.fail {
			t.Errorf("sshd_config %+v: fail=%v, want %v (%v)", tc.m, got, tc.fail, c.Facts)
		}
	}

	paths := []string{"/etc/nginx/conf.d/shop-rossi.it.conf", "/etc/b", "/usr/bin/x", "/usr/local/bin/y"}
	w := MapWorldWritable(topDirs(paths, worldWritableRoots), 1000, true)
	want(t, w, StatusFail, SevHigh)
	if w.Facts["count"] != "4" || w.Facts["dirs"] != "/etc,/usr/bin,/usr/local/bin" {
		t.Errorf("facts %v", w.Facts)
	}
	for _, v := range w.Facts {
		if strings.Contains(v, "shop-rossi") {
			t.Errorf("a file name was reported: %v", w.Facts)
		}
	}
	want(t, MapWorldWritable(nil, 1000, true), StatusPass, SevHigh)
}

func TestMapPHP(t *testing.T) {
	want(t, MapPHP(0, nil), StatusInfo, SevInfo)
	fs := []phpconf.Finding{
		{CheckID: "PHP_ALLOW_URL_INCLUDE@debian-8.2-fpm", Severity: "critical", Passed: false, Details: map[string]string{"directive": "allow_url_include"}},
		{CheckID: "PHP_DISPLAY_ERRORS@debian-8.2-fpm", Severity: "high", Passed: false, Details: map[string]string{"directive": "display_errors"}},
		{CheckID: "PHP_DISPLAY_ERRORS@debian-8.3-fpm", Severity: "high", Passed: false, Details: map[string]string{"directive": "display_errors"}},
		{CheckID: "PHP_EXPOSE_PHP@debian-8.2-fpm", Severity: "low", Passed: false, Details: map[string]string{"directive": "expose_php"}},
		{CheckID: "PHP_OPEN_BASEDIR@debian-8.2-fpm", Severity: "medium", Passed: true, Details: map[string]string{"directive": "open_basedir"}},
	}
	c := MapPHP(2, fs)
	want(t, c, StatusFail, SevCritical)
	if c.Facts["settings"] != "allow_url_include,display_errors" || c.Facts["runtimes"] != "2" {
		t.Errorf("facts %v", c.Facts)
	}
	c = MapPHP(1, []phpconf.Finding{{Severity: "medium", Details: map[string]string{"directive": "session.cookie_secure"}}})
	want(t, c, StatusWarn, SevMedium)
	want(t, MapPHP(1, fs[4:]), StatusPass, SevHigh)
}
