package preflight

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

type fakeEnv struct {
	root  bool
	bins  map[string]bool
	files map[string]string
	runs  map[string]string // "name args" -> output; missing = error
}

func (f fakeEnv) Run(name string, args ...string) (string, error) {
	if out, ok := f.runs[strings.TrimSpace(name+" "+strings.Join(args, " "))]; ok {
		return out, nil
	}
	return "", errors.New("exit 1")
}
func (f fakeEnv) LookPath(n string) bool { return f.bins[n] }
func (f fakeEnv) ReadFile(p string) (string, error) {
	if s, ok := f.files[p]; ok {
		return s, nil
	}
	return "", errors.New("not found")
}
func (f fakeEnv) Exists(p string) bool { _, ok := f.files[p]; return ok }
func (f fakeEnv) Glob(pat string) []string {
	var out []string
	for p := range f.files {
		if ok, _ := filepath.Match(pat, p); ok {
			out = append(out, p)
		}
	}
	return out
}
func (f fakeEnv) IsRoot() bool { return f.root }

// ubuntu returns a plain Ubuntu host with nginx, iptables-nft and apt.
func ubuntu() fakeEnv {
	return fakeEnv{
		root: true,
		bins: map[string]bool{"systemctl": true, "iptables": true, "iptables-restore": true, "nginx": true, "apt-get": true, "pgrep": true},
		files: map[string]string{
			"/etc/os-release":            `PRETTY_NAME="Ubuntu 24.04.5 LTS"`,
			"/run/systemd/system":        "",
			"/etc/nginx/nginx.conf":      "http { include /etc/nginx/sites-enabled/*; }",
			"/etc/nginx/sites-enabled/x": "server { listen 80; }",
		},
		runs: map[string]string{
			"iptables -V":       "iptables v1.8.10 (nf_tables)",
			"iptables -S INPUT": "-P INPUT ACCEPT",
		},
	}
}

func finding(r Report, id string) *Finding {
	for i := range r.Findings {
		if r.Findings[i].ID == id {
			return &r.Findings[i]
		}
	}
	return nil
}

func TestPlainHost(t *testing.T) {
	r := ScanEnv(ubuntu())
	d := r.Decisions
	if !d.FirewallEnforcement || d.Ipset || !d.IpsetInstallSafe || !d.WebserverChangesSafe || d.Docker {
		t.Errorf("decisions: %+v", d)
	}
	if r.Facts["iptables_backend"] != "nf_tables" || r.Facts["os"] != "Ubuntu 24.04.5 LTS" || r.Facts["init"] != "systemd" {
		t.Errorf("facts: %+v", r.Facts)
	}
	if f := finding(r, "ipset"); f == nil || f.Level != Warn {
		t.Errorf("missing ipset warning: %+v", f)
	}
}

func TestPanelBlocksWebserverChanges(t *testing.T) {
	e := ubuntu()
	e.files["/usr/local/cpanel"] = ""
	r := ScanEnv(e)
	if r.Decisions.WebserverChangesSafe || !strings.Contains(r.Decisions.WebserverChangesReason, "cPanel") {
		t.Errorf("decisions: %+v", r.Decisions)
	}
}

func TestConfigManagementBlocksWebserverChanges(t *testing.T) {
	e := ubuntu()
	e.files["/etc/nginx/sites-enabled/x"] = "# Ansible managed\nserver { listen 80; }"
	r := ScanEnv(e)
	if r.Decisions.WebserverChangesSafe || finding(r, "config_mgmt") == nil {
		t.Errorf("config management not detected: %+v", r.Decisions)
	}
}

func TestOwnInjectedFileIsNotConfigManagement(t *testing.T) {
	e := ubuntu()
	e.files["/etc/nginx/conf.d/infrafence-ua-block.conf"] = "# DO NOT EDIT — managed by InfraFence"
	if !ScanEnv(e).Decisions.WebserverChangesSafe {
		t.Error("InfraFence's own file must not count as configuration management")
	}
}

func TestFirewallManagers(t *testing.T) {
	e := ubuntu()
	e.runs["systemctl is-active ufw"] = "active"
	e.runs["ufw status"] = "Status: active"
	e.runs["systemctl is-active firewalld"] = "active"
	e.files["/etc/firewalld/firewalld.conf"] = "FirewallBackend=iptables"
	e.runs["systemctl is-active docker"] = "active"
	e.files["/etc/csf/csf.conf"] = ""
	r := ScanEnv(e)
	if got := r.Facts["firewall_managers"]; got != "csf,docker,firewalld,ufw" {
		t.Errorf("managers = %q", got)
	}
	if f := finding(r, "firewalld"); f == nil || f.Level != Warn {
		t.Errorf("firewalld with iptables backend should warn: %+v", f)
	}
	if !r.Decisions.Docker {
		t.Error("docker not detected")
	}
}

func TestInactiveUfwIsIgnored(t *testing.T) {
	e := ubuntu()
	e.runs["systemctl is-active ufw"] = "active"
	e.runs["ufw status"] = "Status: inactive"
	if finding(ScanEnv(e), "ufw") != nil {
		t.Error("an installed but inactive ufw must not be reported as active")
	}
}

func TestPackageOperationRunning(t *testing.T) {
	e := ubuntu()
	e.runs["pgrep -x apt-get"] = "1234"
	r := ScanEnv(e)
	if r.Decisions.IpsetInstallSafe || finding(r, "pkg_busy") == nil {
		t.Errorf("must not install packages while apt-get runs: %+v", r.Decisions)
	}
}

// Found on a real Ubuntu 24.04 server: unattended-upgrade-shutdown
// --wait-for-signal runs permanently (process name "unattended-upgr") and
// holds no lock. It must not block package installs.
func TestIdleUnattendedUpgradesDaemonIsNotAnOperation(t *testing.T) {
	e := ubuntu()
	e.runs["pgrep -x unattended-upgr"] = "641"
	e.files["/var/lib/dpkg/lock-frontend"] = ""
	e.runs["stat -c %i /var/lib/dpkg/lock-frontend"] = "393219"
	e.files["/proc/locks"] = "1: POSIX  ADVISORY  WRITE 900 fd:01:111 0 EOF\n2: FLOCK  ADVISORY  WRITE 901 00:1a:222 0 EOF\n"
	r := ScanEnv(e)
	if !r.Decisions.IpsetInstallSafe || finding(r, "pkg_busy") != nil {
		t.Errorf("idle daemon counted as a package operation: %+v", r.Decisions)
	}
}

func TestHeldDpkgLockIsAnOperation(t *testing.T) {
	e := ubuntu()
	e.files["/var/lib/dpkg/lock-frontend"] = ""
	e.runs["stat -c %i /var/lib/dpkg/lock-frontend"] = "393219"
	e.files["/proc/locks"] = "1: POSIX  ADVISORY  WRITE 4242 fd:01:393219 0 EOF\n2: POSIX  ADVISORY  WRITE 900 fd:01:111 0 EOF\n"
	e.files["/proc/4242/comm"] = "unattended-upgr\n"
	r := ScanEnv(e)
	f := finding(r, "pkg_busy")
	if r.Decisions.IpsetInstallSafe || f == nil || !strings.Contains(f.Title, "unattended-upgr") {
		t.Errorf("held dpkg lock not detected: %+v %+v", r.Decisions, f)
	}
}

func TestNotRoot(t *testing.T) {
	e := ubuntu()
	e.root = false
	r := ScanEnv(e)
	if r.Decisions.FirewallEnforcement || r.Worst() != Block {
		t.Errorf("non-root must block enforcement: %+v worst=%s", r.Decisions, r.Worst())
	}
}

func TestNoIptables(t *testing.T) {
	e := ubuntu()
	delete(e.bins, "iptables")
	r := ScanEnv(e)
	if r.Decisions.FirewallEnforcement || finding(r, "iptables").Level != Block {
		t.Errorf("missing iptables must block enforcement: %+v", r.Decisions)
	}
}

func TestLiteSpeedEnterpriseBlocksWebserverChanges(t *testing.T) {
	// cPanel-less LiteSpeed Enterprise: httpd is present for its config,
	// but Apache must not be edited or reloaded.
	e := ubuntu()
	delete(e.bins, "nginx")
	e.bins["httpd"] = true
	e.files["/usr/local/lsws/bin/lshttpd"] = ""
	e.files["/usr/local/lsws/VERSION"] = "6.3.1\n"
	e.runs["pgrep -x litespeed"] = "4321"
	r := ScanEnv(e)
	if r.Decisions.WebserverChangesSafe || !strings.Contains(r.Decisions.WebserverChangesReason, "LiteSpeed") {
		t.Errorf("decisions: %+v", r.Decisions)
	}
	if r.Facts["web_servers"] != "httpd,litespeed" || r.Facts["litespeed"] != "enterprise 6.3.1 (running)" {
		t.Errorf("facts: %+v", r.Facts)
	}
	if f := finding(r, "litespeed"); f == nil || !strings.Contains(f.Detail, "Apache") {
		t.Errorf("finding: %+v", f)
	}
}

func TestOpenLiteSpeed(t *testing.T) {
	e := ubuntu()
	delete(e.bins, "nginx")
	e.files["/usr/local/lsws/bin/openlitespeed"] = ""
	e.files["/usr/local/lsws/bin/lshttpd"] = ""
	e.runs["pgrep -x openlitespeed"] = "99"
	r := ScanEnv(e)
	if r.Facts["web_servers"] != "openlitespeed" || r.Decisions.WebserverChangesSafe {
		t.Errorf("facts: %+v decisions: %+v", r.Facts, r.Decisions)
	}
	if got := detectLiteSpeed(e).Name(); got != "openlitespeed" {
		t.Errorf("name = %q", got)
	}
}

func TestLiteSpeedInstalledButApacheServes(t *testing.T) {
	// LiteSpeed switched off (e.g. on cPanel): Apache rules apply as usual.
	e := ubuntu()
	delete(e.bins, "nginx")
	e.bins["apache2"] = true
	e.files["/usr/local/lsws/bin/lshttpd"] = ""
	r := ScanEnv(e)
	if !r.Decisions.WebserverChangesSafe || finding(r, "litespeed") != nil {
		t.Errorf("stopped LiteSpeed must not veto: %+v", r.Decisions)
	}
	if r.Facts["litespeed"] != "enterprise (installed, not running)" {
		t.Errorf("fact = %q", r.Facts["litespeed"])
	}
}
