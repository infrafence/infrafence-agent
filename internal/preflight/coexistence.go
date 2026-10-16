package preflight

import (
	"path/filepath"
	"sort"
	"strings"
)

// Other security tools on the host and what InfraFence does next to each.
// Read-only, like the rest of preflight: files, globs and "is-active"
// queries only. Shown by "infrafence-agent panel coexistence".

// Coexistence modes. The mode is coexist as soon as another active tool
// writes firewall rules.
const (
	// ModeCoexist: another tool manages the firewall. InfraFence keeps to
	// its own chains and sets and never edits, flushes or reorders the other
	// tool's rules.
	ModeCoexist = "coexist"
	// ModePrimary: InfraFence is the only tool managing the firewall.
	ModePrimary = "primary"
)

// Tool is one security tool found on the host.
type Tool struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Kind     string   `json:"kind"` // firewall, brute_force, waf, malware
	Active   bool     `json:"active"`
	Version  string   `json:"version,omitempty"`
	Rulesets []string `json:"rulesets,omitempty"` // ModSecurity vendors / rule sets
	// Firewall: the tool writes its own iptables/nftables rules.
	Firewall bool `json:"manages_firewall"`
	// Action is what InfraFence does about it (English; the plugins
	// translate by ActionID).
	ActionID string `json:"action_id"`
	Action   string `json:"action"`
}

// Coexistence is the full answer.
type Coexistence struct {
	Mode  string `json:"mode"`
	Tools []Tool `json:"tools"`
}

// What InfraFence does, per tool. Kept true to the code: the agent only
// ever touches its own INFRAFENCE* chains and infrafence-* sets, puts back
// its own jumps after another tool rebuilds the firewall, and edits web
// server configuration only where preflight allows it (never under a
// hosting panel).
var coexistActions = map[string]string{
	"csf": "InfraFence keeps its own chain and never edits csf.conf, csf.allow or csf.deny. " +
		"After csf -r it restores only its own jump. CSF ports change only when you ask from the dashboard.",
	"lfd":            "Both read the same logs and block on their own; lfd blocks stay in CSF, InfraFence bans stay in its own set.",
	"imunify":        "InfraFence leaves Imunify360's firewall, ipsets and WAF alone and keeps to its own chain; both block independently.",
	"imunifyav":      "Both scan files. InfraFence never deletes or moves a file on its own: quarantine only on request.",
	"cphulk":         "cPHulk blocks panel and service logins; InfraFence reads the same logs and bans at the firewall. cPHulk is not changed.",
	"fail2ban":       "Compatible: both only drop traffic. InfraFence does not touch fail2ban's chains.",
	"crowdsec":       "Compatible: both only drop traffic. InfraFence does not touch CrowdSec's rules.",
	"plesk_firewall": "Plesk Firewall rewrites the rules when you apply changes; InfraFence never edits them and restores only its own chain within a minute.",
	"modsecurity":    "InfraFence reads the ModSecurity audit log for detections. Under a hosting panel it adds no ModSecurity rules: the panel owns the web server configuration.",
	"bitninja":       "InfraFence leaves BitNinja's firewall and WAF alone and keeps to its own chain; both block independently.",
	"monarx":         "Both scan files. InfraFence never deletes or moves a file on its own: quarantine only on request.",
	"firewalld":      "firewalld keeps its own rules; InfraFence's chain is independent and restored within a minute after a reload.",
	"ufw":            "InfraFence jumps to its chain ahead of ufw's rules; a ufw reload is repaired within a minute.",
}

// DetectCoexistence inspects the current host.
func DetectCoexistence() Coexistence { return DetectCoexistenceEnv(hostEnv{}) }

// DetectCoexistenceEnv inspects the host through env.
func DetectCoexistenceEnv(env Env) Coexistence {
	systemctl := firstExisting(env, systemctlPaths)
	active := func(units ...string) bool {
		if systemctl == "" {
			return false
		}
		for _, u := range units {
			if out, _ := env.Run(systemctl, "is-active", u); strings.TrimSpace(out) == "active" {
				return true
			}
		}
		return false
	}
	anyExists := func(paths ...string) bool {
		for _, p := range paths {
			if env.Exists(p) {
				return true
			}
		}
		return false
	}
	var tools []Tool
	add := func(t Tool) {
		t.ActionID = "coexist_" + t.ID
		t.Action = coexistActions[t.ID]
		tools = append(tools, t)
	}

	if env.Exists("/etc/csf/csf.conf") {
		t := Tool{ID: "csf", Name: "CSF (ConfigServer Firewall)", Kind: "firewall", Firewall: true}
		if v, err := env.ReadFile("/etc/csf/version.txt"); err == nil {
			t.Version = clean(v)
		}
		conf, _ := env.ReadFile("/etc/csf/csf.conf")
		// TESTING = "1": CSF flushes its own rules every few minutes.
		t.Active = active("csf") || csfValue(conf, "TESTING") != "1"
		add(t)
		if anyExists("/usr/sbin/lfd", "/etc/csf/lfd.pl", "/usr/local/csf/bin/lfd") || active("lfd") {
			add(Tool{ID: "lfd", Name: "lfd (Login Failure Daemon)", Kind: "brute_force", Active: active("lfd")})
		}
	}
	if anyExists("/usr/bin/imunify360-agent", "/etc/sysconfig/imunify360") {
		t := Tool{ID: "imunify", Name: "Imunify360", Kind: "firewall", Firewall: true, Active: active("imunify360", "imunify360-agent")}
		add(t)
	} else if anyExists("/usr/bin/imunify-antivirus", "/etc/sysconfig/imunify360/imunify-antivirus.config") {
		add(Tool{ID: "imunifyav", Name: "ImunifyAV", Kind: "malware", Active: active("imunify-antivirus")})
	}
	if env.Exists("/usr/local/cpanel") && anyExists("/var/cpanel/hulkd", "/usr/local/cpanel/bin/hulkdsetup") {
		add(Tool{ID: "cphulk", Name: "cPHulk", Kind: "brute_force", Active: env.Exists("/var/cpanel/hulkd/enabled") || active("cphulkd")})
	}
	if active("fail2ban") || env.Exists("/etc/fail2ban/jail.conf") {
		add(Tool{ID: "fail2ban", Name: "fail2ban", Kind: "brute_force", Firewall: true, Active: active("fail2ban")})
	}
	if active("crowdsec", "crowdsec-firewall-bouncer") {
		add(Tool{ID: "crowdsec", Name: "CrowdSec", Kind: "brute_force", Firewall: true, Active: true})
	}
	if anyExists("/usr/local/psa/var/modules/firewall", "/opt/psa/var/modules/firewall", "/usr/local/psa/admin/plib/modules/firewall") {
		add(Tool{ID: "plesk_firewall", Name: "Plesk Firewall", Kind: "firewall", Firewall: true, Active: active("psa-firewall")})
	}
	if anyExists("/opt/bitninja", "/etc/bitninja") || active("bitninja") {
		add(Tool{ID: "bitninja", Name: "BitNinja", Kind: "firewall", Firewall: true, Active: active("bitninja")})
	}
	if anyExists("/etc/monarx-agent.conf", "/usr/bin/monarx-agent") || active("monarx-agent") {
		add(Tool{ID: "monarx", Name: "Monarx", Kind: "malware", Active: active("monarx-agent")})
	}
	if active("firewalld") {
		add(Tool{ID: "firewalld", Name: "firewalld", Kind: "firewall", Firewall: true, Active: true})
	}
	if ufw := firstExisting(env, ufwPaths); ufw != "" && active("ufw") {
		if out, _ := env.Run(ufw, "status"); strings.Contains(out, "Status: active") {
			add(Tool{ID: "ufw", Name: "ufw", Kind: "firewall", Firewall: true, Active: true})
		}
	}
	if rs := modsecRulesets(env); rs != nil {
		add(Tool{ID: "modsecurity", Name: "ModSecurity", Kind: "waf", Active: true, Rulesets: rs})
	}

	c := Coexistence{Mode: ModePrimary, Tools: tools}
	if c.Tools == nil {
		c.Tools = []Tool{}
	}
	for _, t := range tools {
		if t.Firewall && t.Active {
			c.Mode = ModeCoexist
			break
		}
	}
	return c
}

// modsecRulesets lists the ModSecurity vendors and rule sets in use: cPanel
// vendors (EasyApache 4), the Plesk WAF rule set, OWASP CRS, Comodo and
// Imunify. nil when ModSecurity is not installed.
func modsecRulesets(env Env) []string {
	seen := map[string]bool{}
	installed := false
	add := func(name string) {
		if name != "" && !seen[name] {
			seen[name] = true
		}
	}
	// cPanel: one directory per installed vendor, and one metadata file per
	// configured vendor.
	for _, dir := range []string{"/etc/apache2/conf.d/modsec_vendor_configs", "/usr/local/apache/conf/modsec_vendor_configs"} {
		for _, p := range env.Glob(dir + "/*") {
			installed = true
			add(vendorName(filepath.Base(p)))
		}
	}
	for _, p := range env.Glob("/var/cpanel/modsec_vendors/meta_*.yaml") {
		installed = true
		add(vendorName(strings.TrimSuffix(strings.TrimPrefix(filepath.Base(p), "meta_"), ".yaml")))
	}
	if env.Exists("/etc/apache2/conf.d/modsec2.conf") || env.Exists("/etc/apache2/conf.d/modsec/modsec2.cpanel.conf") {
		installed = true
	}
	// Plesk: the rule set chosen under Web Application Firewall.
	for _, dir := range []string{"/etc/apache2/modsecurity.d/rules", "/etc/httpd/conf/modsecurity.d/rules", "/etc/modsecurity.d/rules"} {
		for _, p := range env.Glob(dir + "/*") {
			installed = true
			add(vendorName(filepath.Base(p)))
		}
	}
	// Distribution packages and manual installs.
	for _, p := range []string{"/usr/share/modsecurity-crs", "/etc/modsecurity/crs", "/etc/nginx/modsec/coreruleset", "/usr/local/owasp-modsecurity-crs", "/etc/httpd/modsecurity.d/activated_rules"} {
		if env.Exists(p) {
			installed = true
			add("OWASP CRS")
		}
	}
	for _, p := range []string{"/etc/modsecurity/modsecurity.conf", "/etc/httpd/conf.d/mod_security.conf", "/etc/apache2/mods-enabled/security2.conf", "/etc/nginx/modsec/modsecurity.conf"} {
		if env.Exists(p) {
			installed = true
		}
	}
	if !installed {
		return nil
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// vendorName maps a cPanel vendor id or Plesk rule set directory to a
// readable name; unknown ones are kept as they are.
func vendorName(id string) string {
	l := strings.ToLower(id)
	switch {
	case strings.HasPrefix(l, "."), l == "":
		return ""
	case strings.Contains(l, "owasp"), strings.Contains(l, "crs"):
		return "OWASP CRS"
	case strings.Contains(l, "comodo"):
		return "Comodo WAF"
	case strings.Contains(l, "imunify"):
		return "Imunify360 WAF"
	case strings.Contains(l, "tortix"), strings.Contains(l, "atomic"):
		return "Atomicorp"
	}
	if len(id) > 64 {
		id = id[:64]
	}
	return id
}

// csfValue reads KEY = "value" from csf.conf.
func csfValue(conf, key string) string {
	for _, l := range strings.Split(conf, "\n") {
		k, v, ok := strings.Cut(l, "=")
		if ok && strings.TrimSpace(k) == key {
			return strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return ""
}

// The panel command runs from WHM and Plesk: every binary it runs is named
// by its absolute path, never looked up in the caller's PATH.
var (
	systemctlPaths = []string{"/usr/bin/systemctl", "/bin/systemctl"}
	ufwPaths       = []string{"/usr/sbin/ufw", "/sbin/ufw"}
	pleskPaths     = []string{"/usr/local/psa/bin/plesk", "/opt/psa/bin/plesk"}
)

// firstExisting returns the first of paths that exists, or "".
func firstExisting(env Env, paths []string) string {
	for _, p := range paths {
		if env.Exists(p) {
			return p
		}
	}
	return ""
}
