// Package audit is the free, one-shot server audit (`infrafence-agent
// audit`, audit.sh): a read-only look at a server that sends ids and facts
// to the dashboard, which scores them and writes the texts.
//
// It reuses the agent's existing checks (preflight, scanner, sshdconfig,
// netstate, the watchers' log patterns, phpconf) and maps them to the
// stable ids of the shared contract (report schema 1). It never changes the
// firewall, a configuration file, a service or a package: it reads files,
// the kernel's socket table and the output of query commands, within a
// fixed time (Deadline) and a fixed number of log bytes.
//
// Every string that leaves the host goes through the privacy filter
// (privacy.go): no hostname, server address, user name other than root,
// path under /home, file content or secret.
package audit

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"time"
)

// Schema is the report schema version shared with the dashboard.
const Schema = 1

// Status of a check.
const (
	StatusFail = "fail"
	StatusWarn = "warn"
	StatusPass = "pass"
	StatusInfo = "info"
)

// Severity of a check.
const (
	SevCritical = "critical"
	SevHigh     = "high"
	SevMedium   = "medium"
	SevLow      = "low"
	SevInfo     = "info"
)

// Check ids, v1 (the dashboard shows an unknown id generically).
const (
	IDSSHPasswordAuth     = "ssh.password_auth"
	IDSSHRootLogin        = "ssh.root_login"
	IDSSHDefaultPortOpen  = "ssh.default_port_open_to_world"
	IDDBPublic            = "services.db_public"
	IDAdminPublic         = "services.admin_public"
	IDUpdatesSecurity     = "updates.security_pending"
	IDRebootRequired      = "updates.reboot_required"
	IDOSEOL               = "os.eol"
	IDFirewallNone        = "firewall.none"
	IDBruteforceNoProtect = "bruteforce.no_protection"
	IDUsersUID0Extra      = "users.uid0_extra"
	IDUsersEmptyPassword  = "users.empty_password"
	IDFilesWorldWritable  = "files.world_writable_system"
	IDPHPDangerous        = "php.dangerous_settings"
	// Beyond v1's list (shown generically): the scanner's PERM_* checks.
	IDFilesSensitivePerms = "files.sensitive_permissions"
)

// Limits of the contract and of the dashboard's validation.
const (
	maxFactValue       = 200
	maxFacts           = 12
	maxChecks          = 64
	maxListening       = 100
	maxTopIPs          = 10
	maxExamplePaths    = 5
	reportWindowHours  = 24
	maxReportBytes     = 256 << 10
	agentVersionMaxLen = 40
)

// Report is schema 1.
type Report struct {
	Schema       int         `json:"schema"`
	AgentVersion string      `json:"agent_version"`
	GeneratedAt  string      `json:"generated_at"`
	OS           OS          `json:"os"`
	Environment  Environment `json:"environment"`
	Checks       []Check     `json:"checks"`
	Listening    []Listener  `json:"listening"`
	Updates      Updates     `json:"updates"`
	Attacks      Attacks     `json:"attacks"`
	Protection   Protection  `json:"protection"`
}

// OS is the distribution, kernel and architecture.
type OS struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Kernel  string `json:"kernel"`
	Arch    string `json:"arch"`
}

// Environment is what runs the sites.
type Environment struct {
	Panel      string `json:"panel"`
	WebServer  string `json:"web_server"`
	Containers bool   `json:"containers"`
}

// Check is one finding: an id and short facts.
type Check struct {
	ID       string            `json:"id"`
	Status   string            `json:"status"`
	Severity string            `json:"severity"`
	Facts    map[string]string `json:"facts"`
}

// Listener is a listening TCP port.
type Listener struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Process string `json:"process"`
	Public  bool   `json:"public"`
}

// Updates are the pending package updates, from the package manager's
// cache. Security and Total are null when the cache can't tell (no cache,
// an unsupported package manager).
type Updates struct {
	Security       *int `json:"security"`
	Total          *int `json:"total"`
	RebootRequired bool `json:"reboot_required"`
}

// Attacks are the last WindowHours of the SSH and web logs.
type Attacks struct {
	WindowHours           int     `json:"window_hours"`
	SSHFailedLogins       int     `json:"ssh_failed_logins"`
	SSHUniqueIPs          int     `json:"ssh_unique_ips"`
	WebSuspiciousRequests int     `json:"web_suspicious_requests"`
	WebUniqueIPs          int     `json:"web_unique_ips"`
	TopIPs                []TopIP `json:"top_ips"`
}

// TopIP is one attacking address.
type TopIP struct {
	IP    string `json:"ip"`
	Count int    `json:"count"`
	Kind  string `json:"kind"` // ssh, web
}

// Protection is what already defends the server.
type Protection struct {
	Firewall   string `json:"firewall"`
	Fail2ban   bool   `json:"fail2ban"`
	CSF        bool   `json:"csf"`
	InfraFence bool   `json:"infrafence"`
}

var (
	factKeyRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)
	checkIDRe = regexp.MustCompile(`^[a-z][a-z0-9_]*\.[a-z][a-z0-9_.]*$`)
	statuses  = map[string]bool{StatusFail: true, StatusWarn: true, StatusPass: true, StatusInfo: true}
	sevs      = map[string]bool{SevCritical: true, SevHigh: true, SevMedium: true, SevLow: true, SevInfo: true}
	firewalls = map[string]bool{"nftables": true, "iptables": true, "ufw": true, "firewalld": true, "none": true}
	ipKinds   = map[string]bool{"ssh": true, "web": true}
)

// Validate checks r against schema 1: the shape the dashboard accepts and
// the limits of the contract. It is run on every report before it is
// printed or sent.
func (r *Report) Validate() error {
	if r.Schema != Schema {
		return fmt.Errorf("schema %d, want %d", r.Schema, Schema)
	}
	if r.AgentVersion == "" || len(r.AgentVersion) > agentVersionMaxLen {
		return fmt.Errorf("agent_version %q", r.AgentVersion)
	}
	if _, err := time.Parse(time.RFC3339, r.GeneratedAt); err != nil {
		return fmt.Errorf("generated_at: %v", err)
	}
	if r.OS.Arch == "" {
		return fmt.Errorf("os.arch is empty")
	}
	if r.Checks == nil || r.Listening == nil || r.Attacks.TopIPs == nil {
		return fmt.Errorf("checks, listening and attacks.top_ips must be arrays, not null")
	}
	if len(r.Checks) > maxChecks {
		return fmt.Errorf("%d checks (max %d)", len(r.Checks), maxChecks)
	}
	for _, c := range r.Checks {
		if !checkIDRe.MatchString(c.ID) {
			return fmt.Errorf("check id %q", c.ID)
		}
		if !statuses[c.Status] || !sevs[c.Severity] {
			return fmt.Errorf("check %s: status %q severity %q", c.ID, c.Status, c.Severity)
		}
		if c.Facts == nil || len(c.Facts) > maxFacts {
			return fmt.Errorf("check %s: %d facts", c.ID, len(c.Facts))
		}
		for k, v := range c.Facts {
			if !factKeyRe.MatchString(k) || len(v) > maxFactValue {
				return fmt.Errorf("check %s: fact %q", c.ID, k)
			}
		}
	}
	if len(r.Listening) > maxListening {
		return fmt.Errorf("%d listening ports", len(r.Listening))
	}
	for _, l := range r.Listening {
		if l.Port < 1 || l.Port > 65535 || (l.Proto != "tcp" && l.Proto != "tcp6") || len(l.Process) > 64 {
			return fmt.Errorf("listening %+v", l)
		}
	}
	for _, p := range []*int{r.Updates.Security, r.Updates.Total} {
		if p != nil && *p < 0 {
			return fmt.Errorf("negative update count")
		}
	}
	a := r.Attacks
	if a.WindowHours != reportWindowHours || a.SSHFailedLogins < 0 || a.SSHUniqueIPs < 0 ||
		a.WebSuspiciousRequests < 0 || a.WebUniqueIPs < 0 || len(a.TopIPs) > maxTopIPs {
		return fmt.Errorf("attacks %+v", a)
	}
	for _, t := range a.TopIPs {
		if net.ParseIP(t.IP) == nil || t.Count < 1 || !ipKinds[t.Kind] {
			return fmt.Errorf("top ip %+v", t)
		}
	}
	if !firewalls[r.Protection.Firewall] {
		return fmt.Errorf("protection.firewall %q (nftables, iptables, ufw, firewalld or none)", r.Protection.Firewall)
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if len(b) > maxReportBytes {
		return fmt.Errorf("report is %d bytes (max %d)", len(b), maxReportBytes)
	}
	return nil
}
