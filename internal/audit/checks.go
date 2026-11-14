package audit

import (
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/infrafence/infrafence-agent/internal/phpconf"
	"github.com/infrafence/infrafence-agent/internal/scanner"
	"github.com/infrafence/infrafence-agent/internal/watcher"
)

// The mapping from the agent's existing checks to the contract's stable
// ids. Each function is pure: it takes what the host reading found
// (collect.go) and returns checks.

// dbPorts are database ports that must not face the internet
// (services.db_public), adminPorts the caches, search engines and admin
// APIs (services.admin_public). Together they are the agent's closable
// ports (cmd/infrafence-agent/fwactions.go) plus SQL Server.
var (
	dbPorts = []watcher.PortService{
		{Port: 3306, Name: "MySQL/MariaDB"}, {Port: 5432, Name: "PostgreSQL"},
		{Port: 27017, Name: "MongoDB"}, {Port: 27018, Name: "MongoDB"},
		{Port: 1433, Name: "SQL Server"}, {Port: 5984, Name: "CouchDB"},
		{Port: 8086, Name: "InfluxDB"}, {Port: 9042, Name: "Cassandra"},
		{Port: 7000, Name: "Cassandra"}, {Port: 7001, Name: "Cassandra"},
		{Port: 8529, Name: "ArangoDB"}, {Port: 28015, Name: "RethinkDB"},
	}
	adminPorts = []watcher.PortService{
		{Port: 2375, Name: "Docker API"}, {Port: 2376, Name: "Docker API"},
		{Port: 6379, Name: "Redis"}, {Port: 6380, Name: "Redis"},
		{Port: 9200, Name: "Elasticsearch"}, {Port: 9300, Name: "Elasticsearch"},
		{Port: 11211, Name: "Memcached"}, {Port: 15672, Name: "RabbitMQ management"},
		{Port: 5601, Name: "Kibana"},
	}
	// Unauthenticated by default: anyone who reaches them owns the data or
	// the host.
	criticalAdmin = map[string]bool{"Docker API": true, "Redis": true, "Elasticsearch": true, "Memcached": true}
)

func check(id, status, sev string, facts map[string]string) Check {
	if facts == nil {
		facts = map[string]string{}
	}
	return Check{ID: id, Status: status, Severity: sev, Facts: facts}
}

// failStatus is the status of a failed scanner check: fail for critical
// and high, warn below.
func failStatus(sev string) string {
	if sev == SevCritical || sev == SevHigh {
		return StatusFail
	}
	return StatusWarn
}

func severity(s string) string {
	if sevs[s] {
		return s
	}
	return SevInfo
}

func findingByID(fs []scanner.Finding, id string) (scanner.Finding, bool) {
	for _, f := range fs {
		if f.CheckID == id {
			return f, true
		}
	}
	return scanner.Finding{}, false
}

// sshFacts are the value and, when it is set in a file under /etc/ssh,
// where.
func sshFacts(f scanner.Finding) map[string]string {
	facts := map[string]string{"value": f.Details["value"]}
	if v := f.Details["effective_from"]; v != "" {
		facts["effective_from"] = v
	}
	if src := f.Details["source"]; strings.HasPrefix(src, "/etc/ssh/") {
		facts["source"] = src
	}
	return facts
}

// MapSSH maps the scanner's SSH checks (scanner.SSHChecks) to
// ssh.password_auth, ssh.root_login and ssh.default_port_open_to_world.
// port22Public: something sshd uses listens on port 22 on a public or on
// every address.
func MapSSH(fs []scanner.Finding, port22Public bool) []Check {
	var out []Check
	if _, unreadable := findingByID(fs, "SSH_CONFIG_READ"); unreadable || len(fs) == 0 {
		unknown := map[string]string{"value": "unknown", "reason": "sshd_config_unreadable"}
		out = append(out,
			check(IDSSHPasswordAuth, StatusInfo, SevInfo, unknown),
			check(IDSSHRootLogin, StatusInfo, SevInfo, map[string]string{"value": "unknown", "reason": "sshd_config_unreadable"}))
	} else {
		for _, m := range []struct{ scannerID, id string }{
			{"SSH_PASSWORD_AUTH", IDSSHPasswordAuth},
			{"SSH_ROOT_LOGIN", IDSSHRootLogin},
		} {
			f, ok := findingByID(fs, m.scannerID)
			if !ok {
				continue
			}
			sev := severity(f.Severity)
			if f.Passed {
				out = append(out, check(m.id, StatusPass, sev, sshFacts(f)))
			} else {
				out = append(out, check(m.id, failStatus(sev), sev, sshFacts(f)))
			}
		}
	}
	port := "22"
	if f, ok := findingByID(fs, "SSH_DEFAULT_PORT"); ok && f.Details["port"] != "" {
		port = f.Details["port"]
	}
	facts := map[string]string{"configured_port": port, "port_22_public": strconv.FormatBool(port22Public)}
	if port22Public {
		out = append(out, check(IDSSHDefaultPortOpen, StatusWarn, SevLow, facts))
	} else {
		out = append(out, check(IDSSHDefaultPortOpen, StatusPass, SevLow, facts))
	}
	return out
}

// MapExposed maps the publicly listening database and admin ports
// (watcher.ExposedPortList over dbPorts and adminPorts) to one
// services.db_public or services.admin_public check per port, or one pass
// each when none is exposed.
func MapExposed(db, admin []watcher.ExposedDBPort) []Check {
	var out []Check
	for _, x := range db {
		out = append(out, check(IDDBPublic, StatusFail, SevHigh, exposedFacts(x)))
	}
	if len(db) == 0 {
		out = append(out, check(IDDBPublic, StatusPass, SevHigh, map[string]string{"count": "0"}))
	}
	for _, x := range admin {
		sev := SevHigh
		if criticalAdmin[x.Service] {
			sev = SevCritical
		}
		out = append(out, check(IDAdminPublic, StatusFail, sev, exposedFacts(x)))
	}
	if len(admin) == 0 {
		out = append(out, check(IDAdminPublic, StatusPass, SevHigh, map[string]string{"count": "0"}))
	}
	return out
}

// exposedFacts say which port and how it listens: on every address, or on
// a public one (never which address).
func exposedFacts(x watcher.ExposedDBPort) map[string]string {
	bind := "public_address"
	for _, b := range strings.Split(x.BindAddress, ", ") {
		if strings.HasPrefix(b, "0.0.0.0:") || strings.HasPrefix(b, "[::]:") {
			bind = "all_addresses"
		}
	}
	return map[string]string{"port": strconv.Itoa(x.Port), "service": x.Service, "bind": bind}
}

// MapUpdates maps the pending updates and the OS release.
func MapUpdates(u Updates, packageManager, osID, osVersion string, eol bool) []Check {
	var out []Check
	pm := map[string]string{"package_manager": packageManager}
	switch {
	case u.Security == nil:
		pm["reason"] = "package_cache_unavailable"
		out = append(out, check(IDUpdatesSecurity, StatusInfo, SevInfo, pm))
	case *u.Security == 0:
		pm["count"] = "0"
		out = append(out, check(IDUpdatesSecurity, StatusPass, SevHigh, pm))
	default:
		pm["count"] = strconv.Itoa(*u.Security)
		if u.Total != nil {
			pm["total"] = strconv.Itoa(*u.Total)
		}
		sev := SevHigh
		if *u.Security > 10 {
			sev = SevCritical
		}
		out = append(out, check(IDUpdatesSecurity, StatusFail, sev, pm))
	}
	if u.RebootRequired {
		out = append(out, check(IDRebootRequired, StatusWarn, SevMedium, nil))
	} else {
		out = append(out, check(IDRebootRequired, StatusPass, SevMedium, nil))
	}
	facts := map[string]string{"id": osID, "version": osVersion}
	if eol {
		out = append(out, check(IDOSEOL, StatusFail, SevCritical, facts))
	} else {
		out = append(out, check(IDOSEOL, StatusPass, SevCritical, facts))
	}
	return out
}

// MapProtection maps the firewall and the brute-force protection.
// crowdsec counts as brute-force protection too.
func MapProtection(p Protection, crowdsec bool) []Check {
	var out []Check
	if p.Firewall == "none" {
		out = append(out, check(IDFirewallNone, StatusFail, SevHigh, map[string]string{"firewall": "none"}))
	} else {
		out = append(out, check(IDFirewallNone, StatusPass, SevHigh, map[string]string{"firewall": p.Firewall}))
	}
	var tools []string
	for _, t := range []struct {
		on   bool
		name string
	}{{p.Fail2ban, "fail2ban"}, {p.CSF, "csf"}, {crowdsec, "crowdsec"}, {p.InfraFence, "infrafence"}} {
		if t.on {
			tools = append(tools, t.name)
		}
	}
	if len(tools) == 0 {
		out = append(out, check(IDBruteforceNoProtect, StatusFail, SevHigh, map[string]string{"tools": "none"}))
	} else {
		out = append(out, check(IDBruteforceNoProtect, StatusPass, SevHigh, map[string]string{"tools": strings.Join(tools, ",")}))
	}
	return out
}

// MapUsers maps USERS_UID0 and USERS_EMPTY_PW (scanner.UserChecks).
func MapUsers(fs []scanner.Finding) []Check {
	var out []Check
	for _, m := range []struct{ scannerID, id string }{
		{"USERS_UID0", IDUsersUID0Extra},
		{"USERS_EMPTY_PW", IDUsersEmptyPassword},
	} {
		f, ok := findingByID(fs, m.scannerID)
		if !ok {
			out = append(out, check(m.id, StatusInfo, SevInfo, map[string]string{"reason": "unreadable"}))
			continue
		}
		facts := map[string]string{"count": f.Details["count"]}
		if f.Passed {
			out = append(out, check(m.id, StatusPass, SevCritical, facts))
		} else {
			out = append(out, check(m.id, StatusFail, SevCritical, facts))
		}
	}
	return out
}

// FileMeta is what the audit needs of a file's stat: whether it exists,
// its permission bits and its owner.
type FileMeta struct {
	Exists bool
	Perm   os.FileMode
	UID    int
}

// sshdConfigBad: sshd_config holds no secret, so being world-readable (0644,
// Ubuntu's default) is no finding; writable by group or others, or not
// owned by root, is.
func sshdConfigBad(m FileMeta) bool {
	return m.Exists && (m.Perm&0o022 != 0 || m.UID != 0)
}

// MapFilePermissions maps the PERM_* checks (scanner.FilePermissionChecks)
// to files.sensitive_permissions. sshd_config is judged on its own stat
// (sshdConfigBad) instead of the scanner's stricter 0600, which the agent's
// hardening scan keeps.
func MapFilePermissions(fs []scanner.Finding, sshdConfig FileMeta) Check {
	var bad []string
	worst := SevInfo
	rank := map[string]int{SevInfo: 0, SevLow: 1, SevMedium: 2, SevHigh: 3, SevCritical: 4}
	if sshdConfigBad(sshdConfig) {
		bad, worst = append(bad, "sshd_config"), SevHigh
	}
	for _, f := range fs {
		if f.Passed || !strings.HasPrefix(f.CheckID, "PERM_") || f.CheckID == "PERM_SSHD_CONFIG" {
			continue
		}
		bad = append(bad, strings.ToLower(strings.TrimPrefix(f.CheckID, "PERM_")))
		if s := severity(f.Severity); rank[s] > rank[worst] {
			worst = s
		}
	}
	if len(bad) == 0 {
		return check(IDFilesSensitivePerms, StatusPass, SevHigh, nil)
	}
	sort.Strings(bad)
	return check(IDFilesSensitivePerms, failStatus(worst), worst, map[string]string{"files": strings.Join(bad, ",")})
}

// MapWorldWritable maps the world-writable system files found
// (worldWritable in collect.go), given as the scanned root each is under:
// their count and those roots, never a file name.
func MapWorldWritable(dirs []string, scanned int, complete bool) Check {
	facts := map[string]string{"scanned": strconv.Itoa(scanned), "complete": strconv.FormatBool(complete)}
	if len(dirs) == 0 {
		return check(IDFilesWorldWritable, StatusPass, SevHigh, facts)
	}
	facts["count"] = strconv.Itoa(len(dirs))
	set := map[string]bool{}
	var uniq []string
	for _, d := range dirs {
		if !set[d] {
			set[d] = true
			uniq = append(uniq, d)
		}
	}
	sort.Strings(uniq)
	if len(uniq) > maxExamplePaths {
		uniq = uniq[:maxExamplePaths]
	}
	facts["dirs"] = strings.Join(uniq, ",")
	return check(IDFilesWorldWritable, StatusFail, SevHigh, facts)
}

// MapPHP maps the PHP configuration checks (phpconf.Check) to
// php.dangerous_settings: the directives set dangerously in any runtime
// or pool (critical, high and medium checks).
func MapPHP(runtimes int, fs []phpconf.Finding) Check {
	facts := map[string]string{"runtimes": strconv.Itoa(runtimes)}
	if runtimes == 0 {
		return check(IDPHPDangerous, StatusInfo, SevInfo, facts)
	}
	set := map[string]bool{}
	worst := SevLow
	for _, f := range fs {
		if f.Passed {
			continue
		}
		switch f.Severity {
		case SevCritical, SevHigh, SevMedium:
		default:
			continue
		}
		d := f.Details["directive"]
		if d == "" {
			continue
		}
		set[d] = true
		if f.Severity == SevCritical || (f.Severity == SevHigh && worst != SevCritical) || (f.Severity == SevMedium && worst == SevLow) {
			worst = f.Severity
		}
	}
	if len(set) == 0 {
		return check(IDPHPDangerous, StatusPass, SevHigh, facts)
	}
	var names []string
	for d := range set {
		names = append(names, d)
	}
	sort.Strings(names)
	facts["settings"] = strings.Join(names, ",")
	return check(IDPHPDangerous, failStatus(worst), worst, facts)
}
