package scanner

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/infrafence/infrafence-agent/internal/sshdconfig"
)

// Finding represents a single security check result.
type Finding struct {
	Category       string            `json:"category"`
	Severity       string            `json:"severity"`
	CheckID        string            `json:"check_id"`
	Title          string            `json:"title"`
	Description    string            `json:"description"`
	Recommendation string            `json:"recommendation,omitempty"`
	Details        map[string]string `json:"details,omitempty"`
	Passed         bool              `json:"passed"`
}

// Run performs all security checks and returns findings.
func Run() []Finding {
	var findings []Finding

	findings = append(findings, checkSSHConfig()...)
	findings = append(findings, checkFilePermissions()...)
	findings = append(findings, checkOpenPorts()...)
	findings = append(findings, checkUsers()...)
	findings = append(findings, checkFirewall()...)
	findings = append(findings, checkProcesses()...)
	findings = append(findings, checkWebServer()...)
	findings = append(findings, checkCredentialExposure()...)

	// Software version checks
	findings = append(findings, checkOSVersion()...)
	findings = append(findings, checkKernelVersion()...)
	findings = append(findings, checkSecurityUpdates()...)
	findings = append(findings, checkPHPVersion()...)
	findings = append(findings, checkPanelPHPHandlers()...)
	findings = append(findings, checkPHPConfig()...)
	findings = append(findings, checkMySQLVersion()...)
	findings = append(findings, checkOpenSSHVersion()...)
	findings = append(findings, checkWebServerVersion()...)

	return findings
}

// ─── SSH Config Checks ───

func checkSSHConfig() []Finding {
	var findings []Finding

	v, ok := readSSHView()
	if !ok {
		findings = append(findings, Finding{
			Category:    "ssh_config",
			Severity:    "info",
			CheckID:     "SSH_CONFIG_READ",
			Title:       "SSH config not readable",
			Description: "Could not read /etc/ssh/sshd_config",
			Passed:      true, // not a failure, might not have permissions
		})
		return findings
	}

	// Check root login
	rootLogin := v.value("PermitRootLogin", "prohibit-password")
	passed := rootLogin == "no" || rootLogin == "prohibit-password" || rootLogin == "without-password"
	findings = append(findings, Finding{
		Category:       "ssh_config",
		Severity:       "critical",
		CheckID:        "SSH_ROOT_LOGIN",
		Title:          "SSH root login",
		Description:    fmt.Sprintf("PermitRootLogin is set to '%s'", rootLogin) + v.where("PermitRootLogin", rootLogin),
		Recommendation: v.fix("PermitRootLogin", "no", "Set PermitRootLogin to 'no'"),
		Details:        v.details("PermitRootLogin", rootLogin),
		Passed:         passed,
	})

	// Check password auth
	passAuth := v.value("PasswordAuthentication", "yes")
	passed = passAuth == "no"
	findings = append(findings, Finding{
		Category:       "ssh_config",
		Severity:       "high",
		CheckID:        "SSH_PASSWORD_AUTH",
		Title:          "SSH password authentication",
		Description:    fmt.Sprintf("PasswordAuthentication is '%s'", passAuth) + v.where("PasswordAuthentication", passAuth),
		Recommendation: v.fix("PasswordAuthentication", "no", "Disable password authentication and use SSH keys only: set PasswordAuthentication no"),
		Details:        v.details("PasswordAuthentication", passAuth),
		Passed:         passed,
	})

	// Check SSH port
	port := v.value("Port", "22")
	passed = port != "22"
	d := v.details("Port", port)
	d["port"] = port
	findings = append(findings, Finding{
		Category:       "ssh_config",
		Severity:       "low",
		CheckID:        "SSH_DEFAULT_PORT",
		Title:          "SSH on default port",
		Description:    fmt.Sprintf("SSH is running on port %s", port) + v.where("Port", port),
		Recommendation: "Consider changing the SSH port from the default 22",
		Details:        d,
		Passed:         passed,
	})

	// Check X11 forwarding
	x11 := v.value("X11Forwarding", "no")
	passed = x11 == "no" || x11 == ""
	findings = append(findings, Finding{
		Category:       "ssh_config",
		Severity:       "low",
		CheckID:        "SSH_X11_FORWARDING",
		Title:          "SSH X11 forwarding",
		Description:    fmt.Sprintf("X11Forwarding is '%s'", x11) + v.where("X11Forwarding", x11),
		Recommendation: v.fix("X11Forwarding", "no", "Disable X11Forwarding unless required"),
		Details:        v.details("X11Forwarding", x11),
		Passed:         passed,
	})

	// Check MaxAuthTries
	maxAuth := v.value("MaxAuthTries", "6")
	n, err := strconv.Atoi(maxAuth)
	passed = err == nil && n <= 4
	findings = append(findings, Finding{
		Category:       "ssh_config",
		Severity:       "medium",
		CheckID:        "SSH_MAX_AUTH_TRIES",
		Title:          "SSH max auth tries",
		Description:    fmt.Sprintf("MaxAuthTries is %s", maxAuth) + v.where("MaxAuthTries", maxAuth),
		Recommendation: v.fix("MaxAuthTries", "4", "Set MaxAuthTries to 4 or lower"),
		Details:        v.details("MaxAuthTries", maxAuth),
		Passed:         passed,
	})

	return findings
}

// ─── File Permission Checks ───

func checkFilePermissions() []Finding {
	var findings []Finding

	checks := []struct {
		path     string
		maxPerm  os.FileMode
		checkID  string
		severity string
		title    string
	}{
		{"/etc/shadow", 0o640, "PERM_SHADOW", "critical", "/etc/shadow permissions"},
		{"/etc/passwd", 0o644, "PERM_PASSWD", "high", "/etc/passwd permissions"},
		{"/etc/ssh/sshd_config", 0o600, "PERM_SSHD_CONFIG", "high", "sshd_config permissions"},
		{"/root/.ssh/authorized_keys", 0o600, "PERM_AUTH_KEYS", "high", "authorized_keys permissions"},
	}

	for _, c := range checks {
		info, err := os.Stat(c.path)
		if err != nil {
			findings = append(findings, Finding{
				Category:    "file_permissions",
				Severity:    "info",
				CheckID:     c.checkID,
				Title:       c.title,
				Description: fmt.Sprintf("%s not found", c.path),
				Passed:      true,
			})
			continue
		}

		perm := info.Mode().Perm()
		passed := perm <= c.maxPerm
		findings = append(findings, Finding{
			Category:       "file_permissions",
			Severity:       c.severity,
			CheckID:        c.checkID,
			Title:          c.title,
			Description:    fmt.Sprintf("%s has permissions %04o (max allowed: %04o)", c.path, perm, c.maxPerm),
			Recommendation: fmt.Sprintf("Run: chmod %04o %s", c.maxPerm, c.path),
			Details:        map[string]string{"current": fmt.Sprintf("%04o", perm), "max": fmt.Sprintf("%04o", c.maxPerm)},
			Passed:         passed,
		})
	}

	return findings
}

// ─── Open Port Checks ───

func checkOpenPorts() []Finding {
	var findings []Finding

	dangerousPorts := map[int]struct {
		service  string
		severity string
	}{
		21:    {"FTP", "high"},
		23:    {"Telnet", "critical"},
		25:    {"SMTP", "medium"},
		3306:  {"MySQL", "high"},
		5432:  {"PostgreSQL", "high"},
		6379:  {"Redis", "critical"},
		11211: {"Memcached", "high"},
		27017: {"MongoDB", "critical"},
	}

	// Get actual bind addresses from ss (more reliable than connecting to localhost)
	exposedPorts := getExposedPorts()

	for port, info := range dangerousPorts {
		bindAddr, listening := exposedPorts[port]
		if !listening {
			continue
		}

		// Services bound to 127.0.0.1 or ::1 are safe (localhost only)
		if bindAddr == "127.0.0.1" || bindAddr == "::1" || bindAddr == "[::1]" {
			findings = append(findings, Finding{
				Category:    "open_ports",
				Severity:    "info",
				CheckID:     fmt.Sprintf("PORT_%d", port),
				Title:       fmt.Sprintf("%s port %d is bound to localhost (safe)", info.service, port),
				Description: fmt.Sprintf("%s is listening on %s:%d — not externally accessible", info.service, bindAddr, port),
				Details:     map[string]string{"port": fmt.Sprintf("%d", port), "service": info.service, "bind": bindAddr},
				Passed:      true,
			})
			continue
		}

		// Service is exposed on 0.0.0.0 or a public IP — real risk
		findings = append(findings, Finding{
			Category:       "open_ports",
			Severity:       info.severity,
			CheckID:        fmt.Sprintf("PORT_%d", port),
			Title:          fmt.Sprintf("%s port %d is exposed externally", info.service, port),
			Description:    fmt.Sprintf("%s is listening on %s:%d — accessible from the network", info.service, bindAddr, port),
			Recommendation: fmt.Sprintf("Bind %s to 127.0.0.1 or restrict access with firewall rules", info.service),
			Details:        map[string]string{"port": fmt.Sprintf("%d", port), "service": info.service, "bind": bindAddr},
			Passed:         false,
		})
	}

	// If no dangerous ports found at all, add a pass
	hasFailed := false
	for _, f := range findings {
		if !f.Passed {
			hasFailed = true
			break
		}
	}
	if !hasFailed && len(findings) == 0 {
		findings = append(findings, Finding{
			Category:    "open_ports",
			Severity:    "info",
			CheckID:     "PORTS_CLEAN",
			Title:       "No dangerous ports exposed",
			Description: "None of the commonly exploited ports are externally accessible",
			Passed:      true,
		})
	}

	return findings
}

// getExposedPorts reads listening TCP ports and their bind addresses via ss.
// Returns map[port]bindAddress where bindAddress is "0.0.0.0", "127.0.0.1", "::", etc.
func getExposedPorts() map[int]string {
	result := make(map[int]string)

	out, err := exec.Command("ss", "-tlnH").Output()
	if err != nil {
		return result
	}

	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		// Local address is field[3], format: "127.0.0.1:6379" or "*:80" or "0.0.0.0:3306" or ":::22" or "[::]:80"
		local := fields[3]
		lastColon := strings.LastIndex(local, ":")
		if lastColon == -1 {
			continue
		}
		addr := local[:lastColon]
		portStr := local[lastColon+1:]

		port := 0
		fmt.Sscanf(portStr, "%d", &port)
		if port == 0 {
			continue
		}

		// Normalize bind address
		if addr == "*" || addr == "" || addr == "0.0.0.0" || addr == "[::]" || addr == "::" {
			result[port] = "0.0.0.0"
		} else if addr == "[::1]" || addr == "::1" {
			result[port] = "::1"
		} else {
			result[port] = addr
		}
	}

	return result
}

// ─── User Checks ───

func checkUsers() []Finding {
	var findings []Finding

	// Check for users with UID 0 (besides root)
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return findings
	}

	uid0Users := []string{}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) >= 4 && parts[2] == "0" && parts[0] != "root" {
			uid0Users = append(uid0Users, parts[0])
		}
	}

	findings = append(findings, Finding{
		Category:       "users",
		Severity:       "critical",
		CheckID:        "USERS_UID0",
		Title:          "Non-root users with UID 0",
		Description:    fmt.Sprintf("Found %d non-root user(s) with UID 0", len(uid0Users)),
		Recommendation: "Remove or fix users with UID 0 besides root",
		Passed:         len(uid0Users) == 0,
	})

	// Check for users with empty passwords in /etc/shadow
	shadow, err := os.ReadFile("/etc/shadow")
	if err == nil {
		emptyPw := 0
		for _, line := range strings.Split(string(shadow), "\n") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 && parts[1] == "" {
				emptyPw++
			}
		}

		findings = append(findings, Finding{
			Category:       "users",
			Severity:       "critical",
			CheckID:        "USERS_EMPTY_PW",
			Title:          "Users with empty passwords",
			Description:    fmt.Sprintf("Found %d user(s) with empty password hashes", emptyPw),
			Recommendation: "Set passwords or lock accounts without passwords",
			Passed:         emptyPw == 0,
		})
	}

	return findings
}

// ─── Firewall Checks ───

func checkFirewall() []Finding {
	var findings []Finding

	// Check if iptables INFRAFENCE chain exists (our chain)
	_, err := os.Stat("/proc/net/ip_tables_names")
	hasIptables := err == nil

	findings = append(findings, Finding{
		Category:       "firewall",
		Severity:       "medium",
		CheckID:        "FW_IPTABLES",
		Title:          "iptables available",
		Description:    fmt.Sprintf("iptables kernel module loaded: %v", hasIptables),
		Recommendation: "Ensure iptables is available for firewall rules",
		Passed:         hasIptables,
	})

	return findings
}

// ─── Helpers ───

// sshView is what the SSH checks read: the values sshd actually uses
// (`sshd -T`, which resolves Include files, Match defaults and built-in
// defaults) and the files read in sshd's order (sshdconfig), which say
// where each value is set and stand in for `sshd -T` when it cannot run
// (on a socket-activated sshd it fails until /run/sshd exists).
type sshView struct {
	dump     string // sshd -T output, "" without
	files    sshdconfig.Config
	hasFiles bool
}

// Replaced in tests.
var (
	sshdDump = func() string {
		for _, bin := range []string{"/usr/sbin/sshd", "/usr/local/sbin/sshd", "/usr/bin/sshd"} {
			if _, err := os.Stat(bin); err != nil {
				continue
			}
			// Read only: -T prints the configuration and exits.
			out, err := runOutput(10*time.Second, bin, "-T")
			if err == nil && strings.Contains(out, "\n") {
				return out
			}
		}
		return ""
	}
	sshFS = sshdconfig.OS
)

func readSSHView() (sshView, bool) {
	v := sshView{dump: sshdDump()}
	v.files, v.hasFiles = sshdconfig.Parse(sshFS)
	return v, v.dump != "" || v.hasFiles
}

// value returns the effective value of key: sshd -T, else the first value
// in the files, else sshd's default def.
func (v sshView) value(key, def string) string {
	if v.dump != "" {
		if val := sshConfigValue(v.dump, key); val != "" {
			return val
		}
		return def
	}
	if s, ok := v.files.Get(key); ok {
		return s.Value
	}
	return def
}

// source returns the file and line that set the effective value val, when
// the files agree with it.
func (v sshView) source(key, val string) (sshdconfig.Setting, bool) {
	s, ok := v.files.Get(key)
	if !ok || !sshdconfig.Same(key, s.Value, val) {
		return sshdconfig.Setting{}, false
	}
	return s, true
}

// where says where val comes from, for the description.
func (v sshView) where(key, val string) string {
	if s, ok := v.source(key, val); ok {
		return fmt.Sprintf(" (set in %s)", s.Where())
	}
	if _, set := v.files.Get(key); v.hasFiles && !set {
		return " (sshd's default: no file sets it)"
	}
	return ""
}

// details are the value and, when known, where it is set.
func (v sshView) details(key, val string) map[string]string {
	d := map[string]string{"value": val, "effective_from": "config files"}
	if v.dump != "" {
		d["effective_from"] = "sshd -T"
	}
	if s, ok := v.source(key, val); ok {
		d["source"], d["source_file"], d["source_line"] = s.Where(), s.File, strconv.Itoa(s.Line)
	}
	return d
}

// fix is the recommendation: what to set, and in which file. sshd keeps the
// first value it reads and reads the sshd_config.d drop-ins where
// sshd_config includes them (at its top on current distributions), so the
// line to change is the one that sets the value now; a line added further
// down sshd_config changes nothing.
func (v sshView) fix(key, want, what string) string {
	if s, ok := v.files.Get(key); ok {
		if s.DropIn() {
			return fmt.Sprintf("%s in %s (line %d), where it is set now, then reload SSH. sshd keeps the first value it reads and reads %s before the rest of sshd_config, so a value set there wins over sshd_config.",
				what, s.File, s.Line, s.File)
		}
		return fmt.Sprintf("%s in %s (line %d), then reload SSH. A file in /etc/ssh/sshd_config.d/ that sets %s would win over it: sshd keeps the first value it reads.",
			what, s.File, s.Line, key)
	}
	return fmt.Sprintf("%s in a file of /etc/ssh/sshd_config.d/ read before any other (for example 00-hardening.conf), or in /etc/ssh/sshd_config above its Include line, then reload SSH: sshd keeps the first value it reads.", what)
}

// runOutput runs a command and returns its standard output, killing it
// after d.
func runOutput(d time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return string(out), err
}

// runTimeout runs a command and returns its combined output, killing it
// after d.
func runTimeout(d time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

func sshConfigValue(content, key string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 && strings.EqualFold(parts[0], key) {
			return parts[1]
		}
	}
	return ""
}

func isPortOpen(host string, port int) bool {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// ─── Process Checks ───

func checkProcesses() []Finding {
	var findings []Finding

	// Count zombie processes by reading /proc/*/status
	zombieCount := 0
	parentCmds := map[string]int{}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		findings = append(findings, Finding{
			Category:    "processes",
			Severity:    "info",
			CheckID:     "PROC_READ",
			Title:       "Cannot read /proc",
			Description: "Could not read /proc filesystem",
			Passed:      true,
		})
		return findings
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		// Only PID directories (all digits)
		isDigit := true
		for _, c := range entry.Name() {
			if c < '0' || c > '9' {
				isDigit = false
				break
			}
		}
		if !isDigit {
			continue
		}

		data, err := os.ReadFile("/proc/" + entry.Name() + "/status")
		if err != nil {
			continue
		}

		state := ""
		ppid := ""
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "State:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					state = fields[1]
				}
			} else if strings.HasPrefix(line, "PPid:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					ppid = fields[1]
				}
			}
		}

		if state == "Z" {
			zombieCount++
			// Read parent command
			commData, err := os.ReadFile("/proc/" + ppid + "/comm")
			if err == nil {
				cmd := strings.TrimSpace(string(commData))
				parentCmds[cmd]++
			}
		}
	}

	// Determine severity based on count
	severity := "info"
	if zombieCount >= 20 {
		severity = "critical"
	} else if zombieCount >= 6 {
		severity = "medium"
	}

	passed := zombieCount < 6

	// Build parent summary
	parentSummary := ""
	for cmd, count := range parentCmds {
		if parentSummary != "" {
			parentSummary += ", "
		}
		parentSummary += fmt.Sprintf("%s(%d)", cmd, count)
	}
	if parentSummary == "" {
		parentSummary = "none"
	}

	details := map[string]string{
		"count":   fmt.Sprintf("%d", zombieCount),
		"parents": parentSummary,
	}

	findings = append(findings, Finding{
		Category:       "processes",
		Severity:       severity,
		CheckID:        "PROC_ZOMBIES",
		Title:          "Zombie processes",
		Description:    fmt.Sprintf("Found %d zombie process(es) on the system", zombieCount),
		Recommendation: "Investigate parent processes that are not reaping child processes",
		Details:        details,
		Passed:         passed,
	})

	return findings
}
