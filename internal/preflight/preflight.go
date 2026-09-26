// Package preflight inspects a host before InfraFence changes anything on it.
// It is strictly read-only: it runs query commands and reads files, and never
// modifies packages, firewall rules, services or configuration. The installer
// runs it before installing, and the agent at startup and daily, to decide
// what it may safely change on a production server.
package preflight

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Level of a finding.
type Level string

const (
	OK    Level = "ok"
	Info  Level = "info"
	Warn  Level = "warn"
	Block Level = "block" // InfraFence cannot enforce on this host
)

// Finding is one observation about the host.
type Finding struct {
	ID     string `json:"id"`
	Level  Level  `json:"level"`
	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"`
}

// Decisions are what the agent/installer may safely do on this host.
type Decisions struct {
	// Firewall enforcement is possible (iptables usable, running as root).
	FirewallEnforcement bool `json:"firewall_enforcement"`
	// ipset is installed (large ban lists, threat feeds, country blocks).
	Ipset bool `json:"ipset"`
	// The installer may install ipset: a package manager exists and no
	// package operation is running right now.
	IpsetInstallSafe bool `json:"ipset_install_safe"`
	// Editing web server configuration (UA blocking, ModSecurity rules) is
	// safe: no hosting panel or configuration management owns those files.
	WebserverChangesSafe   bool   `json:"webserver_changes_safe"`
	WebserverChangesReason string `json:"webserver_changes_reason,omitempty"`
	// Docker is present: container ports are protected via DOCKER-USER.
	Docker bool `json:"docker"`
}

// Report is the full preflight result.
type Report struct {
	Time      time.Time         `json:"time"`
	Facts     map[string]string `json:"facts"`
	Findings  []Finding         `json:"findings"`
	Decisions Decisions         `json:"decisions"`
}

// Worst returns the most severe level among findings.
func (r Report) Worst() Level {
	worst := OK
	rank := map[Level]int{OK: 0, Info: 1, Warn: 2, Block: 3}
	for _, f := range r.Findings {
		if rank[f.Level] > rank[worst] {
			worst = f.Level
		}
	}
	return worst
}

// Env abstracts the host so the logic can be tested.
type Env interface {
	Run(name string, args ...string) (string, error)
	LookPath(name string) bool
	ReadFile(path string) (string, error)
	Exists(path string) bool
	Glob(pattern string) []string
	IsRoot() bool
}

type hostEnv struct{}

func (hostEnv) Run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	done := make(chan struct{})
	var out []byte
	var err error
	go func() {
		out, err = cmd.CombinedOutput()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		<-done
	}
	return strings.TrimSpace(string(out)), err
}
func (hostEnv) LookPath(name string) bool { _, err := exec.LookPath(name); return err == nil }
func (hostEnv) ReadFile(p string) (string, error) {
	b, err := os.ReadFile(p)
	return string(b), err
}
func (hostEnv) Exists(p string) bool         { _, err := os.Stat(p); return err == nil }
func (hostEnv) Glob(pattern string) []string { m, _ := filepath.Glob(pattern); return m }
func (hostEnv) IsRoot() bool                 { return os.Geteuid() == 0 }

// Scan inspects the current host.
func Scan() Report { return ScanEnv(hostEnv{}) }

// ScanEnv inspects the host through env.
func ScanEnv(env Env) Report {
	r := Report{Time: time.Now().UTC(), Facts: map[string]string{}}
	add := func(id string, l Level, title, detail string) {
		r.Findings = append(r.Findings, Finding{ID: id, Level: l, Title: title, Detail: detail})
	}
	active := func(unit string) bool {
		if !env.LookPath("systemctl") {
			return false
		}
		out, _ := env.Run("systemctl", "is-active", unit)
		return strings.TrimSpace(out) == "active"
	}

	// ── System ──
	r.Facts["arch"] = runtime.GOARCH
	if osr, err := env.ReadFile("/etc/os-release"); err == nil {
		r.Facts["os"] = osReleaseField(osr, "PRETTY_NAME")
	}
	if k, err := env.Run("uname", "-r"); err == nil {
		r.Facts["kernel"] = k
	}
	switch {
	case env.LookPath("systemctl") && env.Exists("/run/systemd/system"):
		r.Facts["init"] = "systemd"
	case env.LookPath("initctl"):
		r.Facts["init"] = "upstart"
	default:
		r.Facts["init"] = "sysvinit"
	}
	if !env.IsRoot() {
		add("root", Block, "Not running as root", "Firewall and log access need root.")
	}

	// ── Firewall stack ──
	d := &r.Decisions
	if !env.LookPath("iptables") || !env.LookPath("iptables-restore") {
		add("iptables", Block, "iptables not installed", "InfraFence enforces bans through iptables; detection still works.")
	} else {
		v, _ := env.Run("iptables", "-V")
		r.Facts["iptables"] = v
		if _, err := env.Run("iptables", "-S", "INPUT"); err != nil && env.IsRoot() {
			add("iptables", Block, "iptables is not usable", v)
		} else {
			d.FirewallEnforcement = env.IsRoot()
			backend := "legacy"
			if strings.Contains(v, "nf_tables") {
				backend = "nf_tables"
			}
			r.Facts["iptables_backend"] = backend
			add("iptables", OK, "iptables available ("+backend+")", "")
		}
	}
	d.Ipset = env.LookPath("ipset")
	if d.Ipset {
		add("ipset", OK, "ipset available", "Large ban lists, threat feeds and country blocks are enforced in the kernel.")
	} else {
		add("ipset", Warn, "ipset not installed",
			"Bans fall back to individual iptables rules (max ~500); threat-feed and country blocking are detection-only.")
	}

	var managers []string
	if active("ufw") {
		if out, _ := env.Run("ufw", "status"); strings.Contains(out, "Status: active") {
			managers = append(managers, "ufw")
			add("ufw", Info, "ufw is active",
				"InfraFence jumps to its chain ahead of ufw's rules; a ufw reload is repaired within a minute.")
		}
	}
	if active("firewalld") {
		backend := "unknown"
		if conf, err := env.ReadFile("/etc/firewalld/firewalld.conf"); err == nil {
			if b := confValue(conf, "FirewallBackend"); b != "" {
				backend = b
			}
		}
		managers = append(managers, "firewalld")
		lvl, detail := Info, "firewalld ("+backend+" backend) keeps its own rules; InfraFence's chain is independent."
		if backend == "iptables" {
			lvl, detail = Warn, "firewalld with the iptables backend removes other rules on reload; InfraFence restores them within a minute."
		}
		add("firewalld", lvl, "firewalld is active", detail)
	}
	if env.Exists("/etc/csf/csf.conf") {
		managers = append(managers, "csf")
		add("csf", Warn, "CSF firewall detected",
			"csf -r rebuilds the whole firewall; InfraFence restores its chain within a minute of each restart.")
	}
	if active("fail2ban") {
		managers = append(managers, "fail2ban")
		add("fail2ban", Info, "fail2ban is active", "Compatible: both only drop traffic; they don't conflict.")
	}
	if active("crowdsec") || active("crowdsec-firewall-bouncer") {
		managers = append(managers, "crowdsec")
		add("crowdsec", Info, "CrowdSec is active", "Compatible: both only drop traffic; they don't conflict.")
	}
	if active("netfilter-persistent") || active("iptables") {
		managers = append(managers, "iptables-persistent")
		add("persistent", Info, "Saved iptables rules are restored at boot",
			"If InfraFence's rules end up in a saved ruleset they're simply re-checked; the guard keeps them consistent.")
	}
	if active("docker") || env.Exists("/var/run/docker.sock") {
		d.Docker = true
		managers = append(managers, "docker")
		add("docker", Info, "Docker detected", "Published container ports are protected through the DOCKER-USER chain.")
	}
	if env.Exists("/var/lib/kubelet") || active("kubelet") || active("k3s") {
		managers = append(managers, "kubernetes")
		add("kubernetes", Warn, "Kubernetes node detected",
			"CNI plugins manage their own rules; pod traffic may not traverse INPUT or DOCKER-USER.")
	}
	sort.Strings(managers)
	r.Facts["firewall_managers"] = strings.Join(managers, ",")

	// ── Web server & ownership of its configuration ──
	var web []string
	for _, b := range []string{"nginx", "apache2", "httpd", "caddy"} {
		if env.LookPath(b) {
			web = append(web, b)
		}
	}
	// LiteSpeed lives in /usr/local/lsws/bin, normally not in PATH. The
	// Enterprise edition keeps Apache's httpd binary around for its config,
	// so "httpd" alone doesn't mean Apache serves the sites.
	ls := detectLiteSpeed(env)
	if ls.Installed() {
		state := "running"
		if !ls.Running {
			state = "installed, not running"
		}
		r.Facts["litespeed"] = strings.Join(strings.Fields(ls.Edition+" "+ls.Version), " ") + " (" + state + ")"
		if ls.Running {
			web = append(web, ls.Name())
		}
	}
	r.Facts["web_servers"] = strings.Join(web, ",")
	panel := detectPanel(env)
	r.Facts["panel"] = panel
	managed := managedConfigFiles(env)
	if ls.Running {
		detail := "Protection works through firewall bans and log analysis. InfraFence doesn't edit LiteSpeed's configuration yet: " +
			"bots set to \"block\" are banned at the firewall instead of in the web server, and InfraFence doesn't install ModSecurity rules."
		if ls.Edition == "enterprise" {
			detail += " LiteSpeed Enterprise reads Apache's configuration, so InfraFence must not reload Apache here."
		}
		add("litespeed", Info, "LiteSpeed serves the sites ("+ls.Edition+")", detail)
	}
	switch {
	case len(web) == 0:
		d.WebserverChangesReason = "no supported web server"
	case ls.Running:
		d.WebserverChangesReason = "LiteSpeed (" + ls.Edition + ") serves the sites; InfraFence doesn't edit its configuration"
	case panel != "":
		d.WebserverChangesReason = panel + " manages the web server configuration and may overwrite edits"
		add("panel", Warn, "Hosting panel detected: "+panel,
			"InfraFence won't edit web server config; bot blocking uses firewall bans instead.")
	case len(managed) > 0:
		d.WebserverChangesReason = "configuration management markers in " + strings.Join(managed, ", ")
		add("config_mgmt", Warn, "Web server config is managed by a tool",
			"Found 'managed' markers (Ansible/Puppet/Chef/Salt) in: "+strings.Join(managed, ", ")+". InfraFence won't edit it.")
	default:
		d.WebserverChangesSafe = true
	}

	// ── Package manager ──
	pm := ""
	for _, p := range []string{"apt-get", "dnf", "yum", "zypper", "apk"} {
		if env.LookPath(p) {
			pm = p
			break
		}
	}
	r.Facts["package_manager"] = pm
	busy := runningPackageOps(env)
	if len(busy) > 0 {
		add("pkg_busy", Info, "A package operation is running: "+strings.Join(busy, ", "),
			"InfraFence won't install packages until it finishes.")
	}
	d.IpsetInstallSafe = !d.Ipset && pm != "" && pm != "apk" && len(busy) == 0

	// ── Resources ──
	if free, ok := diskFreeMB("/"); ok {
		r.Facts["disk_free_mb"] = strconv.FormatUint(free, 10)
		if free < 200 {
			add("disk", Warn, "Low disk space on /", strconv.FormatUint(free, 10)+" MB free")
		}
	}
	if mi, err := env.ReadFile("/proc/meminfo"); err == nil {
		if kb := meminfoKB(mi, "MemAvailable"); kb > 0 {
			r.Facts["mem_available_mb"] = strconv.FormatUint(kb/1024, 10)
			if kb/1024 < 128 {
				add("memory", Warn, "Low available memory", strconv.FormatUint(kb/1024, 10)+" MB")
			}
		}
	}
	if env.LookPath("getenforce") {
		if m, err := env.Run("getenforce"); err == nil {
			r.Facts["selinux"] = strings.ToLower(m)
		}
	}
	return r
}

func osReleaseField(s, key string) string {
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(l, key+"=") {
			return strings.Trim(strings.TrimPrefix(l, key+"="), `"`)
		}
	}
	return ""
}

func confValue(s, key string) string {
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, key+"=") {
			return strings.TrimSpace(strings.TrimPrefix(l, key+"="))
		}
	}
	return ""
}

func detectPanel(env Env) string {
	for _, p := range []struct{ path, name string }{
		{"/usr/local/cpanel", "cPanel"},
		{"/usr/local/psa", "Plesk"},
		{"/usr/local/directadmin", "DirectAdmin"},
		{"/usr/local/CyberCP", "CyberPanel"},
		{"/usr/local/hestia", "HestiaCP"},
		{"/usr/local/vesta", "VestaCP"},
		{"/usr/local/ispconfig", "ISPConfig"},
		{"/home/clp", "CloudPanel"},
		{"/etc/webmin/virtual-server", "Virtualmin"},
		{"/data/coolify", "Coolify"},
		{"/etc/runcloud", "RunCloud"},
		{"/etc/gridpane", "GridPane"},
		{"/opt/bitnami", "Bitnami"},
	} {
		if env.Exists(p.path) {
			return p.name
		}
	}
	return ""
}

var managedMarkers = []string{"Ansible managed", "managed by Ansible", "Managed by Puppet", "managed by puppet",
	"managed by Chef", "Generated by Chef", "managed by Salt", "This file is managed by", "DO NOT EDIT"}

// managedConfigFiles returns web server config files carrying a
// configuration-management marker (checks at most 200 files, first 4 KB).
func managedConfigFiles(env Env) []string {
	var files []string
	for _, pat := range []string{"/etc/nginx/nginx.conf", "/etc/nginx/conf.d/*.conf", "/etc/nginx/sites-enabled/*",
		"/etc/apache2/apache2.conf", "/etc/apache2/sites-enabled/*", "/etc/httpd/conf/httpd.conf", "/etc/httpd/conf.d/*.conf"} {
		files = append(files, env.Glob(pat)...)
	}
	var out []string
	for i, f := range files {
		if i >= 200 {
			break
		}
		if strings.Contains(filepath.Base(f), "infrafence") {
			continue
		}
		s, err := env.ReadFile(f)
		if err != nil {
			continue
		}
		if len(s) > 4096 {
			s = s[:4096]
		}
		for _, m := range managedMarkers {
			if strings.Contains(s, m) {
				out = append(out, f)
				break
			}
		}
	}
	return out
}

// packageLocks are held (fcntl) by apt, dpkg and unattended-upgrade while
// they actually work.
var packageLocks = []string{
	"/var/lib/dpkg/lock-frontend",
	"/var/lib/dpkg/lock",
	"/var/lib/apt/lists/lock",
	"/var/cache/apt/archives/lock",
}

// runningPackageOps lists package operations in progress: a package manager
// process, or a dpkg/apt lock that is actually held. Idle daemons don't
// count: unattended-upgrade-shutdown runs permanently on Ubuntu (its process
// name is "unattended-upgr") and packagekitd idles in the background.
func runningPackageOps(env Env) []string {
	var busy []string
	if env.LookPath("pgrep") {
		for _, p := range []string{"apt", "apt-get", "dpkg", "dnf", "yum", "rpm", "zypper"} {
			if out, err := env.Run("pgrep", "-x", p); err == nil && out != "" {
				busy = append(busy, p)
			}
		}
	}
	for _, h := range packageLockHolders(env) {
		if !contains(busy, h) {
			busy = append(busy, h)
		}
	}
	return busy
}

// packageLockHolders returns the processes holding a package-manager lock,
// read from /proc/locks (read-only: no lock is taken).
func packageLockHolders(env Env) []string {
	locks, err := env.ReadFile("/proc/locks")
	if err != nil {
		return nil
	}
	// "1: POSIX  ADVISORY  WRITE 1234 fd:01:5678 0 EOF" -> inode 5678 held by pid 1234
	held := map[string]string{}
	for _, line := range strings.Split(locks, "\n") {
		f := strings.Fields(line)
		for i := 1; i < len(f); i++ {
			if parts := strings.Split(f[i], ":"); len(parts) == 3 {
				held[parts[2]] = f[i-1]
				break
			}
		}
	}
	var out []string
	for _, lock := range packageLocks {
		if !env.Exists(lock) {
			continue
		}
		ino, err := env.Run("stat", "-c", "%i", lock)
		if err != nil || ino == "" {
			continue
		}
		pid, ok := held[strings.TrimSpace(ino)]
		if !ok {
			continue
		}
		name := "pid " + pid
		if comm, err := env.ReadFile("/proc/" + pid + "/comm"); err == nil && strings.TrimSpace(comm) != "" {
			name = strings.TrimSpace(comm)
		}
		if !contains(out, name) {
			out = append(out, name)
		}
	}
	return out
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func meminfoKB(s, key string) uint64 {
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 2 && strings.TrimSuffix(f[0], ":") == key {
			v, _ := strconv.ParseUint(f[1], 10, 64)
			return v
		}
	}
	return 0
}

func diskFreeMB(path string) (uint64, bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, false
	}
	return st.Bavail * uint64(st.Bsize) / (1 << 20), true
}
