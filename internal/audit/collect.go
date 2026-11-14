package audit

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/infrafence/infrafence-agent/internal/authlog"
	"github.com/infrafence/infrafence-agent/internal/loginhistory"
	"github.com/infrafence/infrafence-agent/internal/monitor"
	"github.com/infrafence/infrafence-agent/internal/netstate"
	"github.com/infrafence/infrafence-agent/internal/phpconf"
	"github.com/infrafence/infrafence-agent/internal/preflight"
	"github.com/infrafence/infrafence-agent/internal/scanner"
	"github.com/infrafence/infrafence-agent/internal/watcher"
)

// Deadline bounds the reading of the host (the contract allows 60 seconds
// in all; the rest is for the upload, and cmd's watchdog ends the process
// at HardLimit whatever happens).
const (
	Deadline  = 40 * time.Second
	HardLimit = 58 * time.Second
)

// Options of one audit.
type Options struct {
	Version string
	// TempDir is the only place the audit may write (the package manager's
	// log, when it insists on writing one). Collect creates and removes it
	// when empty.
	TempDir string
	Now     func() time.Time
}

// Commands get a fixed environment and their own process group, killed
// as a whole at their timeout; their output is capped.
var cmdEnv = []string{"PATH=" + SystemPath, "LC_ALL=C"}

// SystemPath is the only PATH of an audit run: the directories run()
// searches.
const SystemPath = "/usr/sbin:/usr/bin:/sbin:/bin"

// PinPath sets this process's PATH to SystemPath. The shared helpers the
// audit calls (preflight, phpconf, scanner, netstate, monitor, watcher)
// exec some commands by bare name (sshd, systemctl, ss, nginx...), which
// exec.LookPath resolves against the process's PATH when the command is
// made: pinned, a "." or a writable directory in root's PATH can't run a
// planted program, and their children get this PATH too. Only the audit
// command calls it; the installed agent's PATH is unchanged.
func PinPath() error { return os.Setenv("PATH", SystemPath) }

const maxCmdOutput = 4 << 20

// cappedBuffer keeps the first max bytes written to it.
type cappedBuffer struct {
	bytes.Buffer
	max int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.Len(); room > 0 {
		if len(p) > room {
			b.Buffer.Write(p[:room])
		} else {
			b.Buffer.Write(p)
		}
	}
	return len(p), nil
}

// run runs a query command and returns its standard output and exit code
// (-1 when it could not run or was killed).
func run(ctx context.Context, timeout time.Duration, name string, args ...string) (string, int) {
	// Only the system directories, never root's PATH (a "." or a
	// writable directory in it would run a planted program as root).
	path := ""
	for _, dir := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		if info, e := os.Stat(dir + "/" + name); e == nil && info.Mode().IsRegular() {
			path = dir + "/" + name
			break
		}
	}
	if path == "" {
		return "", -1
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = cmdEnv
	cmd.Stdin = nil
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 2 * time.Second
	out := &cappedBuffer{max: maxCmdOutput}
	cmd.Stdout = out
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return out.String(), 0
	case errors.As(err, &exit) && ctx.Err() == nil:
		return out.String(), exit.ExitCode()
	default:
		return out.String(), -1
	}
}

// Collect reads the host and returns the sanitized, validated report.
func Collect(ctx context.Context, o Options) (*Report, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	ctx, cancel := context.WithTimeout(ctx, Deadline)
	defer cancel()
	now := o.Now().UTC()
	r := &Report{
		Schema:       Schema,
		AgentVersion: o.Version,
		GeneratedAt:  now.Format(time.RFC3339),
		Checks:       []Check{},
		Listening:    []Listener{},
	}

	// The logs take the longest: read them while the rest runs.
	type attacks struct {
		ssh *sshCounter
		web *counter
	}
	logs := make(chan attacks, 1)
	go func() {
		ssh, web := readAttacks(ctx, now)
		logs <- attacks{ssh, web}
	}()

	r.OS = readOS()
	pre := preflight.Scan()
	managers := splitList(pre.Facts["firewall_managers"])
	panel := preflight.DetectPanel()
	r.Environment.Panel = "none"
	if panel.Found() {
		r.Environment.Panel = panel.ID
	}
	services := monitor.DetectListeningServices()
	r.Environment.WebServer = webServer(services, splitList(pre.Facts["web_servers"]))
	r.Environment.Containers = pre.Decisions.Docker || exists("/run/podman/podman.sock")

	r.Listening = listening(services)

	// Checks.
	sshPorts := netstate.SSHPorts()
	port22 := false
	for _, p := range sshPorts {
		if p == 22 {
			port22 = len(watcher.ExposedPortList([]watcher.PortService{{Port: 22, Name: "SSH"}})) > 0
		}
	}
	r.Checks = append(r.Checks, MapSSH(scanner.SSHChecks(), port22)...)
	r.Checks = append(r.Checks, MapExposed(watcher.ExposedPortList(dbPorts), watcher.ExposedPortList(adminPorts))...)

	pm := pre.Facts["package_manager"]
	r.Updates = readUpdates(ctx, pm, o.TempDir, r.OS.Kernel)
	r.Checks = append(r.Checks, MapUpdates(r.Updates, pmName(pm), r.OS.ID, r.OS.Version, scanner.OSEndOfLife(r.OS.ID, r.OS.Version))...)

	r.Protection = Protection{
		Firewall:   detectFirewall(ctx, managers),
		Fail2ban:   contains(managers, "fail2ban"),
		CSF:        contains(managers, "csf"),
		InfraFence: infraFenceRunning(),
	}
	r.Checks = append(r.Checks, MapProtection(r.Protection, contains(managers, "crowdsec"))...)
	r.Checks = append(r.Checks, MapUsers(scanner.UserChecks())...)
	ww, scanned, complete := worldWritable(ctx, worldWritableRoots, maxWalkEntries)
	ww = topDirs(ww, worldWritableRoots)
	r.Checks = append(r.Checks, MapWorldWritable(ww, scanned, complete))
	r.Checks = append(r.Checks, MapFilePermissions(scanner.FilePermissionChecks(), statMeta("/etc/ssh/sshd_config")))
	h := phpconf.Discover(phpconf.System)
	r.Checks = append(r.Checks, MapPHP(len(h.Runtimes), phpconf.Check(h, phpconf.Options{})))

	// The readers stop at the deadline; one blocked in a system call
	// can't hold the report back.
	var att attacks
	select {
	case att = <-logs:
	case <-ctx.Done():
		select {
		case att = <-logs:
		case <-time.After(2 * time.Second):
			att = attacks{newSSHCounter(), newCounter()}
		}
	}
	ssh, web := att.ssh, att.web
	r.Attacks = Attacks{
		WindowHours:           reportWindowHours,
		SSHFailedLogins:       ssh.total,
		SSHUniqueIPs:          len(ssh.ips),
		WebSuspiciousRequests: web.total,
		WebUniqueIPs:          len(web.byIP),
		TopIPs:                topIPs(ssh.counter, web),
	}

	Sanitize(r, HostPrivate())
	if len(r.Attacks.TopIPs) > maxTopIPs {
		r.Attacks.TopIPs = r.Attacks.TopIPs[:maxTopIPs]
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func splitList(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

func osReleaseValue(content, key string) string {
	for _, l := range strings.Split(content, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), key+"="); ok {
			return strings.Trim(v, `"'`)
		}
	}
	return ""
}

func readOS() OS {
	o := OS{Arch: runtime.GOARCH}
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		o.ID = osReleaseValue(string(b), "ID")
		o.Version = osReleaseValue(string(b), "VERSION_ID")
	}
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		o.Kernel = strings.TrimSpace(string(b))
	}
	return o
}

// webServer is the web server answering on 80 or 443, else the first one
// installed, else "none".
func webServer(services []monitor.ListeningService, installed []string) string {
	norm := func(p string) string {
		switch {
		case p == "nginx" || strings.HasPrefix(p, "nginx"):
			return "nginx"
		case p == "apache2" || p == "httpd":
			return "apache"
		case strings.HasPrefix(p, "litespeed") || strings.HasPrefix(p, "lshttpd") || strings.HasPrefix(p, "openlitespeed"):
			return "litespeed"
		case p == "caddy", p == "traefik", p == "haproxy", p == "envoy":
			return p
		case p == "docker-proxy":
			return "container"
		}
		return ""
	}
	for _, s := range services {
		if s.Port == 80 || s.Port == 443 {
			if n := norm(s.Process); n != "" {
				return n
			}
		}
	}
	for _, w := range installed {
		if n := norm(strings.Fields(w + " ")[0]); n != "" {
			return n
		}
		if strings.Contains(strings.ToLower(w), "litespeed") {
			return "litespeed"
		}
	}
	return "none"
}

// listening is the listening TCP ports, public when they listen on a
// public or on every address (the DB-exposure rules, watcher).
func listening(services []monitor.ListeningService) []Listener {
	table := make([]watcher.PortService, 0, len(services))
	for _, s := range services {
		table = append(table, watcher.PortService{Port: s.Port})
	}
	public := map[int]bool{}
	for _, x := range watcher.ExposedPortList(table) {
		public[x.Port] = true
	}
	out := []Listener{}
	for _, s := range services {
		proto := "tcp"
		if s.Proto == "tcp6" {
			proto = "tcp6"
		}
		out = append(out, Listener{Port: s.Port, Proto: proto, Process: s.Process, Public: public[s.Port]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	if len(out) > maxListening {
		out = out[:maxListening]
	}
	return out
}

// ── updates ──

func pmName(pm string) string {
	switch pm {
	case "apt-get":
		return "apt"
	case "":
		return "none"
	}
	return pm
}

// readUpdates counts pending updates from the package manager's cache
// only: apt-get's simulation (no lock, no cache file written, its log in
// the audit's temp dir) or dnf/yum in cache-only mode with their log in the
// audit's temp dir. Nothing is
// downloaded; a cache too old says less than a fresh one, never more.
func readUpdates(ctx context.Context, pm, tmp, kernel string) Updates {
	var u Updates
	u.RebootRequired = exists("/run/reboot-required") || exists("/var/run/reboot-required") || rpmKernelNewer(ctx, kernel)
	switch pm {
	case "apt-get":
		if lists, _ := filepath.Glob("/var/lib/apt/lists/*_Packages*"); len(lists) == 0 {
			return u
		}
		if tmp == "" {
			return u
		}
		// Dir::Log: apt writes its solver log (eipp.log.xz) even when it
		// only simulates; it goes to the audit's temp dir.
		out, code := run(ctx, 30*time.Second, "apt-get", "-s", "-q",
			"-o", "Debug::NoLocking=true", "-o", "Dir::Cache::pkgcache=", "-o", "Dir::Cache::srcpkgcache=",
			"-o", "Dir::Log="+tmp,
			"-o", "APT::Get::Show-User-Simulation-Note=false", "dist-upgrade")
		if code != 0 {
			return u
		}
		total, sec := aptCounts(out)
		u.Total, u.Security = &total, &sec
	case "dnf", "yum":
		if tmp == "" {
			return u
		}
		base := []string{"-C", "-q", "--setopt=logdir=" + tmp, "--setopt=persistdir=" + tmp, "--setopt=debuglevel=0"}
		out, code := run(ctx, 30*time.Second, pm, append(base, "check-update")...)
		if code != 0 && code != 100 {
			return u
		}
		total := rpmUpdateLines(out)
		secOut, code := run(ctx, 30*time.Second, pm, append(base, "updateinfo", "list", "--security")...)
		if code != 0 {
			return u
		}
		sec := securityLines(secOut)
		if sec > total {
			sec = total // advisories for versions already installed or superseded
		}
		u.Total, u.Security = &total, &sec
	}
	return u
}

// aptCounts counts the "Inst" lines of apt-get -s, and those from a
// security pocket.
func aptCounts(out string) (total, security int) {
	for _, l := range strings.Split(out, "\n") {
		if !strings.HasPrefix(l, "Inst ") {
			continue
		}
		total++
		if strings.Contains(strings.ToLower(l), "security") {
			security++
		}
	}
	return total, security
}

// rpmUpdateLines counts the package lines of dnf/yum check-update
// ("name.arch  version  repo"), up to an "Obsoleting" section.
func rpmUpdateLines(out string) int {
	n := 0
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "Obsoleting") {
			break
		}
		f := strings.Fields(l)
		if len(f) == 3 && strings.Contains(f[0], ".") && !strings.HasSuffix(l, ":") {
			n++
		}
	}
	return n
}

// securityLines counts the packages of `updateinfo list --security`
// (dnf 4: "ADVISORY  Severity/Sec.  package"; dnf 5: a header, then
// "ADVISORY  security  Severity  package  date"). Each package name counts
// once.
func securityLines(out string) int {
	seen := map[string]bool{}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) < 3 || strings.EqualFold(f[0], "Name") {
			continue
		}
		low := strings.ToLower(l)
		if !strings.Contains(low, "/sec") && !strings.Contains(low, "security") {
			continue
		}
		pkg := f[2]
		if len(f) >= 5 && strings.EqualFold(f[1], "security") {
			pkg = f[3]
		}
		seen[rpmName(pkg)] = true
	}
	return len(seen)
}

// rpmName is the package name of "name-[epoch:]version-release.arch": an
// advisory lists each fixed version, and several advisories can fix one
// package, which is still one update.
func rpmName(nevra string) string {
	for i := 0; i < 2; i++ {
		if j := strings.LastIndexByte(nevra, '-'); j > 0 {
			nevra = nevra[:j]
		}
	}
	return nevra
}

// rpmKernelNewer reports whether the most recently installed kernel
// package is not the running kernel (rpm -q, read-only).
func rpmKernelNewer(ctx context.Context, running string) bool {
	if running == "" {
		return false
	}
	out, code := run(ctx, 10*time.Second, "rpm", "-q", "--qf", "%{INSTALLTIME} %{VERSION}-%{RELEASE}.%{ARCH}\n", "kernel-core", "kernel")
	if code < 0 {
		return false
	}
	var newestT int64
	newest := ""
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) != 2 {
			continue
		}
		t, err := strconv.ParseInt(f[0], 10, 64)
		if err != nil {
			continue
		}
		if t > newestT {
			newestT, newest = t, f[1]
		}
	}
	return newest != "" && newest != running
}

// ── firewall ──

// detectFirewall names the firewall filtering incoming traffic: ufw or
// firewalld when active (preflight), iptables with CSF or with rules or a
// drop policy in INPUT, nftables with an input hook chain that filters,
// else "none".
func detectFirewall(ctx context.Context, managers []string) string {
	switch {
	case contains(managers, "ufw"):
		return "ufw"
	case contains(managers, "firewalld"):
		return "firewalld"
	case contains(managers, "csf"):
		return "iptables"
	}
	if out, code := run(ctx, 10*time.Second, "iptables", "-S", "INPUT"); code == 0 && iptablesFilters(out) {
		return "iptables"
	}
	if out, code := run(ctx, 10*time.Second, "nft", "list", "ruleset"); code == 0 && nftFilters(out) {
		return "nftables"
	}
	return "none"
}

// iptablesFilters: `iptables -S INPUT` has a rule or a non-ACCEPT policy.
func iptablesFilters(out string) bool {
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "-A INPUT") {
			return true
		}
		if strings.HasPrefix(l, "-P INPUT") && !strings.HasSuffix(l, "ACCEPT") {
			return true
		}
	}
	return false
}

// nftFilters: a chain hooked on input holds a rule or drops by policy.
func nftFilters(out string) bool {
	inChain, input, rules := false, false, 0
	for _, raw := range strings.Split(out, "\n") {
		l := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(l, "chain ") && strings.HasSuffix(l, "{"):
			inChain, input, rules = true, false, 0
		case !inChain:
		case l == "}":
			if input && rules > 0 {
				return true
			}
			inChain = false
		case strings.HasPrefix(l, "type ") && strings.Contains(l, "hook input"):
			input = true
			if strings.Contains(l, "policy drop") {
				rules++
			}
		case strings.HasPrefix(l, "policy "):
			if strings.Contains(l, "drop") {
				rules++
			}
		case l != "" && !strings.HasPrefix(l, "#") && !strings.HasPrefix(l, "comment "):
			rules++
		}
	}
	return false
}

// infraFenceRunning: an InfraFence agent runs on the host (its service,
// or the container image), read from /proc.
func infraFenceRunning() bool {
	self := os.Getpid()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err != nil || len(b) == 0 {
			continue
		}
		args := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
		if len(args) >= 2 && filepath.Base(args[0]) == "infrafence-agent" && args[1] == "start" {
			return true
		}
	}
	return false
}

// ── world-writable system files ──

var worldWritableRoots = []string{"/etc", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/usr/lib/systemd/system", "/bin", "/sbin"}

const maxWalkEntries = 60000

// worldWritable lists the regular files and the directories without the
// sticky bit that anyone may write, under roots (symlinks are not
// followed; a root that is a symlink, like /bin on merged-/usr systems, is
// skipped). It stops after max entries or at ctx.
func worldWritable(ctx context.Context, roots []string, max int) (found []string, scanned int, complete bool) {
	complete = true
	stop := errors.New("stop")
	for _, root := range roots {
		info, err := os.Lstat(root)
		if err != nil || !info.IsDir() {
			continue
		}
		err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			scanned++
			if scanned > max || (scanned%2048 == 0 && ctx.Err() != nil) {
				return stop
			}
			t := d.Type()
			if t&fs.ModeSymlink != 0 || (!t.IsRegular() && !t.IsDir()) {
				return nil
			}
			fi, err := d.Info()
			if err != nil {
				return nil
			}
			m := fi.Mode()
			if m.Perm()&0o002 == 0 || (m.IsDir() && m&fs.ModeSticky != 0) {
				return nil
			}
			found = append(found, p)
			return nil
		})
		if err != nil {
			complete = false
			break
		}
	}
	sort.Strings(found)
	return found, scanned, complete
}

// topDirs replaces each path by the scanned root it is under ("/etc",
// "/usr/bin"): a file name under /etc can name a customer's site, a root
// can't. One entry per file, so the count stays.
func topDirs(paths, roots []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		top := "other"
		for _, r := range roots {
			if p == r || strings.HasPrefix(p, r+"/") {
				top = r
				break
			}
		}
		out = append(out, top)
	}
	return out
}

// ── attacks ──

// readAttacks reads the last Window of SSH and web logs.
func readAttacks(ctx context.Context, now time.Time) (*sshCounter, *counter) {
	since := now.Add(-Window)
	ssh := newSSHCounter()
	src := authlog.Detect()
	if src.Journal {
		readJournal(ctx, since, ssh.line)
	} else {
		for _, p := range authFiles(src.Path, since) {
			rc, mtime, err := openTail(p, maxAuthFileBytes)
			if err != nil {
				continue
			}
			scanLines(ctx, rc, since, mtime, loginhistory.LineTime, ssh.line)
			_ = rc.Close()
		}
	}
	ssh.finish()

	web := newCounter()
	infos, _ := watcher.DetectWebLogInfo()
	var total int64
	files := 0
	for _, info := range infos {
		if files >= maxWebFiles || total >= maxWebTotalBytes || ctx.Err() != nil {
			break
		}
		if strings.Contains(info.Path, "://") {
			continue // a container's output: not a file on this host
		}
		budget := maxWebFileBytes
		if left := maxWebTotalBytes - total; left < budget {
			budget = left
		}
		rc, mtime, err := openTail(info.Path, budget)
		if err != nil {
			continue
		}
		if mtime.Before(since) {
			_ = rc.Close()
			continue
		}
		files++
		cr := &countingReader{r: rc}
		server := info.Server
		scanLines(ctx, cr, since, mtime, webTime, func(line string) {
			if ip, _, ok := watcher.SuspiciousRequest(line, server); ok {
				web.add(ip)
			}
		})
		total += cr.n
		_ = rc.Close()
	}
	return ssh, web
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// readJournal reads the auth and authpriv messages of the window from the
// journal (journalctl, read-only), at most maxJournalBytes.
func readJournal(ctx context.Context, since time.Time, fn func(string)) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	bin := ""
	for _, p := range []string{"/usr/bin/journalctl", "/bin/journalctl"} {
		if exists(p) {
			bin = p
			break
		}
	}
	if bin == "" {
		return
	}
	cmd := exec.CommandContext(ctx, bin, "--no-pager", "--quiet", "--output=short-iso",
		"--since=@"+strconv.FormatInt(since.Unix(), 10), "SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10")
	cmd.Env = cmdEnv
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 2 * time.Second
	out, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	if err := cmd.Start(); err != nil {
		return
	}
	scanLines(ctx, io.LimitReader(out, maxJournalBytes), since, time.Now(), loginhistory.LineTime, fn)
	// Past the limit, stop journalctl instead of waiting for it.
	cancel()
	_ = cmd.Wait()
}

// statMeta stats path (following links, as sshd reads it).
func statMeta(path string) FileMeta {
	info, err := os.Stat(path)
	if err != nil {
		return FileMeta{}
	}
	m := FileMeta{Exists: true, Perm: info.Mode().Perm(), UID: -1}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		m.UID = int(st.Uid)
	}
	return m
}
