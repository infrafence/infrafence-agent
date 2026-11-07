package watcher

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/infrafence/infrafence-agent/internal/netstate"
)

// DBPattern pairs a compiled regex with the event reason.
type DBPattern struct {
	Re     *regexp.Regexp
	Reason string
}

// dbPatterns contains all database auth detection patterns.
// Each regex must have a capture group for the IP address.
//
// MySQL / MariaDB:
//   - "Access denied for user 'root'@'X.X.X.X'"
//   - "Host 'X.X.X.X' is blocked because of many connection errors"
//   - "Aborted connection ... (Got an error reading communication packets) host: 'X.X.X.X'"
//
// PostgreSQL:
//   - "FATAL: password authentication failed for user ... connection ... host=X.X.X.X"
//   - "FATAL: no pg_hba.conf entry for host \"X.X.X.X\""
//   - "LOG: could not receive data from client: Connection reset by peer ... host=X.X.X.X"
//
// MongoDB:
//   - "Failed to authenticate ... client: X.X.X.X"
//   - "Unauthorized ... client: X.X.X.X"
var dbPatterns = []DBPattern{
	// ── MySQL / MariaDB ───────────────────────────────────────────────
	{Re: regexp.MustCompile(`Access denied for user '\S+'@'([\d.]+)'`), Reason: "db_brute_force"},
	{Re: regexp.MustCompile(`Host '([\d.]+)' is blocked because of many connection errors`), Reason: "db_brute_force"},
	{Re: regexp.MustCompile(`Aborted connection.*host:\s*'([\d.]+)'`), Reason: "db_suspicious"},

	// ── PostgreSQL ────────────────────────────────────────────────────
	{Re: regexp.MustCompile(`FATAL:\s+password authentication failed for user.*host[= ]+"?([\d.]+)`), Reason: "db_brute_force"},
	{Re: regexp.MustCompile(`FATAL:\s+no pg_hba\.conf entry for host "?([\d.]+)`), Reason: "db_brute_force"},
	{Re: regexp.MustCompile(`could not receive data from client.*host[= ]+"?([\d.]+)`), Reason: "db_suspicious"},

	// ── MongoDB ───────────────────────────────────────────────────────
	{Re: regexp.MustCompile(`(?:Failed to authenticate|Authentication failed).*client:\s*([\d.]+)`), Reason: "db_brute_force"},
	{Re: regexp.MustCompile(`Unauthorized.*client:\s*([\d.]+)`), Reason: "db_brute_force"},
}

// DBLogPath holds a detected database log path and its type.
type DBLogPath struct {
	Path   string
	DBType string // "mysql", "postgresql", "mongodb"
}

// DBWatcher tails database logs and calls onBan when an IP exceeds the threshold.
type DBWatcher struct {
	logPaths []DBLogPath
	onBan    BanFunc
	onEvent  EventFunc
	checkIP  CheckIPFunc
	// knownClient says why an address must not be banned ("": it may be):
	// a known client of a database port. See SetKnownClient.
	knownClient func(ip string) string

	mu          sync.Mutex
	threshold   int
	window      time.Duration
	attempts    map[string][]time.Time
	banned      map[string]bool
	whitelist   map[string]bool
	wlNets      []*net.IPNet
	monitorMode bool
	// knownSeen: the guard's answer per address, for one window. dropped:
	// the dropped connections (db_suspicious) per address, reported once a
	// window.
	knownSeen map[string]*dbKnown
	dropped   map[string]*dbDropped
}

// dbKnown is the guard's answer for an address, asked at since.
type dbKnown struct {
	since time.Time
	why   string
	// geo: the country ban it was spared was reported.
	geo bool
}

// dbDropped counts the dropped connections of an address since the window
// that started at since was reported.
type dbDropped struct {
	since time.Time
	lines int
}

// dbMaxEntries bounds each per-address map of the watcher.
const dbMaxEntries = 50000

// detectDBLogPaths returns all detected database log paths.
func detectDBLogPaths() []DBLogPath {
	if p := os.Getenv("DB_LOG_PATH"); p != "" {
		return []DBLogPath{{Path: p, DBType: "custom"}}
	}

	var paths []DBLogPath

	// MySQL / MariaDB
	mysqlPaths := []string{
		"/var/log/mysql/error.log",
		"/var/log/mysqld.log",
		"/var/log/mariadb/mariadb.log",
		"/var/log/mysql/mysql-error.log",
	}
	for _, p := range mysqlPaths {
		if _, err := os.Stat(p); err == nil {
			paths = append(paths, DBLogPath{Path: p, DBType: "mysql"})
			break // one MySQL log is enough
		}
	}

	// PostgreSQL
	pgPaths := []string{
		"/var/log/postgresql/postgresql-main.log",
		"/var/log/postgresql/postgresql.log",
	}
	for _, p := range pgPaths {
		if _, err := os.Stat(p); err == nil {
			paths = append(paths, DBLogPath{Path: p, DBType: "postgresql"})
			break
		}
	}
	// Also check pg_log directories (version-specific)
	pgDirs := []string{"/var/lib/pgsql/data/pg_log", "/var/lib/pgsql/data/log"}
	for _, dir := range pgDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".log") {
				paths = append(paths, DBLogPath{Path: dir + "/" + e.Name(), DBType: "postgresql"})
				break
			}
		}
		break
	}

	// MongoDB
	mongoPaths := []string{
		"/var/log/mongodb/mongod.log",
		"/var/log/mongod.log",
	}
	for _, p := range mongoPaths {
		if _, err := os.Stat(p); err == nil {
			paths = append(paths, DBLogPath{Path: p, DBType: "mongodb"})
			break
		}
	}

	return paths
}

// HasDBService returns true if a database server is detected.
func HasDBService() bool {
	for _, svc := range []string{"mysql", "mysqld", "mariadb", "postgresql", "mongod"} {
		if out, err := exec.Command("systemctl", "is-active", svc).Output(); err == nil {
			if strings.TrimSpace(string(out)) == "active" {
				return true
			}
		}
	}
	return len(detectDBLogPaths()) > 0
}

// ExposedDBPort is a database port reachable from the internet: listening
// on all addresses (0.0.0.0, [::]) or on a public address of the host.
type ExposedDBPort struct {
	Port    int
	Service string // MySQL/MariaDB, PostgreSQL, MongoDB, Redis
	Warning string
	// BindAddress: the exposed listening addresses, "0.0.0.0:3306",
	// "[::]:3306, 203.0.113.10:3306".
	BindAddress string
}

// dbPorts are the database ports checked, in report order.
var dbPorts = []struct {
	port int
	name string
}{
	{3306, "MySQL/MariaDB"},
	{5432, "PostgreSQL"},
	{6379, "Redis"},
	{27017, "MongoDB"},
}

// Replaced in tests.
var (
	dbSockets     = netstate.Sockets
	dbHasPublicV6 = netstate.HasPublicIPv6
)

// ExposedDBPortList checks which database ports listen on all addresses
// (0.0.0.0 or [::]) or on a public address, in port order. Read only: the
// kernel's socket table (/proc/net/tcp, tcp6), no connection is made.
func ExposedDBPortList() []ExposedDBPort {
	return exposedDBPorts(dbSockets(), dbHasPublicV6())
}

func exposedDBPorts(socks []netstate.Conn, publicV6 bool) []ExposedDBPort {
	const listen = 0x0A
	var exposed []ExposedDBPort
	for _, db := range dbPorts {
		var binds []string
		seen := map[string]bool{}
		ipv4 := false
		for _, c := range socks {
			if c.State == listen && c.LocalPort == db.port && c.LocalIP.To4() != nil {
				ipv4 = true
			}
		}
		for _, c := range socks {
			if c.State != listen || c.LocalPort != db.port {
				continue
			}
			ip := c.LocalIP
			switch {
			case ip.IsUnspecified() && ip.To4() == nil:
				// [::] also takes IPv4 unless the socket is IPv6-only. A
				// daemon that opens an IPv4 socket too sets IPv6-only; then,
				// without a public IPv6 address, nothing reaches it.
				if !publicV6 && ipv4 {
					continue
				}
			case ip.IsUnspecified():
			case netstate.IsPublic(ip):
			default:
				continue // loopback, private, link-local
			}
			b := net.JoinHostPort(ip.String(), strconv.Itoa(db.port))
			if !seen[b] {
				seen[b] = true
				binds = append(binds, b)
			}
		}
		if len(binds) == 0 {
			continue
		}
		sort.Strings(binds)
		bind := strings.Join(binds, ", ")
		exposed = append(exposed, ExposedDBPort{
			Port:        db.port,
			Service:     db.name,
			Warning:     fmt.Sprintf("%s is exposed publicly on port %d", db.name, db.port),
			BindAddress: bind,
		})
	}
	return exposed
}

// NewDBWatcher creates a watcher for database logs.
// Returns nil if no database logs are found.
func NewDBWatcher(onBan BanFunc) *DBWatcher {
	paths := detectDBLogPaths()
	if len(paths) == 0 {
		return nil
	}

	return &DBWatcher{
		logPaths:  paths,
		threshold: 5,
		window:    5 * time.Minute,
		onBan:     onBan,
		attempts:  make(map[string][]time.Time),
		banned:    make(map[string]bool),
		whitelist: make(map[string]bool),
	}
}

func (w *DBWatcher) SetCheckIP(fn CheckIPFunc) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.checkIP = fn
}

func (w *DBWatcher) SetOnEvent(fn EventFunc) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.onEvent = fn
}

// SetKnownClient sets the guard consulted before a ban (country included):
// an address knownClient names a reason for is not banned; its attack is
// still reported, with action "not_banned".
func (w *DBWatcher) SetKnownClient(knownClient func(ip string) string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.knownClient = knownClient
}

func (w *DBWatcher) SetMonitorMode(enabled bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.monitorMode = enabled
}

func (w *DBWatcher) UpdateConfig(cfg Config) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if cfg.Threshold > 0 {
		w.threshold = cfg.Threshold
	}
	if cfg.Window > 0 {
		w.window = cfg.Window
	}
}

func (w *DBWatcher) UpdateWhitelist(ips []string, cidrs []string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.whitelist = make(map[string]bool, len(ips))
	for _, ip := range ips {
		w.whitelist[ip] = true
	}
	w.wlNets = make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			w.wlNets = append(w.wlNets, ipNet)
		}
	}
}

func (w *DBWatcher) isWhitelisted(ip string) bool {
	if w.whitelist[ip] {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range w.wlNets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// Run starts tailing all detected database log files. Blocks indefinitely.
func (w *DBWatcher) Run() {
	for _, lp := range w.logPaths {
		log.Printf("[dbwatcher] watching %s (%s) (threshold: %d in %s)", lp.Path, lp.DBType, w.threshold, w.window)
		go w.tailFile(lp.Path)
	}
	go w.cleanupLoop()
	// Block forever
	select {}
}

func (w *DBWatcher) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		w.cleanup(time.Now())
	}
}

// cleanup forgets what is out of the window: attempts, and with them the
// address's ban state, the guard's answers and old dropped-connection
// counts (kept one window more, so the next event carries them).
func (w *DBWatcher) cleanup(now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for ip, times := range w.attempts {
		var recent []time.Time
		for _, t := range times {
			if now.Sub(t) <= w.window {
				recent = append(recent, t)
			}
		}
		if len(recent) == 0 {
			delete(w.attempts, ip)
			delete(w.banned, ip)
		} else {
			w.attempts[ip] = recent
		}
	}
	for ip, k := range w.knownSeen {
		if now.Sub(k.since) > w.window {
			delete(w.knownSeen, ip)
		}
	}
	for ip, d := range w.dropped {
		if now.Sub(d.since) > 2*w.window {
			delete(w.dropped, ip)
		}
	}
	if len(w.attempts) > dbMaxEntries {
		w.attempts = make(map[string][]time.Time)
		w.banned = make(map[string]bool)
		log.Printf("[dbwatcher] attempts map exceeded %d entries — reset", dbMaxEntries)
	}
	if len(w.knownSeen) > dbMaxEntries {
		w.knownSeen = nil
	}
	if len(w.dropped) > dbMaxEntries {
		w.dropped = nil
	}
}

func (w *DBWatcher) tailFile(path string) {
	for {
		if err := w.tail(path); err != nil {
			log.Printf("[dbwatcher] error tailing %s: %v — retrying in 5s", path, err)
			time.Sleep(5 * time.Second)
		}
	}
}

func (w *DBWatcher) tail(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return err
	}
	offset := fi.Size()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	var partial string

	for range ticker.C {
		fi, err = os.Stat(path)
		if err != nil {
			return err
		}
		size := fi.Size()
		if size <= offset {
			if size < offset {
				offset = 0
			}
			continue
		}

		readF, err := os.Open(path)
		if err != nil {
			return err
		}
		readF.Seek(offset, io.SeekStart)
		buf := make([]byte, size-offset)
		n, err := io.ReadFull(readF, buf)
		readF.Close()

		if n > 0 {
			partial += string(buf[:n])
			offset += int64(n)
			for {
				idx := strings.IndexByte(partial, '\n')
				if idx < 0 {
					break
				}
				w.processLine(partial[:idx])
				partial = partial[idx+1:]
			}
		}
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return err
		}
	}
	return nil
}

func (w *DBWatcher) processLine(line string) {
	var ip, reason string
	for _, p := range dbPatterns {
		m := p.Re.FindStringSubmatch(line)
		if len(m) >= 2 {
			ip = m[1]
			reason = p.Reason
			break
		}
	}
	if ip == "" {
		return
	}
	if isPrivateIP(ip) {
		return
	}
	w.recordAttempt(ip, reason)
}

func (w *DBWatcher) recordAttempt(ip, reason string) {
	now := time.Now()
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.banned[ip] {
		return
	}
	if w.isWhitelisted(ip) {
		return
	}
	severity := "warning"
	if reason == "db_brute_force" {
		severity = "critical"
	}

	// Geoblocking (a known client is not banned for its country: reported
	// once a window)
	if w.checkIP != nil {
		if banReason := w.checkIP(ip); banReason != "" {
			k := w.known(ip, now)
			if k == nil || k.why == "" {
				w.banned[ip] = true
				if w.monitorMode {
					if w.onEvent != nil {
						go w.onEvent(ip, reason, "critical", map[string]string{"reason": banReason})
					}
				} else {
					go w.onBan(ip, banReason, 1)
				}
				return
			}
			if !k.geo {
				k.geo = true
				log.Printf("[dbwatcher] not banning %s for its country: known database client (%s, %s)", ip, k.why, banReason)
				if w.onEvent != nil {
					go w.onEvent(ip, reason, severity, map[string]string{
						"reason":     banReason,
						"action":     "not_banned",
						"not_banned": k.why,
					})
				}
			}
		}
	}

	// A dropped connection (db_suspicious) is not an attack: legitimate
	// clients drop connections all the time. Reported once a window, with
	// the lines since the last report, never counted toward a ban. A port
	// scanner that only leaves such lines is not banned by this watcher.
	if reason != "db_brute_force" {
		d := w.dropped[ip]
		if d != nil && now.Sub(d.since) <= w.window {
			d.lines++
			return
		}
		lines := 1
		if d != nil {
			lines += d.lines
		}
		if w.dropped == nil {
			w.dropped = make(map[string]*dbDropped)
		}
		w.dropped[ip] = &dbDropped{since: now}
		if w.onEvent != nil {
			go w.onEvent(ip, reason, severity, map[string]string{"lines": strconv.Itoa(lines)})
		}
		return
	}

	// Report event
	if w.onEvent != nil {
		go w.onEvent(ip, reason, severity, map[string]string{})
	}

	// Threshold
	var recent []time.Time
	for _, t := range w.attempts[ip] {
		if now.Sub(t) <= w.window {
			recent = append(recent, t)
		}
	}
	recent = append(recent, now)
	w.attempts[ip] = recent

	if len(recent) >= w.threshold {
		w.banned[ip] = true
		count := len(recent)
		if w.monitorMode {
			return
		}
		if k := w.known(ip, now); k != nil && k.why != "" {
			// An application with a wrong or just changed password: not
			// cut off. Reported once per window.
			log.Printf("[dbwatcher] not banning %s: known database client (%s, %d failed logins)", ip, k.why, count)
			if w.onEvent != nil {
				go w.onEvent(ip, reason, "critical", map[string]string{
					"reason":     reason,
					"attempts":   strconv.Itoa(count),
					"action":     "not_banned",
					"not_banned": k.why,
				})
			}
			return
		}
		go w.onBan(ip, reason, count)
	}
}

// known returns the guard's answer for ip, asked at most once a window;
// nil without a guard and in monitor mode, which bans nothing. Caller must
// hold w.mu.
func (w *DBWatcher) known(ip string, now time.Time) *dbKnown {
	if w.knownClient == nil || w.monitorMode {
		return nil
	}
	k := w.knownSeen[ip]
	if k == nil || now.Sub(k.since) > w.window {
		if w.knownSeen == nil {
			w.knownSeen = make(map[string]*dbKnown)
		}
		k = &dbKnown{since: now, why: w.knownClient(ip)}
		w.knownSeen[ip] = k
	}
	return k
}
