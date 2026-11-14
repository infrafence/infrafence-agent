// Package loginhistory knows the successful SSH logins of the last 30 days,
// so nothing the agent does locks out the people who administer the server.
//
// The session tracker and the dashboard only see logins that happen while
// the agent runs. On a server in production for years the administrators'
// addresses are in the logs already: at startup (and once a day) the agent
// reads, read only and within fixed bounds, the "Accepted ... for USER from
// ADDRESS" lines of the last 30 days from
//
//   - the authentication log files, rotated and gzipped ones included
//     (/var/log/auth.log*, /var/log/secure*, AUTH_LOG_PATH*);
//   - the systemd journal of the SSH service units (journalctl -u ssh
//     -u sshd, --since -30d);
//   - the login records (/var/log/wtmp*, binary utmp records of remote
//     logins), or `last -i` where wtmpdb replaced wtmp.
//
// A login older than what these keep (logs rotated away, a journal that
// keeps a week) is unknown: the dashboard whitelist stays the guarantee.
package loginhistory

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Window is how far back logins count.
const Window = 30 * 24 * time.Hour

// Bounds on what one scan reads (variables for the tests).
var (
	maxFileBytes    int64 = 64 << 20  // per log file (the newest part of a larger one)
	maxTotalBytes   int64 = 256 << 20 // all log files together
	maxGlobFiles          = 30        // files per pattern
	maxJournalBytes int64 = 128 << 20
	maxWtmpBytes    int64 = 32 << 20 // per login records file (~87,000 records)
	// A pause every throttleEvery bytes keeps a scan of large logs from
	// taking a CPU core on a busy server.
	throttleEvery int64 = 4 << 20
	throttlePause       = 20 * time.Millisecond
)

const (
	journalTimeout = 90 * time.Second
	lastTimeout    = 30 * time.Second
	maxUsers       = 5
)

// Login is one successful login found.
type Login struct {
	IP     string
	User   string
	Time   time.Time
	Source string // auth_log, journal, wtmp, last, live
}

// reAccepted matches OpenSSH's successful authentication message, from sshd
// or (OpenSSH 9.8+) sshd-session: "Accepted publickey for root from
// 198.51.100.7 port 52113 ssh2: ED25519 SHA256:...". Methods: password,
// publickey, keyboard-interactive/pam, gssapi-with-mic, hostbased.
var (
	reSSHDTag  = regexp.MustCompile(`^sshd(?:-session)?\[\d+\]$`)
	reAccepted = regexp.MustCompile(`^Accepted ([a-z][a-z0-9/-]{0,40}) for (\S{1,64}) from ([0-9A-Fa-f:.]{2,45}) port \d{1,5}(?: |$)`)
)

// SyslogMessage splits a syslog-format line ("Mmm dd hh:mm:ss host tag:
// message", or with an RFC 3339 timestamp) into its program tag and
// message. Only these positions count: a client controls the text of many
// sshd messages (the user name of "Invalid user NAME from ..." can hold
// spaces), so an "Accepted ..." anywhere else in a line is not a login.
func SyslogMessage(line string) (tag, msg string, ok bool) {
	var rest string
	switch {
	case len(line) >= 20 && line[4] == '-' && line[0] >= '0' && line[0] <= '9':
		i := strings.IndexByte(line, ' ')
		if i < 0 {
			return "", "", false
		}
		rest = line[i+1:]
	case len(line) >= 16 && line[15] == ' ':
		if _, err := time.Parse("Jan _2 15:04:05", line[:15]); err != nil {
			return "", "", false
		}
		rest = line[16:]
	default:
		return "", "", false
	}
	host, rest, found := strings.Cut(rest, " ")
	if !found || host == "" {
		return "", "", false
	}
	tag, msg, found = strings.Cut(rest, ": ")
	if !found || tag == "" || strings.ContainsAny(tag, " \t") {
		return "", "", false
	}
	return tag, msg, true
}

// ParseLine returns the login of a syslog-format authentication line, or
// false. ref dates a traditional timestamp without a year ("Nov  3
// 10:00:00"): the latest such date not after ref plus a day (a line is
// never newer than the file that holds it, nor than now).
func ParseLine(line string, ref time.Time) (Login, bool) {
	if !strings.Contains(line, "Accepted ") {
		return Login{}, false
	}
	tag, msg, ok := SyslogMessage(line)
	if !ok || !reSSHDTag.MatchString(tag) {
		return Login{}, false
	}
	m := reAccepted.FindStringSubmatch(msg)
	if m == nil {
		return Login{}, false
	}
	ip := normIP(m[3])
	if ip == "" {
		return Login{}, false
	}
	t, ok := lineTime(line, ref)
	if !ok {
		return Login{}, false
	}
	return Login{IP: ip, User: cleanUser(m[2]), Time: t}, true
}

// normIP returns the address in its canonical form ("::ffff:a.b.c.d" as
// IPv4), or "" for no address, an unspecified or a loopback one.
func normIP(s string) string {
	p := net.ParseIP(strings.TrimSpace(s))
	if p == nil || p.IsUnspecified() || p.IsLoopback() {
		return ""
	}
	if v4 := p.To4(); v4 != nil {
		return v4.String()
	}
	return p.String()
}

func cleanUser(u string) string {
	u = strings.Map(func(r rune) rune {
		if r < 0x21 || r == 0x7f {
			return -1
		}
		return r
	}, u)
	if len(u) > 64 {
		u = u[:64]
	}
	return u
}

var isoLayouts = []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999-0700", "2006-01-02T15:04:05-0700"}

// lineTime reads the timestamp at the start of a line: RFC 3339 (rsyslog's
// high-precision format, journalctl -o short-iso) or the traditional
// "Mmm dd hh:mm:ss".
func lineTime(line string, ref time.Time) (time.Time, bool) {
	if len(line) >= 19 && line[4] == '-' && line[0] >= '0' && line[0] <= '9' {
		field, _, _ := strings.Cut(line, " ")
		for _, l := range isoLayouts {
			if t, err := time.Parse(l, field); err == nil {
				return t, true
			}
		}
		return time.Time{}, false
	}
	if len(line) < 15 {
		return time.Time{}, false
	}
	t, err := time.ParseInLocation("Jan _2 15:04:05", line[:15], ref.Location())
	if err != nil {
		return time.Time{}, false
	}
	t = t.AddDate(ref.Year(), 0, 0)
	if t.After(ref.Add(24 * time.Hour)) {
		t = t.AddDate(-1, 0, 0)
	}
	return t, true
}

// Options say where a scan reads from; Default is the real host.
type Options struct {
	AuthGlobs []string
	WtmpGlobs []string
	// Journal returns the journal's SSH lines in short-iso format (nil: no
	// journal); Last the output of `last -i --time-format iso` (nil: none).
	Journal func(ctx context.Context) (io.ReadCloser, func(), error)
	Last    func(ctx context.Context) string
}

// Default reads the standard locations, AUTH_LOG_PATH's file and its
// rotations included.
func Default() Options {
	auth := []string{"/var/log/auth.log*", "/var/log/secure*"}
	if p := os.Getenv("AUTH_LOG_PATH"); p != "" && filepath.IsAbs(p) {
		auth = append(auth, p+"*")
	}
	return Options{
		AuthGlobs: auth,
		WtmpGlobs: []string{"/var/log/wtmp*"},
		Journal:   journal,
		Last:      lastOutput,
	}
}

// Result is what one scan found.
type Result struct {
	Logins    []Login
	Sources   []string // where logins were read from: auth_log, journal, wtmp, last
	Files     int
	Bytes     int64
	Truncated bool // a bound cut the reading short
}

type scanner struct {
	now    time.Time
	since  time.Time
	res    Result
	unread int64 // bytes since the last pause
	seen   map[string]bool
}

func (s *scanner) add(l Login, source string) {
	if l.Time.Before(s.since) || l.Time.After(s.now.Add(24*time.Hour)) {
		return
	}
	l.Source = source
	s.res.Logins = append(s.res.Logins, l)
	if !s.seen[source] {
		s.seen[source] = true
		s.res.Sources = append(s.res.Sources, source)
	}
}

func (s *scanner) throttle(n int) {
	s.unread += int64(n)
	s.res.Bytes += int64(n)
	if s.unread >= throttleEvery {
		s.unread = 0
		time.Sleep(throttlePause)
	}
}

// Scan reads the successful SSH logins since now-Window. It only reads, and
// stops at the bounds above (Result.Truncated).
func Scan(ctx context.Context, now time.Time, o Options) Result {
	s := &scanner{now: now, since: now.Add(-Window), seen: map[string]bool{}}
	s.scanAuthFiles(ctx, o.AuthGlobs)
	if o.Journal != nil && ctx.Err() == nil {
		s.scanJournal(ctx, o.Journal)
	}
	wtmp := s.scanWtmp(ctx, o.WtmpGlobs)
	if wtmp == 0 && o.Last != nil && ctx.Err() == nil {
		s.scanLast(o.Last(ctx))
	}
	return s.res
}

// files expands the patterns: regular files only, newest first, modified in
// the window (an older one holds older lines only), each once.
func (s *scanner) files(globs []string) []string {
	type f struct {
		path string
		mod  time.Time
	}
	var out []f
	seen := map[string]bool{}
	for _, g := range globs {
		matches, _ := filepath.Glob(g)
		var list []f
		for _, p := range matches {
			if seen[p] {
				continue
			}
			fi, err := os.Lstat(p)
			if err != nil || !fi.Mode().IsRegular() || fi.ModTime().Before(s.since) {
				continue
			}
			seen[p] = true
			list = append(list, f{p, fi.ModTime()})
		}
		sort.Slice(list, func(i, j int) bool { return list[i].mod.After(list[j].mod) })
		if len(list) > maxGlobFiles {
			list, s.res.Truncated = list[:maxGlobFiles], true
		}
		out = append(out, list...)
	}
	paths := make([]string, len(out))
	for i, x := range out {
		paths[i] = x.path
	}
	return paths
}

func (s *scanner) scanAuthFiles(ctx context.Context, globs []string) {
	for _, p := range s.files(globs) {
		if ctx.Err() != nil {
			return
		}
		if s.res.Bytes >= maxTotalBytes {
			s.res.Truncated = true
			return
		}
		if err := s.scanAuthFile(p); err != nil {
			log.Printf("[ssh-logins] %s: %v", p, err)
		}
	}
}

// openLimited opens a log file for reading: the newest max bytes of a plain
// file (from the first full line), the first max decompressed bytes of a
// gzipped one.
func (s *scanner) openLimited(path string, max int64) (io.Reader, func(), time.Time, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, time.Time{}, err
	}
	s.res.Files++
	if strings.HasSuffix(path, ".gz") {
		zr, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			return nil, nil, time.Time{}, err
		}
		return &limitFlag{r: zr, n: max, cut: &s.res.Truncated}, func() { zr.Close(); f.Close() }, fi.ModTime(), nil
	}
	var r io.Reader = f
	if fi.Size() > max {
		s.res.Truncated = true
		if _, err := f.Seek(fi.Size()-max, io.SeekStart); err != nil {
			f.Close()
			return nil, nil, time.Time{}, err
		}
		br := bufio.NewReader(f)
		_, _ = br.ReadString('\n') // a partial line
		r = br
	}
	return io.LimitReader(r, max), func() { f.Close() }, fi.ModTime(), nil
}

// limitFlag is io.LimitReader that records whether the limit was hit.
type limitFlag struct {
	r   io.Reader
	n   int64
	cut *bool
}

func (l *limitFlag) Read(p []byte) (int, error) {
	if l.n <= 0 {
		*l.cut = true
		return 0, io.EOF
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= int64(n)
	return n, err
}

func (s *scanner) scanAuthFile(path string) error {
	r, done, mod, err := s.openLimited(path, min(maxFileBytes, maxTotalBytes-s.res.Bytes))
	if err != nil {
		return err
	}
	defer done()
	s.scanLines(r, mod, "auth_log")
	return nil
}

// scanLines reads syslog lines; ref dates those without a year. A line
// over 1 MiB is skipped, not the rest of the file.
func (s *scanner) scanLines(r io.Reader, ref time.Time, source string) {
	br := bufio.NewReaderSize(r, 64*1024)
	accepted := []byte("Accepted ")
	var long []byte
	skipping := false
	for {
		chunk, err := br.ReadSlice('\n')
		s.throttle(len(chunk))
		switch {
		case err == bufio.ErrBufferFull:
			if !skipping {
				long = append(long, chunk...)
				if len(long) > 1<<20 {
					long, skipping = nil, true
				}
			}
			continue
		case skipping:
			skipping = false
		default:
			line := chunk
			if len(long) > 0 {
				line = append(long, chunk...)
				long = long[:0]
			}
			if bytes.Contains(line, accepted) {
				if l, ok := ParseLine(strings.TrimRight(string(line), "\r\n"), ref); ok {
					s.add(l, source)
				}
			}
		}
		if err != nil {
			return
		}
	}
}

// journalArgs: the SSH service units' messages of the last 30 days, with
// the year in every timestamp. _SYSTEMD_UNIT is set by journald itself, so
// a message another program logs under the name "sshd" does not count.
var journalArgs = []string{"--since=-30d", "--output=short-iso", "--no-pager", "--quiet",
	"-u", "ssh.service", "-u", "sshd.service", "-u", "ssh@*.service", "-u", "sshd@*.service"}

func journal(ctx context.Context) (io.ReadCloser, func(), error) {
	if _, err := exec.LookPath("journalctl"); err != nil {
		return nil, nil, err
	}
	if _, err := os.Stat("/run/systemd/journal"); err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, journalTimeout)
	cmd := exec.CommandContext(ctx, "journalctl", journalArgs...)
	out, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, nil, err
	}
	return out, func() { cancel(); _ = cmd.Wait() }, nil
}

func (s *scanner) scanJournal(ctx context.Context, open func(context.Context) (io.ReadCloser, func(), error)) {
	r, done, err := open(ctx)
	if err != nil || r == nil {
		return
	}
	defer done()
	s.scanLines(&limitFlag{r: r, n: maxJournalBytes, cut: &s.res.Truncated}, s.now, "journal")
}

// utmp record layout (glibc, every Linux architecture the agent ships for:
// 384 bytes, 32-bit times).
const (
	utmpSize     = 384
	utmpUser     = 7 // USER_PROCESS
	utOffLine    = 8
	utOffUser    = 44
	utOffHost    = 76
	utOffSec     = 340
	utOffAddr    = 348
	utLineLen    = 32
	utUserLen    = 32
	utHostLen    = 256
	utAddrLength = 16
)

// scanWtmp reads the login records; returns how many files it read.
func (s *scanner) scanWtmp(ctx context.Context, globs []string) int {
	n := 0
	for _, p := range s.files(globs) {
		if ctx.Err() != nil {
			break
		}
		if strings.Contains(filepath.Base(p), "btmp") {
			continue // failed logins
		}
		if err := s.scanWtmpFile(p); err != nil {
			log.Printf("[ssh-logins] %s: %v", p, err)
			continue
		}
		n++
	}
	return n
}

func (s *scanner) scanWtmpFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	s.res.Files++
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		zr, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer zr.Close()
		r = &limitFlag{r: zr, n: maxWtmpBytes, cut: &s.res.Truncated}
	} else if fi.Size() > maxWtmpBytes {
		// The newest records, from a record boundary.
		s.res.Truncated = true
		off := fi.Size() - maxWtmpBytes
		off += (utmpSize - off%utmpSize) % utmpSize
		if _, err := f.Seek(off, io.SeekStart); err != nil {
			return err
		}
		r = io.LimitReader(f, maxWtmpBytes)
	}
	br := bufio.NewReaderSize(r, 64*1024)
	rec := make([]byte, utmpSize)
	for {
		if _, err := io.ReadFull(br, rec); err != nil {
			return nil // EOF or a partial last record
		}
		s.throttle(utmpSize)
		if l, ok := parseUtmp(rec); ok {
			s.add(l, "wtmp")
		}
	}
}

// parseUtmp returns the remote login of a USER_PROCESS record.
func parseUtmp(rec []byte) (Login, bool) {
	if len(rec) < utmpSize || int16(binary.NativeEndian.Uint16(rec[0:2])) != utmpUser {
		return Login{}, false
	}
	addr := rec[utOffAddr : utOffAddr+utAddrLength]
	var ip string
	switch {
	case allZero(addr):
		ip = normIP(cstr(rec[utOffHost : utOffHost+utHostLen]))
	case allZero(addr[4:]):
		ip = normIP(net.IP(addr[:4]).String())
	default:
		ip = normIP(net.IP(addr).String())
	}
	if ip == "" {
		return Login{}, false
	}
	if !sshTTY(cstr(rec[utOffLine : utOffLine+utLineLen])) {
		return Login{}, false // ftpd, a console...
	}
	user := cleanUser(cstr(rec[utOffUser : utOffUser+utUserLen]))
	if user == "" {
		return Login{}, false
	}
	sec := binary.NativeEndian.Uint32(rec[utOffSec : utOffSec+4])
	return Login{IP: ip, User: user, Time: time.Unix(int64(sec), 0)}, true
}

// sshTTY: the terminal of an SSH login record, a pseudo-terminal ("pts/3")
// or sshd's "ssh:notty". FTP servers write "ftp<pid>", consoles "tty1".
func sshTTY(line string) bool {
	return strings.HasPrefix(line, "pts/") || strings.HasPrefix(line, "ssh")
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func lastOutput(ctx context.Context) string {
	if _, err := exec.LookPath("last"); err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, lastTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "last", "-i", "--time-format", "iso", "--since", "-30days").Output()
	if err != nil && len(out) == 0 {
		// An older `last` without --time-format.
		out, _ = exec.CommandContext(ctx, "last", "-i", "--since", "-30days").Output()
	}
	if int64(len(out)) > maxWtmpBytes {
		out = out[:maxWtmpBytes]
	}
	return string(out)
}

// scanLast reads `last -i` lines ("root pts/0 198.51.100.7
// 2026-11-03T10:00:00+01:00 - still logged in"); a line without an ISO time
// counts as a login now (it is in the last 30 days, asked with --since).
func (s *scanner) scanLast(out string) {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || f[0] == "reboot" || f[0] == "wtmp" || f[0] == "wtmpdb" || !sshTTY(f[1]) {
			continue
		}
		ip := normIP(f[2])
		if ip == "" {
			continue
		}
		t := s.now
		for _, w := range f[3:] {
			if tt, ok := lineTime(w, s.now); ok && len(w) >= 19 {
				t = tt
				break
			}
		}
		s.add(Login{IP: ip, User: cleanUser(f[0]), Time: t}, "last")
	}
}

// LineTime returns the time at the start of a syslog-format line (RFC 3339,
// journalctl -o short-iso, or "Mmm dd hh:mm:ss" dated as ParseLine does
// against ref).
func LineTime(line string, ref time.Time) (time.Time, bool) { return lineTime(line, ref) }
