package watcher

import (
	"io"
	"log"
	"maps"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// MailPattern pairs a compiled regex with the event type it represents.
// Named groups: ip (required), and when the line has them user, method,
// rcpt, proto and auth (an Exim authenticator name). Protocol and MTA are
// fixed per pattern unless the line names them (proto group, Postfix
// service name).
type MailPattern struct {
	Re       *regexp.Regexp
	Reason   string
	MTA      string // postfix, exim, dovecot, roundcube
	Protocol string // smtp, imap, ...; "" when it comes from the line or is unknown
	// DovecotFields: the line carries Dovecot's user=<...> and method=...
	DovecotFields bool
	// OneIP, when set, finds every address in the line where the client's
	// could be: text the client controls (an Exim HELO, a Roundcube user
	// name) comes before the real one, so a line with two different
	// addresses there is not counted (it could get another address banned).
	OneIP *regexp.Regexp
}

var (
	bracketIPs = regexp.MustCompile(`\[(\d+\.\d+\.\d+\.\d+)\]`)
	fromIPs    = regexp.MustCompile(`\bfrom (\d+\.\d+\.\d+\.\d+)`)
)

// mailPatterns contains all mail detection patterns, ordered by frequency.
//
// Postfix SASL:
//   - "warning: unknown[X.X.X.X]: SASL LOGIN authentication failed: UGFzc3dvcmQ6"
//     (newer versions add ", sasl_username=user@example.com")
//   - "NOQUEUE: reject: RCPT from unknown[X.X.X.X]: 554 5.7.1 <a@b>: Relay access denied; from=<...> to=<a@b> ..."
//   - "too many errors after AUTH from unknown[X.X.X.X]"
//   - "warning: X.X.X.X: hostname does not resolve"
//   - "improper command pipelining after ... from unknown[X.X.X.X]"
//
// Exim (cPanel /var/log/exim_mainlog, Debian /var/log/exim4/mainlog):
//   - "dovecot_login authenticator failed for (helo) [X.X.X.X]:1234: 535 Incorrect authentication data (set_id=user@example.com)"
//   - "H=(helo) [X.X.X.X]:1234 F=<a@b> rejected RCPT <c@d>: relay not permitted"
//
// Dovecot:
//   - "imap-login: Disconnected (auth failed, 3 attempts in 12 secs): user=<u>, method=PLAIN, rip=X.X.X.X, ..."
//   - "imap-login: Login aborted: Connection closed (auth failed, 1 attempts in 2 secs) (auth_failed): user=<u>, method=PLAIN, rip=X.X.X.X"
//   - "auth: passwd-file(user,X.X.X.X,<session>): unknown user"
//   - "imap(user,<X.X.X.X>): Too many invalid commands"
//   - "auth: passwd(user,X.X.X.X): Password mismatch"
//
// Roundcube:
//   - "IMAP Error: Login failed for user against server from X.X.X.X. AUTHENTICATE PLAIN: Authentication failed."
//   - "Failed login for user from X.X.X.X in session"
var mailPatterns = []MailPattern{
	// ── Postfix SASL ──────────────────────────────────────────────────
	{Re: regexp.MustCompile(`\S+\[(?P<ip>[\d.]+)\]: SASL (?P<method>[A-Z0-9-]+) authentication failed(?:.*sasl_username=(?P<user>[^\s,]+))?`), Reason: "mail_brute_force", MTA: "postfix"},
	{Re: regexp.MustCompile(`NOQUEUE: reject:.*from \S+\[(?P<ip>[\d.]+)\].*(?:Relay access denied|Client host rejected)(?:.* to=<(?P<rcpt>[^>]*)>)?`), Reason: "mail_relay_scan", MTA: "postfix"},
	{Re: regexp.MustCompile(`too many errors after AUTH from \S+\[(?P<ip>[\d.]+)\]`), Reason: "mail_brute_force", MTA: "postfix"},
	{Re: regexp.MustCompile(`warning: (?P<ip>[\d.]+): hostname \S+ does not resolve`), Reason: "mail_suspicious", MTA: "postfix"},
	{Re: regexp.MustCompile(`improper command pipelining after \S+ from \S+\[(?P<ip>[\d.]+)\]`), Reason: "mail_suspicious", MTA: "postfix"},

	// ── Exim ──────────────────────────────────────────────────────────
	{Re: regexp.MustCompile(`(?P<auth>[A-Za-z0-9_-]+) authenticator failed for .*?\[(?P<ip>[\d.]+)\](?::\d+)?: 535\b(?:.*\(set_id=(?P<user>[^)\s]+)\))?`), Reason: "mail_brute_force", MTA: "exim", Protocol: "smtp", OneIP: bracketIPs},
	{Re: regexp.MustCompile(`H=.*?\[(?P<ip>[\d.]+)\](?::\d+)?.* rejected RCPT <(?P<rcpt>[^>]*)>: (?i:relay(?:ing)? not permitted)`), Reason: "mail_relay_scan", MTA: "exim", Protocol: "smtp", OneIP: bracketIPs},

	// ── Dovecot ───────────────────────────────────────────────────────
	{Re: regexp.MustCompile(`(?P<proto>imap|pop3|submission|managesieve)-login: (?:Disconnected|Aborted login|Login aborted)[^(]*\((?:auth failed|tried to use (?:disabled|disallowed)).*rip=(?P<ip>[\d.]+)`), Reason: "mail_brute_force", MTA: "dovecot", DovecotFields: true},
	{Re: regexp.MustCompile(`auth(?:-worker\(\d+\))?:.*\((?P<user>[^,()\s]*),(?P<ip>[\d.]+)(?:,<[^>]*>)?\):\s+unknown user`), Reason: "mail_brute_force", MTA: "dovecot"},
	{Re: regexp.MustCompile(`(?P<proto>imap|pop3)\((?P<user>[^,()\s]*),<?(?P<ip>[\d.]+)>?\).*Too many invalid`), Reason: "mail_brute_force", MTA: "dovecot"},
	{Re: regexp.MustCompile(`auth(?:-worker\(\d+\))?:.*\((?P<user>[^,()\s]*),(?P<ip>[\d.]+)(?:,<[^>]*>)?\):\s+[Pp]assword mismatch`), Reason: "mail_brute_force", MTA: "dovecot"},

	// ── Roundcube ─────────────────────────────────────────────────────
	{Re: regexp.MustCompile(`IMAP Error: Login failed for (?P<user>\S+) against \S+ from (?P<ip>[\d.]+)(?:.*AUTHENTICATE (?P<method>[A-Z0-9-]+))?`), Reason: "mail_brute_force", MTA: "roundcube", Protocol: "roundcube", OneIP: fromIPs},
	{Re: regexp.MustCompile(`Failed login for (?P<user>\S+) from (?P<ip>[\d.]+) in session`), Reason: "mail_brute_force", MTA: "roundcube", Protocol: "roundcube", OneIP: fromIPs},
}

var (
	dovecotUser   = regexp.MustCompile(`\buser=<([^>]*)>`)
	dovecotMethod = regexp.MustCompile(`\bmethod=([A-Za-z0-9-]+)`)
)

// Bounds of the details taken from a log line, and of the reads.
const (
	maxMailRead      = 1 << 20
	maxMailLine      = 8192
	maxMailUser      = 128
	maxMailRecipient = 254
)

// parseMailLine matches line against the mail patterns: the attacker's
// address, the event type and the details the line really contains
// (target_user, protocol, auth_method, recipient, recipient_domain, mta).
// ip is "" when nothing matches.
func parseMailLine(line string) (ip, reason string, details map[string]string) {
	for _, p := range mailPatterns {
		m := p.Re.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		g := map[string]string{}
		for i, name := range p.Re.SubexpNames() {
			if name != "" && m[i] != "" {
				g[name] = m[i]
			}
		}
		// "from 203.0.113.5. AUTHENTICATE": the sentence's full stop.
		ip = strings.TrimRight(g["ip"], ".")
		if net.ParseIP(ip) == nil {
			return "", "", nil
		}
		if p.OneIP != nil {
			for _, c := range p.OneIP.FindAllStringSubmatch(line, -1) {
				if c[1] != ip {
					return "", "", nil
				}
			}
		}
		details = map[string]string{"mta": p.MTA}
		user := g["user"]
		method := g["method"]
		if p.DovecotFields {
			if u := dovecotUser.FindStringSubmatch(line); u != nil {
				user = u[1]
			}
			if mm := dovecotMethod.FindStringSubmatch(line); mm != nil {
				method = mm[1]
			}
		}
		if user = cleanMailField(user, maxMailUser); user != "" {
			details["target_user"] = user
		}
		if method == "" && g["auth"] != "" {
			method = eximAuthMethod(g["auth"])
		}
		if method = cleanMailField(method, 32); method != "" {
			details["auth_method"] = strings.ToLower(method)
		}
		proto := p.Protocol
		if g["proto"] != "" {
			proto = g["proto"]
		} else if p.MTA == "postfix" {
			proto = postfixProtocol(line)
		}
		if proto != "" {
			details["protocol"] = proto
		}
		if rcpt := cleanMailField(g["rcpt"], maxMailRecipient); rcpt != "" {
			details["recipient"] = rcpt
			if _, domain, ok := strings.Cut(rcpt, "@"); ok && domain != "" {
				details["recipient_domain"] = strings.ToLower(domain)
			}
		}
		return ip, p.Reason, details
	}
	return "", "", nil
}

// postfixProtocol: the smtpd of the submission (587) and smtps (465)
// services takes logins from mail clients; plain smtpd is SMTP (25).
func postfixProtocol(line string) string {
	if strings.Contains(line, "/submission/smtpd[") || strings.Contains(line, "/smtps/smtpd[") {
		return "submission"
	}
	if strings.Contains(line, "smtpd[") {
		return "smtp"
	}
	return ""
}

// eximAuthMethod reads the mechanism from an Exim authenticator name
// (cPanel's dovecot_login / dovecot_plain, Debian's plain_server,
// login_server, cram_md5_server). "" when the name does not say.
func eximAuthMethod(name string) string {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "cram"):
		return "cram-md5"
	case strings.Contains(n, "digest"):
		return "digest-md5"
	case strings.Contains(n, "plain"):
		return "plain"
	case strings.Contains(n, "login"):
		return "login"
	}
	return ""
}

// cleanMailField drops control characters and bounds the length.
func cleanMailField(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	for len(s) > max {
		_, size := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-size]
	}
	return s
}

// MailWatcher tails mail logs and calls onBan when an IP exceeds the threshold.
type MailWatcher struct {
	logPaths []string
	onBan    BanFunc
	onEvent  EventFunc
	checkIP  CheckIPFunc

	mu          sync.Mutex
	threshold   int
	window      time.Duration
	attempts    map[string][]time.Time
	banned      map[string]bool
	whitelist   map[string]bool
	wlNets      []*net.IPNet
	monitorMode bool
}

// eximLogPaths: cPanel, Debian/Ubuntu (exim4), RHEL family (EPEL exim).
// Exim writes its own log, not syslog's mail log.
var eximLogPaths = []string{"/var/log/exim_mainlog", "/var/log/exim4/mainlog", "/var/log/exim/main.log"}

// detectMailLogPaths returns the mail logs to watch: MAIL_LOG_PATH when
// set, otherwise the syslog mail log (Postfix, Dovecot, Roundcube when it
// logs to syslog) and Exim's main log, those that exist.
func detectMailLogPaths() []string {
	if p := os.Getenv("MAIL_LOG_PATH"); p != "" {
		return []string{p}
	}
	var paths []string
	for _, p := range []string{"/var/log/mail.log", "/var/log/maillog", "/var/log/dovecot.log"} {
		if _, err := os.Stat(p); err == nil {
			paths = append(paths, p)
			break // one syslog mail log is enough
		}
	}
	for _, p := range eximLogPaths {
		if _, err := os.Stat(p); err == nil {
			paths = append(paths, p)
			break
		}
	}
	return paths
}

// HasMailService returns true if a mail server is detected on this system.
func HasMailService() bool {
	for _, svc := range []string{"postfix", "dovecot", "exim", "exim4"} {
		if out, err := exec.Command("systemctl", "is-active", svc).Output(); err == nil {
			if strings.TrimSpace(string(out)) == "active" {
				return true
			}
		}
	}
	return len(detectMailLogPaths()) > 0
}

// NewMailWatcher creates a watcher for mail server logs.
// Returns nil if no mail log is found.
func NewMailWatcher(onBan BanFunc) *MailWatcher {
	paths := detectMailLogPaths()
	if len(paths) == 0 {
		return nil
	}

	return &MailWatcher{
		logPaths:  paths,
		threshold: 5,
		window:    5 * time.Minute,
		onBan:     onBan,
		attempts:  make(map[string][]time.Time),
		banned:    make(map[string]bool),
		whitelist: make(map[string]bool),
	}
}

// SetCheckIP sets a callback for geoblocking checks.
func (w *MailWatcher) SetCheckIP(fn CheckIPFunc) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.checkIP = fn
}

// SetOnEvent sets the callback for reporting detection events.
func (w *MailWatcher) SetOnEvent(fn EventFunc) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.onEvent = fn
}

// SetMonitorMode enables or disables monitor-only mode.
func (w *MailWatcher) SetMonitorMode(enabled bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.monitorMode = enabled
}

// UpdateConfig reconfigures threshold and window at runtime.
func (w *MailWatcher) UpdateConfig(cfg Config) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if cfg.Threshold > 0 {
		w.threshold = cfg.Threshold
	}
	if cfg.Window > 0 {
		w.window = cfg.Window
	}
}

// UpdateWhitelist replaces the whitelist with a new set of IPs/CIDRs.
func (w *MailWatcher) UpdateWhitelist(ips []string, cidrs []string) {
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

func (w *MailWatcher) isWhitelisted(ip string) bool {
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

// Run starts tailing the mail logs. Blocks indefinitely.
func (w *MailWatcher) Run() {
	go w.cleanupLoop()

	for _, p := range w.logPaths {
		log.Printf("[mailwatcher] watching %s (threshold: %d in %s)", p, w.threshold, w.window)
		go func(path string) {
			for {
				if err := w.tail(path); err != nil {
					log.Printf("[mailwatcher] %s: %v — retrying in 5s", path, err)
					time.Sleep(5 * time.Second)
				}
			}
		}(p)
	}
	select {}
}

func (w *MailWatcher) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		w.mu.Lock()
		now := time.Now()
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
		const maxEntries = 50000
		if len(w.attempts) > maxEntries {
			w.attempts = make(map[string][]time.Time)
			w.banned = make(map[string]bool)
			log.Printf("[mailwatcher] attempts map exceeded %d entries — reset", maxEntries)
		}
		w.mu.Unlock()
	}
}

func (w *MailWatcher) tail(path string) error {
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
				offset = 0 // file rotated
			}
			continue
		}

		readF, err := os.Open(path)
		if err != nil {
			return err
		}

		readF.Seek(offset, io.SeekStart)
		// At most 1 MiB per tick: a large backlog (a log replaced by a
		// bigger one) is read over several ticks, not into memory at once.
		buf := make([]byte, min(size-offset, maxMailRead))
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
				if idx <= maxMailLine {
					w.processLine(partial[:idx])
				}
				partial = partial[idx+1:]
			}
			if len(partial) > maxMailLine {
				partial = "" // no mail log line is this long: dropped
			}
		}

		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return err
		}
	}

	return nil
}

func (w *MailWatcher) processLine(line string) {
	ip, reason, details := parseMailLine(line)
	if ip == "" {
		return
	}

	if isPrivateIP(ip) {
		return
	}

	w.recordAttempt(ip, reason, details)
}

// recordAttempt counts a failure from ip and reports it with details (the
// fields of the log line, plus attempts: the failures from ip in the
// window, this one included).
func (w *MailWatcher) recordAttempt(ip, reason string, details map[string]string) {
	now := time.Now()

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.banned[ip] {
		return
	}

	if w.isWhitelisted(ip) {
		return
	}

	// Geoblocking — immediate ban
	if w.checkIP != nil {
		if banReason := w.checkIP(ip); banReason != "" {
			w.banned[ip] = true
			if w.monitorMode {
				if w.onEvent != nil {
					d := maps.Clone(details)
					d["reason"] = banReason
					d["attempts"] = "1"
					go w.onEvent(ip, reason, "critical", d)
				}
			} else {
				go w.onBan(ip, banReason, 1)
			}
			return
		}
	}

	var recent []time.Time
	for _, t := range w.attempts[ip] {
		if now.Sub(t) <= w.window {
			recent = append(recent, t)
		}
	}
	recent = append(recent, now)
	w.attempts[ip] = recent
	count := len(recent)

	// Report event for monitor mode or event tracking
	if w.onEvent != nil {
		severity := "warning"
		if reason == "mail_brute_force" {
			severity = "critical"
		}
		d := maps.Clone(details)
		if d == nil {
			d = map[string]string{}
		}
		d["attempts"] = strconv.Itoa(count)
		go w.onEvent(ip, reason, severity, d)
	}

	// Threshold check
	if count >= w.threshold {
		w.banned[ip] = true
		if w.monitorMode {
			// Already reported event above
		} else {
			go w.onBan(ip, reason, count)
		}
	}
}
