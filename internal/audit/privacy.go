package audit

import (
	"bufio"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/infrafence/infrafence-agent/internal/netstate"
)

// Redacted replaces a value that held something private.
const Redacted = "[redacted]"

// Private is what identifies this server or its people, and so never
// leaves it: its host names, its addresses and its user accounts (root is
// allowed: it says nothing about who runs the server).
type Private struct {
	Hostnames []string
	IPs       []string
	Users     []string
}

// HostPrivate reads the private values of this host: the host name (and
// its first label), /etc/hostname, every interface address, and the login
// accounts of /etc/passwd (UID from UID_MIN, 1000 by default, up to
// 59999, and any other account with UID 0).
func HostPrivate() Private {
	var p Private
	if h, err := os.Hostname(); err == nil {
		p.Hostnames = append(p.Hostnames, h)
	}
	if b, err := os.ReadFile("/etc/hostname"); err == nil {
		p.Hostnames = append(p.Hostnames, strings.TrimSpace(string(b)))
	}
	for _, h := range p.Hostnames {
		if first, _, ok := strings.Cut(h, "."); ok {
			p.Hostnames = append(p.Hostnames, first)
		}
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				p.IPs = append(p.IPs, ipn.IP.String())
			}
		}
	}
	p.Users = loginUsers("/etc/passwd", uidMin("/etc/login.defs"))
	return p
}

func uidMin(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 1000
	}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) == 2 && f[0] == "UID_MIN" {
			if n, err := strconv.Atoi(f[1]); err == nil && n > 0 {
				return n
			}
		}
	}
	return 1000
}

// loginUsers returns the people's accounts of a passwd file.
func loginUsers(path string, min int) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ":")
		if len(parts) < 4 || parts[0] == "" || parts[0] == "root" {
			continue
		}
		uid, err := strconv.Atoi(parts[2])
		if err != nil {
			continue
		}
		if uid == 0 || (uid >= min && uid < 60000) {
			out = append(out, parts[0])
		}
	}
	return out
}

var (
	// Secrets: key material, credentials in a key=value or URL, tokens.
	secretRes = []*regexp.Regexp{
		regexp.MustCompile(`-----BEGIN`),
		regexp.MustCompile(`(?i)(pass(word|wd)?|secret|token|api[_-]?key|auth|credential|private[_-]?key)\s*[=:]`),
		regexp.MustCompile(`://[^/\s:@]+:[^/\s@]+@`),
		regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|sk_(live|test)_[A-Za-z0-9]{10,})`),
		regexp.MustCompile(`[A-Za-z0-9+=_-]{32,}`), // long random-looking strings (not paths)
		regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`),
	}
	homeRe = regexp.MustCompile(`(^|[^A-Za-z0-9_])/home(/|$|[^A-Za-z0-9_])`)
	// Anything shaped like an IP address (a fact has no reason to hold one).
	ipv4Re = regexp.MustCompile(`\b\d{1,3}(\.\d{1,3}){3}\b`)
	ipv6Re = regexp.MustCompile(`(?i)\b[0-9a-f]{0,4}(:[0-9a-f]{0,4}){2,7}\b`)
	osIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)
	// osTokenRe: what os.version and os.kernel may be, or they are
	// redacted. The underscore is there for RHEL kernels
	// (4.18.0-553.el8_10.x86_64).
	osTokenRe = regexp.MustCompile(`^[A-Za-z0-9._~+-]{1,64}$`)
)

// filter applies the privacy rules to strings.
type filter struct {
	p     Private
	hosts []string
	users []string
	ips   map[string]bool
}

func newFilter(p Private) filter {
	f := filter{p: p, ips: map[string]bool{}}
	for _, h := range p.Hostnames {
		h = strings.ToLower(strings.TrimSpace(h))
		// "localhost" says nothing; a name of one to three characters
		// can't be told from ordinary words.
		if len(h) >= 4 && h != "localhost" && h != "localhost.localdomain" {
			f.hosts = append(f.hosts, h)
		}
	}
	for _, u := range p.Users {
		if u = strings.TrimSpace(u); u != "" && u != "root" {
			f.users = append(f.users, strings.ToLower(u))
		}
	}
	for _, ip := range p.IPs {
		if parsed := net.ParseIP(ip); parsed != nil {
			f.ips[parsed.String()] = true
		}
	}
	return f
}

// clean trims a value to the contract's limits: printable characters
// only, at most maxFactValue bytes.
func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if !unicode.IsPrint(r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > maxFactValue {
		cut := maxFactValue
		for cut > 0 && !utf8Start(s[cut]) {
			cut--
		}
		s = s[:cut]
	}
	return s
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

// containsWord reports whether s holds w with no letter, digit or
// underscore right before or after it.
func containsWord(s, w string) bool {
	for i := 0; ; {
		j := strings.Index(s[i:], w)
		if j < 0 {
			return false
		}
		start, end := i+j, i+j+len(w)
		before := start == 0 || !isWordByte(s[start-1])
		after := end == len(s) || !isWordByte(s[end])
		if before && after {
			return true
		}
		i = start + 1
	}
}

func isWordByte(b byte) bool {
	return b == '_' || b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// identifying reports whether s names this host or its server addresses.
func (f filter) identifying(s string) bool {
	low := strings.ToLower(s)
	for _, h := range f.hosts {
		if containsWord(low, h) {
			return true
		}
	}
	for ip := range f.ips {
		if containsWord(low, strings.ToLower(ip)) {
			return true
		}
	}
	return false
}

// text filters a free-text value (a fact, a process name): any private
// value makes the whole value Redacted.
func (f filter) text(s string) string {
	s = clean(s)
	if s == "" {
		return s
	}
	if f.identifying(s) || homeRe.MatchString(s) || ipv4Re.MatchString(s) || ipv6Re.MatchString(s) {
		return Redacted
	}
	low := strings.ToLower(s)
	for _, u := range f.users {
		if containsWord(low, u) {
			return Redacted
		}
	}
	for _, re := range secretRes {
		if re.MatchString(s) {
			return Redacted
		}
	}
	return s
}

// fixed filters a value from a fixed vocabulary or the system (the kernel
// release, a version): only the host's names and addresses are removed.
func (f filter) fixed(s string) string {
	s = clean(s)
	if f.identifying(s) {
		return Redacted
	}
	return s
}

// attacker reports whether ip may be listed as an attacker: a public
// address that is not one of this server's.
func (f filter) attacker(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil || !netstate.IsPublic(parsed) {
		return false
	}
	return !f.ips[parsed.String()]
}

// Sanitize applies the privacy rules to every string of r, in place. It is
// the last step before a report is shown or sent.
func Sanitize(r *Report, p Private) {
	f := newFilter(p)
	if !osIDRe.MatchString(r.OS.ID) {
		r.OS.ID = Redacted
	}
	r.OS.ID = f.fixed(r.OS.ID)
	r.OS.Version = f.fixed(osToken(r.OS.Version))
	r.OS.Kernel = f.fixed(osToken(r.OS.Kernel))
	r.OS.Arch = f.fixed(r.OS.Arch)
	r.AgentVersion = f.fixed(r.AgentVersion)
	r.Environment.Panel = f.text(r.Environment.Panel)
	r.Environment.WebServer = f.text(r.Environment.WebServer)
	for i := range r.Checks {
		c := &r.Checks[i]
		facts := make(map[string]string, len(c.Facts))
		for k, v := range c.Facts {
			if !factKeyRe.MatchString(k) || len(facts) >= maxFacts {
				continue
			}
			facts[k] = f.text(v)
		}
		c.Facts = facts
	}
	for i := range r.Listening {
		r.Listening[i].Process = f.text(r.Listening[i].Process)
		if len(r.Listening[i].Process) > 64 {
			r.Listening[i].Process = r.Listening[i].Process[:64]
		}
	}
	top := make([]TopIP, 0, len(r.Attacks.TopIPs))
	for _, t := range r.Attacks.TopIPs {
		if f.attacker(t.IP) {
			top = append(top, t)
		}
	}
	r.Attacks.TopIPs = top
}

// osToken keeps an os.version or os.kernel value that is one short token
// (osTokenRe); anything else (spaces, slashes, quotes, more than 64
// characters) is redacted. Empty stays empty: os-release may have no
// VERSION_ID.
func osToken(s string) string {
	if s == "" || osTokenRe.MatchString(s) {
		return s
	}
	return Redacted
}
