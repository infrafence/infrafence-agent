package opnsense

import (
	"encoding/json"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Log files (syslog-ng, one directory per category, latest.log follows
// the file of the day).
const (
	LogFilter    = "/var/log/filter/latest.log"
	LogAudit     = "/var/log/audit/latest.log" // program "audit" and facility auth: sshd, GUI logins
	LogSystem    = "/var/log/system/latest.log"
	LogOpenVPN   = "/var/log/openvpn/latest.log"
	LogWireGuard = "/var/log/wireguard/latest.log"
	EveJSON      = "/var/log/suricata/eve.json"
)

// SyslogLine is a parsed log line.
type SyslogLine struct {
	Time    time.Time
	Host    string
	Program string
	Msg     string
}

// ParseSyslog reads an RFC 5424 line as OPNsense writes them
// ("<38>1 2026-11-15T10:00:00+01:00 host sshd 123 - [meta sequenceId="1"] msg")
// or an RFC 3164 one ("Nov 15 10:00:00 host sshd[123]: msg").
func ParseSyslog(line string) (SyslogLine, bool) {
	s := strings.TrimSpace(line)
	if strings.HasPrefix(s, "<") {
		if i := strings.IndexByte(s, '>'); i > 0 && i < 5 {
			s = s[i+1:]
		}
	}
	if strings.HasPrefix(s, "1 ") {
		f := strings.SplitN(s[2:], " ", 6)
		if len(f) < 6 {
			return SyslogLine{}, false
		}
		out := SyslogLine{Host: f[1], Program: f[2]}
		out.Time, _ = time.Parse(time.RFC3339Nano, f[0])
		rest := f[5]
		// Structured data: "-" or one or more [id k="v" ...] elements.
		if strings.HasPrefix(rest, "- ") || rest == "-" {
			rest = strings.TrimPrefix(strings.TrimPrefix(rest, "-"), " ")
		} else {
			for strings.HasPrefix(rest, "[") {
				end := sdEnd(rest)
				if end < 0 {
					return SyslogLine{}, false
				}
				rest = rest[end+1:]
			}
			rest = strings.TrimPrefix(rest, " ")
		}
		out.Msg = strings.TrimPrefix(rest, "\ufeff")
		return out, true
	}
	// RFC 3164: "Mmm dd hh:mm:ss host prog[pid]: msg"
	if len(s) > 16 && s[3] == ' ' && s[6] == ' ' {
		rest := s[16:]
		host, rest, ok := strings.Cut(rest, " ")
		if !ok {
			return SyslogLine{}, false
		}
		tag, msg, ok := strings.Cut(rest, ": ")
		if !ok {
			return SyslogLine{}, false
		}
		if i := strings.IndexByte(tag, '['); i >= 0 {
			tag = tag[:i]
		}
		t, _ := time.Parse("Jan _2 15:04:05", s[:15])
		return SyslogLine{Time: t, Host: host, Program: tag, Msg: msg}, true
	}
	return SyslogLine{}, false
}

// sdEnd finds the "]" closing the SD element at s[0], skipping quoted
// values (where "\]" and "\"" are escaped).
func sdEnd(s string) int {
	inQ := false
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			inQ = !inQ
		case ']':
			if !inQ {
				return i
			}
		}
	}
	return -1
}

// FilterRecord is one pf filterlog record.
type FilterRecord struct {
	Rule      string
	Label     string // rule hash or uuid
	Interface string // device: vtnet1, igb0
	Reason    string
	Action    string // pass, block, reject
	Dir       string // in, out
	IPVersion int
	Proto     string // tcp, udp, icmp, ...
	Src       string
	Dst       string
	SrcPort   int
	DstPort   int
}

// ParseFilterLog reads a filterlog line (the CSV is the message).
func ParseFilterLog(line string) (FilterRecord, bool) {
	var csv string
	if sl, ok := ParseSyslog(line); ok {
		if sl.Program != "filterlog" {
			return FilterRecord{}, false
		}
		csv = sl.Msg
	} else {
		return FilterRecord{}, false
	}
	f := strings.Split(strings.TrimSpace(csv), ",")
	if len(f) < 9 {
		return FilterRecord{}, false
	}
	r := FilterRecord{Rule: f[0], Label: f[3], Interface: f[4], Reason: f[5], Action: f[6], Dir: f[7]}
	r.IPVersion, _ = strconv.Atoi(f[8])
	var rest []string
	switch r.IPVersion {
	case 4:
		// tos,ecn,ttl,id,offset,ipflags,protonum,protoname,length,src,dst
		if len(f) < 20 {
			return FilterRecord{}, false
		}
		r.Proto, r.Src, r.Dst = strings.ToLower(f[16]), f[18], f[19]
		rest = f[20:]
	case 6:
		// class,flow,hoplimit,protoname,protonum,length,src,dst
		if len(f) < 17 {
			return FilterRecord{}, false
		}
		r.Proto, r.Src, r.Dst = strings.ToLower(f[12]), f[15], f[16]
		rest = f[17:]
	default:
		return FilterRecord{}, false
	}
	if net.ParseIP(r.Src) == nil || net.ParseIP(r.Dst) == nil {
		return FilterRecord{}, false
	}
	if (r.Proto == "tcp" || r.Proto == "udp") && len(rest) >= 2 {
		r.SrcPort, _ = strconv.Atoi(rest[0])
		r.DstPort, _ = strconv.Atoi(rest[1])
	}
	return r, true
}

// IDSAlert is a Suricata alert from eve.json.
type IDSAlert struct {
	Time      string `json:"timestamp"`
	SrcIP     string `json:"src_ip"`
	SrcPort   int    `json:"src_port"`
	DestIP    string `json:"dest_ip"`
	DestPort  int    `json:"dest_port"`
	Proto     string `json:"proto"`
	Interface string `json:"in_iface"`
	Alert     struct {
		Action    string `json:"action"` // allowed, blocked
		SID       int64  `json:"signature_id"`
		Rev       int    `json:"rev"`
		Signature string `json:"signature"`
		Category  string `json:"category"`
		Severity  int    `json:"severity"` // 1 high .. 3 low
	} `json:"alert"`
}

// ParseEve reads one eve.json line: ok only for an alert.
func ParseEve(line string) (IDSAlert, bool) {
	var probe struct {
		Type string `json:"event_type"`
	}
	b := []byte(line)
	if json.Unmarshal(b, &probe) != nil || probe.Type != "alert" {
		return IDSAlert{}, false
	}
	var a IDSAlert
	if json.Unmarshal(b, &a) != nil || net.ParseIP(a.SrcIP) == nil {
		return IDSAlert{}, false
	}
	return a, true
}

// SeverityName maps Suricata's 1..3 to the dashboard's severities.
func (a IDSAlert) SeverityName() string {
	switch a.Alert.Severity {
	case 1:
		return "critical"
	case 2:
		return "warning"
	}
	return "info"
}

// AuthEvent is a login attempt seen in the logs.
type AuthEvent struct {
	Service string // ssh, opnsense-gui, openvpn, wireguard
	Result  string // failure, success
	IP      string
	User    string
	Reason  string // matched pattern, for the event details
	// Spoofable: the address comes from an unauthenticated UDP packet, so
	// it is never banned (anyone could get any address banned).
	Spoofable bool
}

// ip matches an IPv4 or IPv6 address.
const ipRe = `([0-9a-fA-F:.]*[0-9a-fA-F])`

type authPattern struct {
	program string // "" any
	re      *regexp.Regexp
	service string
	result  string
	reason  string
	userIdx int // group with the user (0: none)
	ipIdx   int
	// spoofable: the source address is not authenticated (UDP before a
	// handshake): counted and reported, never banned.
	spoofable bool
}

// Every pattern is anchored at both ends and takes the user greedily, so
// the address is the last "from <ip>" of the line: a user name is
// attacker-controlled text and may itself contain "from 8.8.4.4 port 1".
var authPatterns = []authPattern{
	// sshd (OpenSSH on FreeBSD)
	{program: "sshd", re: regexp.MustCompile(`^Failed (?:password|publickey|keyboard-interactive/pam|none) for (?:invalid user )?(.*) from ` + ipRe + ` port \d+ ssh2$`), service: "ssh", result: "failure", reason: "brute_force_ssh", userIdx: 1, ipIdx: 2},
	{program: "sshd", re: regexp.MustCompile(`^Invalid user (.*) from ` + ipRe + ` port \d+$`), service: "ssh", result: "failure", reason: "brute_force_ssh", userIdx: 1, ipIdx: 2},
	{program: "sshd", re: regexp.MustCompile(`^error: maximum authentication attempts exceeded for (?:invalid user )?(.*) from ` + ipRe + ` port \d+ ssh2 \[preauth\]$`), service: "ssh", result: "failure", reason: "brute_force_ssh", userIdx: 1, ipIdx: 2},
	{program: "sshd", re: regexp.MustCompile(`^error: PAM: Authentication error for (?:illegal user )?(.*) from ` + ipRe + `$`), service: "ssh", result: "failure", reason: "brute_force_ssh", userIdx: 1, ipIdx: 2},
	{program: "sshd", re: regexp.MustCompile(`^Accepted (?:password|publickey|keyboard-interactive/pam) for (\S+) from ` + ipRe + ` port \d+ ssh2(?:: \S+ \S+)?$`), service: "ssh", result: "success", reason: "ssh_login", userIdx: 1, ipIdx: 2},
	// Web GUI, MVC login (AuthenticationFactory) and the legacy page
	// ("<script>: " prefix from log_msg()).
	{program: "audit", re: regexp.MustCompile(`^(?:\S+: )?user (.*) could not authenticate for WebGui\. \[using [^\]]*\] at ` + ipRe + `$`), service: "opnsense-gui", result: "failure", reason: "brute_force_gui", userIdx: 1, ipIdx: 2},
	{program: "audit", re: regexp.MustCompile(`^\S+: Web GUI authentication error for '(.*)' from ` + ipRe + `$`), service: "opnsense-gui", result: "failure", reason: "brute_force_gui", userIdx: 1, ipIdx: 2},
	{program: "audit", re: regexp.MustCompile(`^\S+: Successful login for user '([^']*)' from: ` + ipRe + `$`), service: "opnsense-gui", result: "success", reason: "gui_login", userIdx: 1, ipIdx: 2},
	{program: "audit", re: regexp.MustCompile(`^(?:\S+: )?user (\S+) authenticated successfully for WebGui \[using [^\]]*\] at ` + ipRe + `$`), service: "opnsense-gui", result: "success", reason: "gui_login", userIdx: 1, ipIdx: 2},
	// OpenVPN server: a failed user/password check comes after a complete
	// TLS handshake, so its address is real. Handshake and HMAC failures
	// are pre-authentication UDP: the source can be spoofed, so they are
	// reported, never banned ("1.2.3.4:51234 ...", "[AF_INET6]2001:db8::1:1194 ...").
	{program: "openvpn", re: regexp.MustCompile(`^(?:\S+/)?(?:\[AF_INET6?\])?` + ipRe + `:\d+ TLS Auth Error: Auth Username/Password verification failed for peer$`), service: "openvpn", result: "failure", reason: "brute_force_vpn", ipIdx: 1},
	{program: "openvpn", re: regexp.MustCompile(`^(?:\S+/)?(?:\[AF_INET6?\])?` + ipRe + `:\d+ (?:TLS Error: TLS handshake failed|TLS Error: cannot locate HMAC in incoming packet from \S+|TLS Error: tls-crypt unwrapping failed from \S+|VERIFY ERROR: .*)$`), service: "openvpn", result: "failure", reason: "brute_force_vpn", ipIdx: 1, spoofable: true},
	// WireGuard drops unauthenticated packets without a trace; with debug
	// logging, FreeBSD's if_wg names the endpoint of a bad handshake: UDP,
	// spoofable, reported only.
	{program: "kernel", re: regexp.MustCompile(`^wg\d+: (?:Invalid handshake initiation|Invalid handshake response|Invalid initiation MAC|Invalid cookie) from \[?` + ipRe + `\]?:\d+$`), service: "wireguard", result: "failure", reason: "brute_force_vpn", ipIdx: 1, spoofable: true},
	{program: "wireguard", re: regexp.MustCompile(`^wg\d+: (?:Invalid handshake initiation|Invalid handshake response|Invalid initiation MAC|Invalid cookie) from \[?` + ipRe + `\]?:\d+$`), service: "wireguard", result: "failure", reason: "brute_force_vpn", ipIdx: 1, spoofable: true},
}

// ParseAuth reads an auth log line (any OPNsense log file).
func ParseAuth(line string) (AuthEvent, bool) {
	sl, ok := ParseSyslog(line)
	if !ok {
		return AuthEvent{}, false
	}
	prog := sl.Program
	for _, p := range authPatterns {
		if p.program != "" && p.program != prog && !(p.program == "openvpn" && strings.HasPrefix(prog, "openvpn")) {
			continue
		}
		m := p.re.FindStringSubmatch(sl.Msg)
		if m == nil {
			continue
		}
		ip := m[p.ipIdx]
		if parsed := net.ParseIP(ip); parsed == nil {
			continue
		} else {
			ip = parsed.String()
		}
		ev := AuthEvent{Service: p.service, Result: p.result, IP: ip, Reason: p.reason, Spoofable: p.spoofable}
		if p.userIdx > 0 {
			ev.User = truncate(m[p.userIdx], 64)
		}
		return ev, true
	}
	return AuthEvent{}, false
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
