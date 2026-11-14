package watcher

import (
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Read-only helpers for the one-shot server audit (internal/audit): the
// same patterns the watchers use, applied to log lines already written,
// without any of the watchers' state (scores, bans, whitelists).

// MatchSSH returns the client address and the reason of an SSH
// authentication log line the SSH watcher counts as an attack
// ("brute_force_ssh", "brute_force_ssh_preauth"), or "" for any other line.
func MatchSSH(line string) (ip, reason string) { return matchSSH(line) }

// SuspiciousRequest reads one access log line of a source written by
// server (as DetectWebLogInfo names it, "" when unknown) and returns the
// client address and the attack class when the web watcher's built-in
// rules match it: path traversal, SQL injection, .env and config probing,
// RCE, XSS, SSRF, web shells, known exploits (instantBanPatterns) and known
// scanner user agents. Static resources and private addresses never match.
func SuspiciousRequest(line, server string) (ip, kind string, ok bool) {
	entry, res := parseLine(line, server)
	if res != parseOK {
		return "", "", false
	}
	ip = normIP(entry.ip)
	if ip == "" || isPrivateIP(ip) {
		return "", "", false
	}
	uriRaw := strings.ToLower(entry.uri)
	uriLower := uriRaw
	if d, err := url.QueryUnescape(uriLower); err == nil {
		uriLower = d
	}
	if d, err := url.QueryUnescape(uriLower); err == nil {
		uriLower = d
	}
	if isStaticResource(uriLower) {
		return "", "", false
	}
	for _, rule := range instantBanPatterns {
		for _, pat := range rule.patterns {
			if strings.Contains(uriLower, pat) || strings.Contains(uriRaw, pat) {
				return ip, rule.eventType, true
			}
		}
	}
	ua := strings.ToLower(entry.userAgent)
	for _, agent := range scannerAgents {
		if strings.Contains(ua, agent) {
			return ip, "scanner_detected", true
		}
	}
	return "", "", false
}

// AccessLogTime returns the time of an access log line: the combined
// format's "[02/Jan/2006:15:04:05 -0700]", or the "time"/"ts"/"StartUTC"
// field of a JSON line (Caddy writes seconds since the epoch).
func AccessLogTime(line string) (time.Time, bool) {
	if i := strings.IndexByte(line, '['); i >= 0 {
		if j := strings.IndexByte(line[i:], ']'); j > 0 {
			if t, err := time.Parse("02/Jan/2006:15:04:05 -0700", line[i+1:i+j]); err == nil {
				return t, true
			}
		}
	}
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "{") {
		return time.Time{}, false
	}
	for _, key := range []string{`"time":"`, `"StartUTC":"`, `"ts":"`, `"timestamp":"`} {
		if i := strings.Index(trimmed, key); i >= 0 {
			rest := trimmed[i+len(key):]
			if j := strings.IndexByte(rest, '"'); j > 0 {
				if t, err := time.Parse(time.RFC3339Nano, rest[:j]); err == nil {
					return t, true
				}
			}
		}
	}
	if i := strings.Index(trimmed, `"ts":`); i >= 0 {
		rest := strings.TrimSpace(trimmed[i+5:])
		if end := strings.IndexAny(rest, ",}"); end > 0 {
			if f, err := strconv.ParseFloat(strings.TrimSpace(rest[:end]), 64); err == nil && f > 0 {
				return time.Unix(0, int64(f*1e9)).UTC(), true
			}
		}
	}
	return time.Time{}, false
}
