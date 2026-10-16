// Package panel is the local interface the hosting panel plugins (WHM and
// Plesk) use: "infrafence-agent panel <command> --json" sends one request to
// the running agent over a Unix socket only root can reach, and prints the
// agent's JSON answer. Nothing here listens on the network.
//
// Every answer is one JSON object, {"ok": true, ...} or {"ok": false,
// "error": "<code>", "message": "..."}. The plugins read the error code,
// never the message.
package panel

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// SocketPath is where the running agent listens.
const SocketPath = "/run/infrafence/panel.sock"

// Error codes.
const (
	ErrBadRequest      = "bad_request"
	ErrUnknownCommand  = "unknown_command"
	ErrInvalidIP       = "invalid_ip"
	ErrInvalidPath     = "invalid_path"
	ErrInvalidActor    = "invalid_actor"
	ErrAgentNotRunning = "agent_not_running"
	ErrNotBanned       = "not_banned"
	ErrNotAllowed      = "not_in_allowlist"
	ErrManaged         = "managed_by_dashboard"
	ErrUnknownPath     = "not_a_document_root"
	ErrNotScannable    = "not_scannable"
	ErrScanRunning     = "scan_running"
	ErrInternal        = "internal_error"
	ErrNotRoot         = "not_root"
)

// Request is one command sent to the agent.
type Request struct {
	Command string `json:"command"`
	IP      string `json:"ip,omitempty"`
	Path    string `json:"path,omitempty"`
	Note    string `json:"note,omitempty"`
	Actor   string `json:"actor,omitempty"`
	Limit   int    `json:"limit,omitempty"`
	Since   string `json:"since,omitempty"` // RFC 3339
}

// Response is the agent's answer: ok, or an error code with a message, plus
// the command's own fields.
type Response map[string]any

// OK returns a successful answer carrying fields.
func OK(fields map[string]any) Response {
	r := Response{"ok": true}
	for k, v := range fields {
		r[k] = v
	}
	return r
}

// Fail returns an error answer.
func Fail(code, format string, args ...any) Response {
	return Response{"ok": false, "error": code, "message": fmt.Sprintf(format, args...)}
}

// Succeeded reports whether r is an ok answer.
func (r Response) Succeeded() bool { ok, _ := r["ok"].(bool); return ok }

// Commands that change something on the server; each needs --actor.
var Mutating = map[string]bool{"unban": true, "allow": true, "disallow": true, "scan": true}

// Commands lists every command and whether it takes an address or a path.
var Commands = map[string]string{
	"status": "", "bans": "", "unban": "ip", "allow": "ip", "allowlist": "", "disallow": "ip",
	"findings": "", "events": "", "coexistence": "", "sites": "", "scan": "path",
}

const (
	DefaultLimit = 50
	MaxLimit     = 500
	maxNote      = 200
	maxActor     = 64
	maxPath      = 1024
)

// ParseIP accepts exactly one IPv4 or IPv6 address (no range, port or zone)
// and returns its canonical form.
func ParseIP(s string) (string, bool) {
	if s == "" || len(s) > 45 || strings.TrimSpace(s) != s {
		return "", false
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return "", false
	}
	a = a.Unmap()
	if a.IsUnspecified() || a.IsMulticast() || a == netip.IPv4Unspecified() || a.Is4() && a.As4()[0] == 255 {
		return "", false
	}
	return a.String(), true
}

// ValidActor: the panel user name, as WHM and Plesk allow it.
func ValidActor(s string) bool {
	if s == "" || len(s) > maxActor {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._@-+", c)) {
			return false
		}
	}
	return true
}

// CleanNote returns the note if it is short, printable text.
func CleanNote(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if len(s) > maxNote {
		return "", false
	}
	for _, c := range s {
		if !unicode.IsPrint(c) {
			return "", false
		}
	}
	return s, true
}

// ValidPath accepts a clean absolute path without control characters.
func ValidPath(s string) bool {
	if s == "" || len(s) > maxPath || !filepath.IsAbs(s) || filepath.Clean(s) != s || s == "/" {
		return false
	}
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// ParseLimit reads --limit: 1..MaxLimit, DefaultLimit when empty.
func ParseLimit(s string) (int, bool) {
	if s == "" {
		return DefaultLimit, true
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > MaxLimit {
		return 0, false
	}
	return n, true
}

// ParseSince reads --since: an RFC 3339 time or a duration back from now
// ("24h", "30m"), at most 90 days. Returns the time in RFC 3339 (UTC).
func ParseSince(s string, now time.Time) (string, bool) {
	if s == "" {
		return "", true
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC().Format(time.RFC3339), true
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 || d > 90*24*time.Hour {
		return "", false
	}
	return now.Add(-d).UTC().Format(time.RFC3339), true
}

// ParseArgs turns "infrafence-agent panel" arguments into a request:
// <command> [ip|path] [--actor X] [--note X] [--limit N] [--since X] [--json].
// Both "--flag value" and "--flag=value" work.
func ParseArgs(args []string, now time.Time) (Request, bool, Response) {
	var req Request
	jsonOut := false
	var positional []string
	flags := map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "--") {
			positional = append(positional, a)
			continue
		}
		name, val, hasVal := strings.Cut(strings.TrimPrefix(a, "--"), "=")
		switch name {
		case "json":
			if hasVal {
				return req, jsonOut, Fail(ErrBadRequest, "--json takes no value")
			}
			jsonOut = true
			continue
		case "actor", "note", "limit", "since":
		default:
			return req, jsonOut, Fail(ErrBadRequest, "unknown option --%s", name)
		}
		if !hasVal {
			if i+1 >= len(args) {
				return req, jsonOut, Fail(ErrBadRequest, "--%s needs a value", name)
			}
			i++
			val = args[i]
		}
		if _, dup := flags[name]; dup {
			return req, jsonOut, Fail(ErrBadRequest, "--%s given twice", name)
		}
		flags[name] = val
	}
	if len(positional) == 0 {
		return req, jsonOut, Fail(ErrBadRequest, "missing command")
	}
	req.Command = positional[0]
	operand, known := Commands[req.Command]
	if !known {
		return req, jsonOut, Fail(ErrUnknownCommand, "unknown command %q", req.Command)
	}
	want := 1
	if operand != "" {
		want = 2
	}
	if len(positional) != want {
		if operand != "" {
			return req, jsonOut, Fail(ErrBadRequest, "%s needs exactly one %s", req.Command, operand)
		}
		return req, jsonOut, Fail(ErrBadRequest, "%s takes no arguments", req.Command)
	}
	switch operand {
	case "ip":
		ip, ok := ParseIP(positional[1])
		if !ok {
			return req, jsonOut, Fail(ErrInvalidIP, "not a single IPv4 or IPv6 address")
		}
		req.IP = ip
	case "path":
		if !ValidPath(positional[1]) {
			return req, jsonOut, Fail(ErrInvalidPath, "not a clean absolute path")
		}
		req.Path = positional[1]
	}

	allowed := map[string]bool{}
	if Mutating[req.Command] {
		allowed["actor"] = true
	}
	switch req.Command {
	case "allow":
		allowed["note"] = true
	case "bans", "findings":
		allowed["limit"] = true
	case "events":
		allowed["limit"], allowed["since"] = true, true
	}
	for name := range flags {
		if !allowed[name] {
			return req, jsonOut, Fail(ErrBadRequest, "%s does not take --%s", req.Command, name)
		}
	}
	if Mutating[req.Command] {
		if !ValidActor(flags["actor"]) {
			return req, jsonOut, Fail(ErrInvalidActor, "--actor must be the panel user (letters, digits, . _ @ - +)")
		}
		req.Actor = flags["actor"]
	}
	if v, ok := flags["note"]; ok {
		note, ok := CleanNote(v)
		if !ok {
			return req, jsonOut, Fail(ErrBadRequest, "--note must be printable text of at most %d bytes", maxNote)
		}
		req.Note = note
	}
	if allowed["limit"] {
		n, ok := ParseLimit(flags["limit"])
		if !ok {
			return req, jsonOut, Fail(ErrBadRequest, "--limit must be between 1 and %d", MaxLimit)
		}
		req.Limit = n
	}
	if v := flags["since"]; v != "" {
		since, ok := ParseSince(v, now)
		if !ok {
			return req, jsonOut, Fail(ErrBadRequest, "--since must be an RFC 3339 time or a duration such as 24h (at most 90 days)")
		}
		req.Since = since
	}
	return req, jsonOut, nil
}

// Validate re-checks a request received on the socket: the agent never
// trusts that it came from ParseArgs.
func Validate(req *Request) Response {
	operand, known := Commands[req.Command]
	if !known {
		return Fail(ErrUnknownCommand, "unknown command %q", req.Command)
	}
	switch operand {
	case "ip":
		ip, ok := ParseIP(req.IP)
		if !ok {
			return Fail(ErrInvalidIP, "not a single IPv4 or IPv6 address")
		}
		req.IP = ip
	case "path":
		if !ValidPath(req.Path) {
			return Fail(ErrInvalidPath, "not a clean absolute path")
		}
	}
	if Mutating[req.Command] && !ValidActor(req.Actor) {
		return Fail(ErrInvalidActor, "missing or invalid actor")
	}
	note, ok := CleanNote(req.Note)
	if !ok {
		return Fail(ErrBadRequest, "invalid note")
	}
	req.Note = note
	if req.Limit == 0 {
		req.Limit = DefaultLimit
	}
	if req.Limit < 1 || req.Limit > MaxLimit {
		return Fail(ErrBadRequest, "limit must be between 1 and %d", MaxLimit)
	}
	if req.Since != "" {
		if _, err := time.Parse(time.RFC3339, req.Since); err != nil {
			return Fail(ErrBadRequest, "invalid since")
		}
	}
	return nil
}
