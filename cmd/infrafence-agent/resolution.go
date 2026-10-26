package main

import (
	"cmp"
	"log"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/remediation"
)

// Problem events and their resolution. A problem event reports a condition
// that can still be true on the server: a database port open to the
// internet, a changed system file, a dangerous PHP setting, malware, a fix
// or update that failed. Each carries details.subject, a stable key of what
// it is about, the same in the agent and in the dashboard:
//
//	port:<proto>/<port>   db_exposed, firewall_action_* (close_port, open_port)
//	file:<path>           integrity_change, php_dropin_changed
//	php:<check_id>        php_config_risk, hardening_fix_* of a PHP check
//	hardening:<check_id>  hardening_fix_* of any other check
//	malware:<path>        malware_realtime, quarantine_*
//	cve:<id>              virtual_patch_done, virtual_patch_failed
//	package:<name>        package_update_* of one package
//
// Result events (firewall_action_*, quarantine_*, hardening_fix_applied,
// virtual_patch_done, package_update_*) carry the subject they acted on
// too, so the dashboard can tie them to the problem.
//
// A subject is resolved from a time on: the dashboard sends what it
// resolved (the sync's resolutions: a port closed, a fix applied, marked as
// resolved...), and the agent records what it fixed itself (a port its
// firewall closed, a fix applied and verified, a file quarantined, a package
// updated). These are kept in the panel state (panelstate.go), 0600, for 30
// days. An event at or before the resolution is resolved; a newer one is
// open again. "infrafence-agent panel events" and "findings" show it.

const (
	resolutionMaxAge     = 30 * 24 * time.Hour
	maxResolutions       = 500 // the agent's own, kept in the panel state
	maxSyncedResolutions = 500 // the dashboard sends at most 200
	maxSubject           = 1100
	maxFixedSubjects     = 100 // packages of one update
	// A resolution later than this (clock skew, a bad value) would hide new
	// occurrences until then: it is dropped.
	resolutionMaxSkew = 5 * time.Minute
)

// resolution is one resolved subject.
type resolution struct {
	Subject string `json:"subject"`
	At      int64  `json:"at"`  // Unix time
	How     string `json:"how"` // port_closed, fix_applied, quarantined, package_updated...
	By      string `json:"by,omitempty"`
}

// syncedResolutions are those of the last sync (none from older dashboards).
var syncedResolutions atomic.Pointer[[]resolution]

var (
	dbExposedWarning = regexp.MustCompile(` on port (\d{1,5})$`)
	subjectPrefix    = regexp.MustCompile(`^[a-z_]{1,16}:.`)
	resolutionWord   = regexp.MustCompile(`^[A-Za-z_]{1,32}$`)
)

// eventSubject is the subject of an event, or "" when it has none.
func eventSubject(e api.EventRequest) string {
	d := e.Details
	switch e.Type {
	case "db_exposed":
		if s := portSubject(d["proto"], d["port"]); s != "" {
			return s
		}
		// Sent by agents before 1.0.34 (and kept): the port is in the text.
		if m := dbExposedWarning.FindStringSubmatch(d["warning"]); m != nil {
			return portSubject("tcp", m[1])
		}
	case "firewall_action_done", "firewall_action_failed", "firewall_action_rolled_back":
		if d["kind"] == "close_port" || d["kind"] == "open_port" {
			return portSubject(d["proto"], d["port"])
		}
	case "integrity_change", "php_dropin_changed":
		return pathSubject("file:", d["file"])
	case "php_config_risk":
		if remediation.IsPHPCheck(d["check_id"]) {
			return "php:" + d["check_id"]
		}
	case "hardening_fix_applied", "hardening_fix_failed", "hardening_fix_rolled_back":
		if id := d["check_id"]; id != "" {
			if remediation.IsPHPCheck(id) {
				return "php:" + id
			}
			return "hardening:" + id
		}
	case "malware_realtime":
		return pathSubject("malware:", d["file_path"])
	case "quarantine_completed", "quarantine_failed", "quarantine_restored", "quarantine_restore_failed":
		return pathSubject("malware:", d["file"])
	case "virtual_patch_done", "virtual_patch_failed":
		if c := d["cve"]; c != "" {
			return "cve:" + c
		}
	case "package_update_started", "package_update_done", "package_update_failed":
		if p := strings.Fields(d["packages"]); len(p) == 1 {
			return "package:" + p[0]
		}
	}
	return ""
}

// problemEvent: e reports a condition that can be resolved (as opposed to
// an attack, a result or a progress note). Only these get a state.
func problemEvent(e api.EventRequest) bool {
	switch e.Type {
	case "db_exposed", "integrity_change", "php_dropin_changed", "php_config_risk", "malware_realtime", "package_update_failed":
		return true
	case "virtual_patch_failed":
		return e.Details["action"] == "apply"
	case "hardening_fix_failed", "hardening_fix_rolled_back":
		// A revert that failed leaves the fix in place: nothing at risk.
		return e.Details["action"] != "revert"
	}
	return false
}

func portSubject(proto, port string) string {
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return ""
	}
	proto = strings.ToLower(proto)
	if proto == "" {
		proto = "tcp"
	}
	if proto != "tcp" && proto != "udp" {
		return ""
	}
	return "port:" + proto + "/" + strconv.Itoa(n)
}

func pathSubject(prefix, path string) string {
	if !strings.HasPrefix(path, "/") {
		return ""
	}
	return prefix + path
}

// addEventSubject sets details.subject on an event that has one (the
// event enricher: every event the agent sends).
func addEventSubject(e *api.EventRequest) {
	if e.Details["subject"] != "" {
		return
	}
	s := eventSubject(*e)
	if s == "" {
		return
	}
	// The details map may be shared with the caller: copy before adding.
	d := make(map[string]string, len(e.Details)+1)
	for k, v := range e.Details {
		d[k] = v
	}
	d["subject"] = s
	e.Details = d
}

// fixedByAgent returns the subjects the agent resolved itself with e, and
// how: a port its firewall closed (not one still reachable over IPv6), a
// fix applied and verified, a file quarantined, a package updated.
func fixedByAgent(e api.EventRequest) (subjects []string, how string) {
	d := e.Details
	switch e.Type {
	case "firewall_action_done":
		if d["kind"] == "close_port" && d["status"] == "done" && d["message"] != ipv6ExposedMessage {
			if s := eventSubject(e); s != "" {
				return []string{s}, "port_closed"
			}
		}
	case "hardening_fix_applied":
		// A warning: applied, but the verification failed afterwards.
		if d["action"] != "revert" && d["status"] == "applied" && e.Severity == "info" {
			if s := eventSubject(e); s != "" {
				return []string{s}, "fix_applied"
			}
		}
	case "virtual_patch_done":
		if d["action"] == "apply" {
			if s := eventSubject(e); s != "" {
				return []string{s}, "fix_applied"
			}
		}
	case "quarantine_completed":
		if s := eventSubject(e); s != "" {
			return []string{s}, "quarantined"
		}
	case "package_update_done":
		for _, p := range strings.Fields(d["packages"]) {
			if s := "package:" + p; validSubject(s) && len(subjects) < maxFixedSubjects {
				subjects = append(subjects, s)
			}
		}
		return subjects, "package_updated"
	}
	return nil, ""
}

// noteFixedLocked records what the agent fixed with e; the caller holds
// panelState.
func noteFixedLocked(e api.EventRequest) {
	subjects, how := fixedByAgent(e)
	if len(subjects) == 0 {
		return
	}
	now := panelNow()
	at := now
	if t, ok := parseEventTime(e.OccurredAt); ok && !t.After(now) {
		at = t
	}
	fixed := make(map[string]bool, len(subjects))
	for _, s := range subjects {
		fixed[cleanText(s, maxSubject)] = true
	}
	kept := panelState.p.Resolved[:0]
	for _, r := range panelState.p.Resolved {
		if !fixed[r.Subject] {
			kept = append(kept, r)
		}
	}
	for s := range fixed {
		kept = append(kept, resolution{Subject: s, At: at.Unix(), How: how, By: "agent"})
	}
	panelState.p.Resolved = boundResolutions(kept, now)
	savePanelStateLocked()
}

// boundResolutions keeps the agent's own resolutions that are valid, at
// most 30 days old and not in the future: the newest maxResolutions, in
// time order (also for a state file written by an older or damaged agent).
func boundResolutions(rs []resolution, now time.Time) []resolution {
	kept := rs[:0]
	for _, r := range rs {
		t := time.Unix(r.At, 0)
		if validSubject(r.Subject) && resolutionWord.MatchString(r.How) && now.Sub(t) <= resolutionMaxAge && !t.After(now.Add(resolutionMaxSkew)) {
			kept = append(kept, r)
		}
	}
	slices.SortStableFunc(kept, func(a, b resolution) int { return cmp.Compare(a.At, b.At) })
	if n := len(kept) - maxResolutions; n > 0 {
		kept = kept[n:]
	}
	return kept
}

// panelNoteResolutions keeps the resolutions of a sync.
func panelNoteResolutions(rs []api.Resolution) {
	if !panelOn.Load() {
		return
	}
	out := make([]resolution, 0, min(len(rs), maxSyncedResolutions))
	for _, r := range rs {
		if len(out) == maxSyncedResolutions {
			break
		}
		t, ok := parseEventTime(r.ResolvedAt)
		if !ok || t.After(panelNow().Add(resolutionMaxSkew)) || !validSubject(r.Subject) || !resolutionWord.MatchString(r.How) {
			continue
		}
		by := r.By
		if !resolutionWord.MatchString(by) {
			by = ""
		}
		out = append(out, resolution{Subject: r.Subject, At: t.Unix(), How: r.How, By: by})
	}
	syncedResolutions.Store(&out)
}

func validSubject(s string) bool {
	return len(s) <= maxSubject && subjectPrefix.MatchString(s) && cleanText(s, maxSubject) == s
}

// parseEventTime reads an RFC 3339 time, with or without fractional
// seconds.
func parseEventTime(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, s)
	return t, err == nil
}

// resolutionLocked is the first resolution of subject at or after at (the
// agent's own or the dashboard's); the caller holds panelState.
func resolutionLocked(subject string, at time.Time) (resolution, bool) {
	var best resolution
	found := false
	consider := func(rs []resolution) {
		for _, r := range rs {
			if r.Subject == subject && r.At >= at.Unix() && (!found || r.At < best.At) {
				best, found = r, true
			}
		}
	}
	consider(panelState.p.Resolved)
	if p := syncedResolutions.Load(); p != nil {
		consider(*p)
	}
	return best, found
}

// resolutionFields are the subject, state, resolved_at and resolved_how
// of an item of the events and findings answers: state "open" or
// "resolved" for a problem, null otherwise. The caller holds panelState.
func resolutionFieldsLocked(subject string, problem bool, at string) (subj, state, resolvedAt, how any) {
	if subject == "" {
		return nil, nil, nil, nil
	}
	if !problem {
		return subject, nil, nil, nil
	}
	if t, ok := parseEventTime(at); ok {
		if r, ok := resolutionLocked(subject, t); ok {
			return subject, "resolved", time.Unix(r.At, 0).UTC().Format(time.RFC3339), r.How
		}
	}
	return subject, "open", nil, nil
}

// resolveFindingLocked fills in a finding's subject and state: every
// finding is a problem, resolved from its last sighting on. The caller holds
// panelState.
func resolveFindingLocked(f *panelFinding) {
	prefix := "malware:"
	if f.Kind == "integrity" {
		prefix = "file:"
	}
	f.Subject = cleanText(prefix+f.Path, maxSubject)
	_, state, at, how := resolutionFieldsLocked(f.Subject, true, f.LastSeen)
	f.State, _ = state.(string)
	f.ResolvedAt, f.ResolvedHow = at, how
}

// portClosedByAgent: the agent's firewall rules closing port to the public
// are in force (over IPv6 too), so a database listening on all addresses
// there is not exposed. Saved or requested state is not enough: when the
// rules could not be loaded, the port is reported as exposed.
// A port the agent closed before (saved) but whose rules are not in force
// yet is checked again for up to a minute: the first firewall setup may still
// be running.
func portClosedByAgent(port int) bool {
	for try := 0; ; try++ {
		if firewallHasPort(port) {
			if ipv6Exposed(port) {
				log.Printf("[dbwatcher] port %d is closed over IPv4 only: still reachable over IPv6", port)
				return false
			}
			return true
		}
		appliedMu.Lock()
		saved := fwAppliedPorts[port]
		appliedMu.Unlock()
		if !saved || try >= portInForceTries {
			if saved {
				log.Printf("[dbwatcher] port %d: the agent's rules closing it are not in force", port)
			}
			return false
		}
		time.Sleep(portInForceWait)
	}
}

// Replaced in tests.
var (
	portInForceTries = 30
	portInForceWait  = 2 * time.Second
)
