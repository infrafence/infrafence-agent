package main

import (
	"encoding/json"
	"log"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/malware"
)

// What the panel commands keep (panel.go). Bans lifted and addresses
// allowed from WHM or Plesk are kept in /var/lib/infrafence/panel-state.json
// (0600, replaced atomically, written only once the panel changed
// something), so they hold across restarts and while the dashboard cannot be
// reached:
//
//   - a ban lifted from the panel is lifted on this server only. It is left
//     out of this server's syncs until the dashboard stops sending it (the
//     ban expired, or someone removed it in the dashboard), or for at most
//     30 days (liftMaxAge): after that a ban the dashboard still sends is
//     enforced again. The dashboard keeps the ban, for the organization's
//     other servers too; the panel_unban event only records the local lift
//     (scope "server"). Only the bans present when it was lifted are left
//     out (their ids, completed by the syncs of the first hour); a new
//     detection of the address bans it again;
//   - an address allowed from the panel is added to the dashboard's allow
//     list until it is disallowed from the panel;
//   - the events reporting these changes wait in an outbox until the
//     dashboard accepts them.
//
// The last sync, recent events and recent findings are kept in memory only.

var panelStatePath = "/var/lib/infrafence/panel-state.json"

// panelOn: the panel side runs on this host (panelEnable). Off, every hook
// above returns at once: nothing is copied, kept or filtered.
var panelOn atomic.Bool

// panelEnabledFor: the WHM and Plesk plugins exist for cPanel/WHM and
// Plesk; any other host needs "panel": true in the agent's config.
func panelEnabledFor(panelID string, configFlag bool) bool {
	return panelID == "cpanel" || panelID == "plesk" || configFlag
}

// panelEnable turns the panel side on when panelEnabledFor allows it, and
// loads its saved state. Call before the first sync; startPanelSocket
// follows only when this returned true.
func panelEnable(panelID string, configFlag bool, report func([]api.EventRequest) error) bool {
	if !panelEnabledFor(panelID, configFlag) {
		return false
	}
	panelOn.Store(true)
	loadPanelState()
	panelReportFn = report
	return true
}

const (
	liftMaxAge    = 30 * 24 * time.Hour
	adoptFor      = time.Hour
	maxLifted     = 1000
	maxPanelAllow = 1000
	maxOutbox     = 500
	outboxMaxAge  = 7 * 24 * time.Hour
	maxEvents     = 1000
	maxFindings   = 1000
	maxBanInfo    = 10000
)

type liftedBan struct {
	IP string `json:"ip"`
	// Dashboard ban ids left out of the syncs (0: a network ban).
	IDs []int64 `json:"ids,omitempty"`
	// Adopt: the syncs add the ids they list for IP, until some are found
	// or adoptFor has passed.
	Adopt    bool   `json:"adopt,omitempty"`
	Actor    string `json:"actor"`
	LiftedAt int64  `json:"lifted_at"`
	Until    int64  `json:"until"`
}

type panelAllowEntry struct {
	IP      string `json:"ip"`
	Note    string `json:"note,omitempty"`
	Actor   string `json:"actor"`
	AddedAt int64  `json:"added_at"`
}

type panelPersisted struct {
	Lifted  []liftedBan       `json:"lifted,omitempty"`
	Allowed []panelAllowEntry `json:"allowed,omitempty"`
	Outbox  []outboxItem      `json:"outbox,omitempty"`
	NextSeq int64             `json:"next_seq,omitempty"`
}

// panelSyncView is what the last sync said, for the read commands.
type panelSyncView struct {
	at          time.Time
	bans        []api.Ban // as received, lifted ones included
	whitelists  []api.WhitelistEntry
	monitorMode bool
	suspended   bool
	plan        string
	autoMode    json.RawMessage
	malwareScan *bool // scheduled malware scanning on; nil: not sent
}

type localBan struct {
	reason  string
	created time.Time
}

type panelEvent struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	SourceIP string `json:"source_ip,omitempty"`
	Time     string `json:"time"`
	Source   string `json:"source,omitempty"`
}

type panelFinding struct {
	Path     string `json:"path"`
	Kind     string `json:"kind"` // malware, integrity
	Name     any    `json:"name"`
	Severity string `json:"severity"`
	Status   string `json:"status"` // detected, quarantined
	Detected string `json:"detected"`
	LastSeen string `json:"last_seen"`
	key      string
}

var panelState = struct {
	sync.Mutex
	p        panelPersisted
	view     panelSyncView
	banInfo  map[string]localBan
	events   []panelEvent
	findings []panelFinding
}{banInfo: map[string]localBan{}}

// Replaced in tests.
var panelNow = time.Now

// loadPanelState reads the saved state, if the panel ever changed anything.
func loadPanelState() {
	panelState.Lock()
	defer panelState.Unlock()
	data, err := os.ReadFile(panelStatePath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[panel] state: %v", err)
		}
		return
	}
	var p panelPersisted
	if err := json.Unmarshal(data, &p); err != nil {
		log.Printf("[panel] state: %v (ignored)", err)
		return
	}
	panelState.p = p
}

// savePanelStateLocked writes the state; the caller holds the lock.
func savePanelStateLocked() error {
	err := writeFileAtomic(panelStatePath, panelState.p)
	if err != nil {
		log.Printf("[panel] save state: %v", err)
	}
	return err
}

// panelFilterBans records the sync and returns its bans without the ones
// lifted from the panel, dropping lifts the dashboard has caught up with.
func panelFilterBans(bans []api.Ban) []api.Ban {
	if !panelOn.Load() {
		return bans
	}
	panelState.Lock()
	defer panelState.Unlock()
	if len(panelState.p.Lifted) == 0 {
		return bans
	}
	now := panelNow().Unix()
	present := map[string][]int64{}
	for _, b := range bans {
		present[b.IPAddress] = append(present[b.IPAddress], b.ID)
	}
	changed := false
	kept := panelState.p.Lifted[:0]
	for _, l := range panelState.p.Lifted {
		if now > l.Until {
			changed = true
			continue
		}
		ids := present[l.IP]
		if l.Adopt {
			// The dashboard may record a fresh local ban only a little
			// later: its ids are adopted for up to adoptFor after the lift.
			for _, id := range ids {
				if !slices.Contains(l.IDs, id) {
					l.IDs = append(l.IDs, id)
					changed = true
				}
			}
			if len(l.IDs) > 0 || now > l.LiftedAt+int64(adoptFor/time.Second) {
				l.Adopt = false
				changed = true
			}
			if l.Adopt || len(l.IDs) > 0 {
				kept = append(kept, l)
			}
			continue
		} else if !slices.Contains(l.IDs, 0) && !slices.ContainsFunc(l.IDs, func(id int64) bool { return slices.Contains(ids, id) }) {
			// The dashboard no longer sends any of them.
			changed = true
			continue
		}
		kept = append(kept, l)
	}
	panelState.p.Lifted = kept
	if changed {
		savePanelStateLocked()
	}
	if len(kept) == 0 {
		return bans
	}
	lifted := map[string][]int64{}
	for _, l := range kept {
		lifted[l.IP] = l.IDs
	}
	out := make([]api.Ban, 0, len(bans))
	for _, b := range bans {
		if slices.Contains(lifted[b.IPAddress], b.ID) {
			continue
		}
		out = append(out, b)
	}
	return out
}

// panelNoteSync keeps what the read commands need from a sync.
func panelNoteSync(s *api.SyncResponse) {
	if !panelOn.Load() {
		return
	}
	v := panelSyncView{
		at:          panelNow(),
		bans:        append([]api.Ban(nil), s.Bans...),
		whitelists:  append([]api.WhitelistEntry(nil), s.Whitelists...),
		monitorMode: s.Config.MonitorMode,
		suspended:   s.Config.Suspended,
		plan:        s.Config.Plan,
		autoMode:    s.Config.AutoMode,
	}
	if s.Config.MalwareScanConfig != nil {
		on := s.Config.MalwareScanConfig.Enabled
		v.malwareScan = &on
	}
	panelState.Lock()
	panelState.view = v
	// Details of the agent's own bans, for addresses it still bans.
	for ip := range panelState.banInfo {
		if !panelIsBanned(ip) {
			delete(panelState.banInfo, ip)
		}
	}
	panelState.Unlock()
}

// panelAllowedIPs returns the addresses allowed from the panel.
func panelAllowedIPs() []string {
	if !panelOn.Load() {
		return nil
	}
	panelState.Lock()
	defer panelState.Unlock()
	out := make([]string, 0, len(panelState.p.Allowed))
	for _, a := range panelState.p.Allowed {
		out = append(out, a.IP)
	}
	return out
}

func panelAllowed(ip string) bool {
	if !panelOn.Load() {
		return false
	}
	panelState.Lock()
	defer panelState.Unlock()
	return slices.ContainsFunc(panelState.p.Allowed, func(a panelAllowEntry) bool { return a.IP == ip })
}

// panelNoteLocalBan remembers why the agent banned ip itself, and forgets a
// panel lift of it: the address was detected again after the lift.
func panelNoteLocalBan(ip, reason string) {
	if !panelOn.Load() {
		return
	}
	panelState.Lock()
	defer panelState.Unlock()
	if len(panelState.banInfo) < maxBanInfo {
		panelState.banInfo[ip] = localBan{reason: reason, created: panelNow()}
	}
	for i, l := range panelState.p.Lifted {
		if l.IP == ip {
			panelState.p.Lifted = slices.Delete(panelState.p.Lifted, i, i+1)
			savePanelStateLocked()
			break
		}
	}
}

// panelNoteEvent keeps recent events, and the findings among them, for the
// events and findings commands. Progress events are left out.
func panelNoteEvent(e api.EventRequest) {
	if !panelOn.Load() {
		return
	}
	if strings.HasSuffix(e.Type, "_progress") {
		return
	}
	at := e.OccurredAt
	if at == "" {
		at = panelNow().UTC().Format(time.RFC3339)
	}
	panelState.Lock()
	defer panelState.Unlock()
	panelState.events = append(panelState.events, panelEvent{
		Type: cleanText(e.Type, 64), Severity: cleanText(e.Severity, 16), SourceIP: cleanText(e.SourceIP, 45),
		Time: cleanText(at, 40), Source: cleanText(e.Details["source"], 64),
	})
	if n := len(panelState.events) - maxEvents; n > 0 {
		panelState.events = slices.Delete(panelState.events, 0, n)
	}
	switch e.Type {
	case "malware_realtime":
		noteFindingLocked(e.Details["file_path"], "malware", e.Details["name"], e.Severity, at)
	case "integrity_change":
		noteFindingLocked(e.Details["file"], "integrity", "", e.Severity, at)
	case "quarantine_completed":
		for i := range panelState.findings {
			if panelState.findings[i].Path == e.Details["file"] {
				panelState.findings[i].Status = "quarantined"
			}
		}
	}
}

// panelNoteScanFindings adds the findings of a malware scan.
func panelNoteScanFindings(fs []malware.Finding) {
	if !panelOn.Load() {
		return
	}
	at := panelNow().UTC().Format(time.RFC3339)
	panelState.Lock()
	defer panelState.Unlock()
	for _, f := range fs {
		if f.SignatureID == "ROOTKIT_EXEC_IN_TMP" {
			continue
		}
		noteFindingLocked(f.FilePath, "malware", f.Name, f.Severity, at)
	}
}

func noteFindingLocked(path, kind, name, severity, at string) {
	path, name, severity, at = cleanText(path, 1024), cleanText(name, 200), cleanText(severity, 16), cleanText(at, 40)
	if path == "" {
		return
	}
	key := kind + "\x00" + path + "\x00" + name
	for i := range panelState.findings {
		if panelState.findings[i].key == key {
			panelState.findings[i].LastSeen = at
			panelState.findings[i].Severity = severity
			if panelState.findings[i].Status == "quarantined" {
				panelState.findings[i].Status = "detected"
			}
			return
		}
	}
	panelState.findings = append(panelState.findings, panelFinding{
		Path: path, Kind: kind, Name: orNull(name), Severity: severity, Status: "detected", Detected: at, LastSeen: at, key: key,
	})
	if n := len(panelState.findings) - maxFindings; n > 0 {
		panelState.findings = slices.Delete(panelState.findings, 0, n)
	}
}

// panelReportFn sends events to the dashboard; set at startup, replaced in
// tests.
var panelReportFn func([]api.EventRequest) error

// outboxMu serializes every send of a panel event, direct or from the
// outbox, so the dashboard receives them in the order they happened (an
// allow still waiting must not arrive after the disallow that followed it).
var outboxMu sync.Mutex

type outboxItem struct {
	Seq   int64            `json:"seq"`
	Event api.EventRequest `json:"event"`
}

// panelReport sends the events now, or keeps them in the outbox for the
// next sync. Returns whether the dashboard accepted them.
func panelReport(events []api.EventRequest) bool {
	outboxMu.Lock()
	defer outboxMu.Unlock()
	if panelOutboxLen() == 0 && panelReportFn != nil && panelReportFn(events) == nil {
		return true
	}
	panelState.Lock()
	var last int64
	for _, e := range events {
		panelState.p.NextSeq++
		last = panelState.p.NextSeq
		panelState.p.Outbox = append(panelState.p.Outbox, outboxItem{Seq: last, Event: e})
	}
	if n := len(panelState.p.Outbox) - maxOutbox; n > 0 {
		panelState.p.Outbox = slices.Delete(panelState.p.Outbox, 0, n)
	}
	savePanelStateLocked()
	panelState.Unlock()
	// Earlier events were waiting: they go first.
	flushOutboxLocked()
	panelState.Lock()
	defer panelState.Unlock()
	return !slices.ContainsFunc(panelState.p.Outbox, func(it outboxItem) bool { return it.Seq == last })
}

// panelFlushOutbox resends the events waiting in the outbox (after a sync:
// the dashboard is reachable again). Skipped while a panel command is
// sending: it flushes the outbox itself.
func panelFlushOutbox() {
	if !panelOn.Load() {
		return
	}
	if !outboxMu.TryLock() {
		return
	}
	defer outboxMu.Unlock()
	flushOutboxLocked()
}

// flushOutboxLocked sends the outbox in order; the caller holds outboxMu.
// Events older than a week are dropped.
func flushOutboxLocked() {
	if panelReportFn == nil {
		return
	}
	panelState.Lock()
	pending := append([]outboxItem(nil), panelState.p.Outbox...)
	panelState.Unlock()
	if len(pending) == 0 {
		return
	}
	cutoff := panelNow().Add(-outboxMaxAge)
	var send []api.EventRequest
	for _, it := range pending {
		if t, err := time.Parse(time.RFC3339, it.Event.OccurredAt); err == nil && t.Before(cutoff) {
			continue
		}
		send = append(send, it.Event)
	}
	if len(send) > 0 {
		if err := panelReportFn(send); err != nil {
			log.Printf("[panel] outbox: %d event(s) still waiting: %v", len(send), err)
			return
		}
		log.Printf("[panel] outbox: %d event(s) delivered", len(send))
	}
	sent := pending[len(pending)-1].Seq
	panelState.Lock()
	panelState.p.Outbox = slices.DeleteFunc(panelState.p.Outbox, func(it outboxItem) bool { return it.Seq <= sent })
	savePanelStateLocked()
	panelState.Unlock()
}

func panelOutboxLen() int {
	if !panelOn.Load() {
		return 0
	}
	panelState.Lock()
	defer panelState.Unlock()
	return len(panelState.p.Outbox)
}

// cleanText makes text that comes from logs, file names or rule names safe
// to hand to the panel: control characters replaced, length capped. The
// plugins still HTML-escape everything they show.
func cleanText(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == utf8.RuneError {
			return '?'
		}
		return r
	}, s)
	if len(s) > max {
		s = s[:max]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}
