package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/malware"
	"github.com/infrafence/infrafence-agent/internal/panel"
	"github.com/infrafence/infrafence-agent/internal/preflight"
)

// fakePanelHost replaces the firewall, the dashboard and the host.
type fakePanelHost struct {
	now       time.Time
	banned    map[string]bool
	unbanned  []string
	allowSets [][]string
	syncs     []string
	reported  []api.EventRequest
	reportErr error
	sites     []preflight.Site
	roots     []malware.WebRoot
	scanning  bool
	mu        sync.Mutex // scans start in the background
	scanned   []malware.WebRoot
}

func (f *fakePanelHost) scans() []malware.WebRoot {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]malware.WebRoot(nil), f.scanned...)
}

func withFakePanel(t *testing.T) *fakePanelHost {
	t.Helper()
	f := &fakePanelHost{now: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC), banned: map[string]bool{}}
	saved := []any{panelStatePath, panelNow, panelIsBanned, panelUnbanIP, panelSetAllowList, panelIsAllowListed,
		panelInThreatSet, panelRequestSync, panelReportFn, panelDetectSites, panelCoexistence, panelDetectRoots,
		panelClaimScan, panelStartScan, panelEuid, panelDetectPanelID, panelSocketPath, panelInfo, panelSystemDirs}
	panelStatePath = filepath.Join(t.TempDir(), "panel-state.json")
	panelNow = func() time.Time { return f.now }
	panelIsBanned = func(ip string) bool { return f.banned[ip] }
	panelUnbanIP = func(ip string) error { f.unbanned = append(f.unbanned, ip); delete(f.banned, ip); return nil }
	panelSetAllowList = func(e []string) { f.allowSets = append(f.allowSets, append([]string(nil), e...)) }
	panelIsAllowListed = func(string) bool { return false }
	panelInThreatSet = func(string) bool { return false }
	panelRequestSync = func(r string) { f.syncs = append(f.syncs, r) }
	panelReportFn = func(ev []api.EventRequest) error {
		if f.reportErr != nil {
			return f.reportErr
		}
		f.reported = append(f.reported, ev...)
		return nil
	}
	panelDetectSites = func(string) []preflight.Site { return f.sites }
	panelCoexistence = func() preflight.Coexistence {
		return preflight.Coexistence{Mode: preflight.ModeCoexist, Tools: []preflight.Tool{{ID: "csf", Name: "CSF", Active: true, Firewall: true}}}
	}
	panelDetectRoots = func() []malware.WebRoot { return f.roots }
	panelClaimScan = func() bool { return !f.scanning }
	// Test directories live under /tmp on Linux.
	panelSystemDirs = []string{"/etc", "/proc"}
	panelStartScan = func(r malware.WebRoot) { f.mu.Lock(); f.scanned = append(f.scanned, r); f.mu.Unlock() }
	panelEuid = func() int { return 0 }
	panelDetectPanelID = func() string { return "cpanel" }
	// Short: socket paths are limited to about 100 bytes.
	sockDir, err := os.MkdirTemp("/tmp", "ifp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	panelSocketPath = filepath.Join(sockDir, "missing.sock")
	panelInfo.agentID, panelInfo.serverURL, panelInfo.panelID = 42, "https://app.infrafence.com", "cpanel"
	resetPanelState()
	webRootsCache.roots = nil
	sitesCache.sites = nil
	panelOn.Store(true)
	t.Cleanup(func() {
		panelOn.Store(false)
		panelStatePath = saved[0].(string)
		panelNow = saved[1].(func() time.Time)
		panelIsBanned = saved[2].(func(string) bool)
		panelUnbanIP = saved[3].(func(string) error)
		panelSetAllowList = saved[4].(func([]string))
		panelIsAllowListed = saved[5].(func(string) bool)
		panelInThreatSet = saved[6].(func(string) bool)
		panelRequestSync = saved[7].(func(string))
		panelReportFn = saved[8].(func([]api.EventRequest) error)
		panelDetectSites = saved[9].(func(string) []preflight.Site)
		panelCoexistence = saved[10].(func() preflight.Coexistence)
		panelDetectRoots = saved[11].(func() []malware.WebRoot)
		panelClaimScan = saved[12].(func() bool)
		panelStartScan = saved[13].(func(malware.WebRoot))
		panelEuid = saved[14].(func() int)
		panelDetectPanelID = saved[15].(func() string)
		panelSocketPath = saved[16].(string)
		panelSystemDirs = saved[18].([]string)
		panelInfo = saved[17].(struct {
			agentID   int64
			serverURL string
			panelID   string
		})
		resetPanelState()
		webRootsCache.roots = nil
		panelLastHeartbeat.Store(0)
	})
	return f
}

func resetPanelState() {
	panelState.Lock()
	panelState.p = panelPersisted{}
	panelState.view = panelSyncView{}
	panelState.banInfo = map[string]localBan{}
	panelState.events = nil
	panelState.findings = nil
	panelState.Unlock()
}

func strp(s string) *string { return &s }

// syncWith runs what syncAndApply does with the panel state and returns the
// bans that would be applied.
func syncWith(bans []api.Ban, wl ...api.WhitelistEntry) []string {
	s := &api.SyncResponse{Bans: bans, Whitelists: wl}
	panelNoteSync(s)
	var ips []string
	for _, b := range panelFilterBans(s.Bans) {
		ips = append(ips, b.IPAddress)
	}
	return ips
}

func (f *fakePanelHost) in(d time.Duration) *string {
	return strp(f.now.Add(d).Format(time.RFC3339))
}

func TestDashboardURL(t *testing.T) {
	for _, c := range []struct {
		url  string
		id   int64
		want string
	}{
		{"https://app.infrafence.com", 9, "https://app.infrafence.com/servers/9"},
		{"https://app.infrafence.com/", 9, "https://app.infrafence.com/servers/9"},
		{"http://127.0.0.1:8080", 1, "http://127.0.0.1:8080/servers/1"},
		{"javascript:alert(1)", 9, ""},
		{"https://user:pw@app.infrafence.com", 9, ""},
		{"https://app.infrafence.com", 0, ""},
	} {
		if got := dashboardURL(c.url, c.id); got != c.want {
			t.Errorf("dashboardURL(%q, %d) = %q, want %q", c.url, c.id, got, c.want)
		}
	}
}

func TestPanelStatus(t *testing.T) {
	f := withFakePanel(t)
	panelNoteSync(&api.SyncResponse{Config: api.SyncConfig{Plan: "pro", AutoMode: json.RawMessage(`{"enabled":true}`)}})
	panelLastHeartbeat.Store(f.now.Add(-time.Minute).Unix())
	r := handlePanel(panel.Request{Command: "status"})
	if !r.Succeeded() || r["agent_id"] != int64(42) || r["plan"] != "pro" || r["connected"] != true ||
		r["dashboard_url"] != "https://app.infrafence.com/servers/42" || r["version"] != version {
		t.Errorf("status: %v", r)
	}
	if string(r["automode"].(json.RawMessage)) != `{"enabled":true}` {
		t.Errorf("automode: %v", r["automode"])
	}
	panelLastHeartbeat.Store(f.now.Add(-10 * time.Minute).Unix())
	if r := handlePanel(panel.Request{Command: "status"}); r["connected"] != false || r["plan"] != "pro" {
		t.Errorf("stale heartbeat: %v", r)
	}
	// An older dashboard sends neither plan nor AutoMode.
	panelNoteSync(&api.SyncResponse{})
	if r := handlePanel(panel.Request{Command: "status"}); r["plan"] != nil || r["automode"] != nil {
		t.Errorf("missing plan/automode: %v", r)
	}
}

func TestPanelUnbanIsKeptUntilTheDashboardDropsIt(t *testing.T) {
	f := withFakePanel(t)
	bans := []api.Ban{
		{ID: 1, IPAddress: "203.0.113.7", ExpiresAt: f.in(24 * time.Hour)},
		{ID: 2, IPAddress: "198.51.100.9"},
	}
	syncWith(bans)
	f.banned["203.0.113.7"], f.banned["198.51.100.9"] = true, true

	r := handlePanel(panel.Request{Command: "unban", IP: "203.0.113.7", Actor: "root"})
	if !r.Succeeded() || r["reported"] != true {
		t.Fatalf("unban: %v", r)
	}
	if !reflect.DeepEqual(f.unbanned, []string{"203.0.113.7"}) || len(f.syncs) != 1 {
		t.Errorf("firewall %v, syncs %v", f.unbanned, f.syncs)
	}
	if len(f.reported) != 1 {
		t.Fatalf("reported %+v", f.reported)
	}
	ev := f.reported[0]
	if ev.Type != "panel_unban" || ev.SourceIP != "" || ev.Details["source"] != "panel" || ev.Details["actor"] != "root" ||
		ev.Details["ip"] != "203.0.113.7" || ev.Details["panel"] != "cpanel" ||
		ev.Details["scope"] != "server" || ev.Details["ban_source"] != "manual" || ev.Details["lifted_until"] != "2026-10-17T12:00:00Z" {
		t.Errorf("event: %+v", ev)
	}
	// A record of a local lift, never a list of bans to delete.
	if _, ok := ev.Details["ban_ids"]; ok {
		t.Errorf("event carries ban ids: %+v", ev)
	}
	if r["scope"] != "server" || r["source"] != "manual" || r["lifted_until"] != "2026-10-17T12:00:00Z" {
		t.Errorf("reply: %v", r)
	}
	st, err := os.Stat(panelStatePath)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("state file: %v %v", st, err)
	}

	// The dashboard still sends the ban: not applied again.
	if got := syncWith(bans); !reflect.DeepEqual(got, []string{"198.51.100.9"}) {
		t.Errorf("lifted ban reapplied: %v", got)
	}
	if got := syncWith(bans); !reflect.DeepEqual(got, []string{"198.51.100.9"}) {
		t.Errorf("second sync: %v", got)
	}
	if r := handlePanel(panel.Request{Command: "unban", IP: "203.0.113.7", Actor: "root"}); r["error"] != panel.ErrNotBanned {
		t.Errorf("second unban: %v", r)
	}
	// The dashboard no longer sends it (expired or removed there): the lift
	// is forgotten, and a new ban (new id) is applied.
	syncWith(bans[1:])
	if n := len(panelState.p.Lifted); n != 0 {
		t.Errorf("%d lifts left", n)
	}
	if got := syncWith(append(bans[1:], api.Ban{ID: 3, IPAddress: "203.0.113.7"})); len(got) != 2 {
		t.Errorf("new ban not applied: %v", got)
	}
}

func TestPanelUnbanOfAFreshLocalBan(t *testing.T) {
	f := withFakePanel(t)
	syncWith(nil)
	// Banned by the agent, reported, not in a sync yet.
	f.banned["203.0.113.8"] = true
	panelNoteLocalBan("203.0.113.8", "ssh brute force")
	if r := handlePanel(panel.Request{Command: "unban", IP: "203.0.113.8", Actor: "root"}); !r.Succeeded() {
		t.Fatalf("unban: %v", r)
	}
	// The first sync after the lift brings the dashboard's id for it.
	bans := []api.Ban{{ID: 7, IPAddress: "203.0.113.8"}}
	if got := syncWith(bans); len(got) != 0 {
		t.Errorf("adopted ban applied: %v", got)
	}
	if got := syncWith(bans); len(got) != 0 {
		t.Errorf("later sync: %v", got)
	}
	syncWith(nil)
	if len(panelState.p.Lifted) != 0 {
		t.Errorf("lift kept after the dashboard dropped the ban: %+v", panelState.p.Lifted)
	}
}

func TestPanelUnbanNetworkBanUntilItExpires(t *testing.T) {
	f := withFakePanel(t)
	bans := []api.Ban{{ID: 0, IPAddress: "192.0.2.50", ExpiresAt: f.in(48 * time.Hour)}}
	syncWith(bans)
	if r := handlePanel(panel.Request{Command: "unban", IP: "192.0.2.50", Actor: "admin"}); !r.Succeeded() || r["source"] != "network" || r["scope"] != "server" {
		t.Fatalf("unban: %v", r)
	}
	if ev := f.reported[len(f.reported)-1]; ev.Details["ban_source"] != "network" || ev.Details["scope"] != "server" {
		t.Errorf("event: %+v", ev)
	}
	syncWith(nil) // a network ban can leave the list and come back
	if got := syncWith(bans); len(got) != 0 {
		t.Errorf("network ban reapplied: %v", got)
	}
	f.now = f.now.Add(49 * time.Hour)
	if got := syncWith(bans); len(got) != 1 {
		t.Errorf("after expiry: %v", got)
	}
}

func TestPanelLiftSurvivesRestartAndNewDetection(t *testing.T) {
	f := withFakePanel(t)
	bans := []api.Ban{{ID: 5, IPAddress: "203.0.113.9"}}
	syncWith(bans)
	handlePanel(panel.Request{Command: "unban", IP: "203.0.113.9", Actor: "root"})

	resetPanelState()
	loadPanelState()
	if got := syncWith(bans); len(got) != 0 {
		t.Errorf("lift lost on restart: %v", got)
	}
	// Detected again: banned again by the agent, the lift no longer applies.
	f.banned["203.0.113.9"] = true
	panelNoteLocalBan("203.0.113.9", "ssh brute force")
	if got := syncWith(bans); len(got) != 1 {
		t.Errorf("new detection not enforced: %v", got)
	}
}

func TestPanelUnbanNotBanned(t *testing.T) {
	withFakePanel(t)
	syncWith(nil)
	r := handlePanel(panel.Request{Command: "unban", IP: "203.0.113.10", Actor: "root"})
	if r["error"] != panel.ErrNotBanned {
		t.Errorf("got %v", r)
	}
	if _, err := os.Stat(panelStatePath); !os.IsNotExist(err) {
		t.Error("state file written although nothing changed")
	}
}

func TestPanelNothingChangesWithoutPanelUse(t *testing.T) {
	f := withFakePanel(t)
	bans := []api.Ban{{ID: 1, IPAddress: "203.0.113.7"}, {ID: 0, IPAddress: "192.0.2.50", ExpiresAt: f.in(time.Hour)}}
	if got := syncWith(bans); len(got) != 2 {
		t.Errorf("bans filtered without any lift: %v", got)
	}
	if ips := panelAllowedIPs(); len(ips) != 0 {
		t.Errorf("allowed: %v", ips)
	}
	panelNoteEvent(api.EventRequest{Type: "ssh_brute_force", Severity: "warning"})
	panelFlushOutbox()
	if _, err := os.Stat(panelStatePath); !os.IsNotExist(err) {
		t.Error("state file created without a panel change")
	}
}

func TestPanelAllowAndDisallow(t *testing.T) {
	f := withFakePanel(t)
	// Before the first sync the dashboard's list is unknown: nothing is
	// pushed to the firewall (it would drop the dashboard's entries), the
	// sync applies it.
	if r := handlePanel(panel.Request{Command: "allow", IP: "198.51.100.4", Note: "office", Actor: "root"}); !r.Succeeded() {
		t.Fatalf("allow: %v", r)
	}
	if len(f.allowSets) != 0 || len(f.syncs) != 1 {
		t.Errorf("before sync: sets %v syncs %v", f.allowSets, f.syncs)
	}
	if !reflect.DeepEqual(panelAllowedIPs(), []string{"198.51.100.4"}) || !panelAllowed("198.51.100.4") {
		t.Errorf("allowed: %v", panelAllowedIPs())
	}
	if ev := f.reported[0]; ev.Type != "panel_allow" || ev.Details["note"] != "office" || ev.Details["actor"] != "root" {
		t.Errorf("event: %+v", ev)
	}

	syncWith(nil, api.WhitelistEntry{ID: 1, IPAddress: strp("203.0.113.20")}, api.WhitelistEntry{ID: 2, IPRange: strp("10.0.0.0/8")})
	if r := handlePanel(panel.Request{Command: "allow", IP: "2001:db8::4", Actor: "root"}); !r.Succeeded() {
		t.Fatalf("allow v6: %v", r)
	}
	want := []string{"203.0.113.20", "10.0.0.0/8", "198.51.100.4", "2001:db8::4"}
	if len(f.allowSets) != 1 || !reflect.DeepEqual(f.allowSets[0], want) {
		t.Errorf("allow list applied: %v", f.allowSets)
	}
	if r := handlePanel(panel.Request{Command: "allow", IP: "198.51.100.4", Actor: "root"}); r["already"] != true {
		t.Errorf("allow twice: %v", r)
	}

	list := handlePanel(panel.Request{Command: "allowlist"})["allowlist"].([]panelAllowItem)
	if len(list) != 4 || list[0].Source != "panel" || list[0].Note != "office" || list[3].Source != "dashboard" || list[3].Address != "10.0.0.0/8" {
		t.Errorf("allowlist: %+v", list)
	}

	if r := handlePanel(panel.Request{Command: "disallow", IP: "203.0.113.20", Actor: "root"}); r["error"] != panel.ErrManaged {
		t.Errorf("dashboard entry: %v", r)
	}
	if r := handlePanel(panel.Request{Command: "disallow", IP: "203.0.113.99", Actor: "root"}); r["error"] != panel.ErrNotAllowed {
		t.Errorf("unknown entry: %v", r)
	}
	if r := handlePanel(panel.Request{Command: "disallow", IP: "198.51.100.4", Actor: "admin"}); !r.Succeeded() {
		t.Errorf("disallow: %v", r)
	}
	if last := f.allowSets[len(f.allowSets)-1]; slices.Contains(last, "198.51.100.4") {
		t.Errorf("still enforced: %v", last)
	}
	if ev := f.reported[len(f.reported)-1]; ev.Type != "panel_disallow" || ev.Details["actor"] != "admin" {
		t.Errorf("event: %+v", ev)
	}
}

func TestPanelOutbox(t *testing.T) {
	f := withFakePanel(t)
	syncWith([]api.Ban{{ID: 1, IPAddress: "203.0.113.7"}})
	f.reportErr = errors.New("server returned 503")
	r := handlePanel(panel.Request{Command: "unban", IP: "203.0.113.7", Actor: "root"})
	if !r.Succeeded() || r["reported"] != false || panelOutboxLen() != 1 {
		t.Fatalf("unban offline: %v, outbox %d", r, panelOutboxLen())
	}
	// Kept across a restart.
	resetPanelState()
	loadPanelState()
	if panelOutboxLen() != 1 {
		t.Fatal("outbox lost")
	}
	panelFlushOutbox()
	if panelOutboxLen() != 1 {
		t.Error("outbox cleared while the dashboard is down")
	}
	f.reportErr = nil
	panelFlushOutbox()
	if panelOutboxLen() != 0 || len(f.reported) != 1 || f.reported[0].Type != "panel_unban" {
		t.Errorf("flush: outbox %d, reported %+v", panelOutboxLen(), f.reported)
	}

	// Events older than a week are dropped instead of sent.
	f.reportErr = errors.New("down")
	panelReport([]api.EventRequest{panelEventFor("panel_allow", "root", nil)})
	f.reportErr = nil
	f.now = f.now.Add(8 * 24 * time.Hour)
	panelFlushOutbox()
	if panelOutboxLen() != 0 || len(f.reported) != 1 {
		t.Errorf("stale event: outbox %d, reported %d", panelOutboxLen(), len(f.reported))
	}
}

func TestPanelBans(t *testing.T) {
	f := withFakePanel(t)
	f.banned["203.0.113.30"] = true
	panelNoteLocalBan("203.0.113.30", "web attack")
	f.now = f.now.Add(time.Minute)
	f.banned["203.0.113.31"] = true
	panelNoteLocalBan("203.0.113.31", "ssh brute force") // not synced yet
	syncWith([]api.Ban{
		{ID: 1, IPAddress: "203.0.113.30", ExpiresAt: f.in(time.Hour)},
		{ID: 2, IPAddress: "198.51.100.40"},
		{ID: 0, IPAddress: "192.0.2.60", ExpiresAt: f.in(time.Hour)},
		{ID: 3, IPAddress: "198.51.100.41", Source: "automode", Reason: "under attack", CreatedAt: "2026-10-16T12:00:30Z"},
		{ID: 4, IPAddress: "198.51.100.42", ExpiresAt: f.in(-time.Hour)},
	})
	f.banned["198.51.100.40"] = true
	handlePanel(panel.Request{Command: "unban", IP: "198.51.100.40", Actor: "root"})

	r := handlePanel(panel.Request{Command: "bans", Limit: 50})
	bans := r["bans"].([]panelBan)
	got := map[string]panelBan{}
	for _, b := range bans {
		got[b.IP] = b
	}
	if len(bans) != 4 || r["total"] != 4 {
		t.Fatalf("bans: %+v", bans)
	}
	if b := got["203.0.113.30"]; b.Source != "local" || b.Reason != "web attack" || b.Created == nil || b.Expires == nil {
		t.Errorf("local: %+v", b)
	}
	if b := got["203.0.113.31"]; b.Source != "local" || b.Reason != "ssh brute force" {
		t.Errorf("unsynced local: %+v", b)
	}
	if b := got["192.0.2.60"]; b.Source != "network" {
		t.Errorf("network: %+v", b)
	}
	if b := got["198.51.100.41"]; b.Source != "automode" || b.Reason != "under attack" || b.Expires != nil {
		t.Errorf("dashboard-described: %+v", b)
	}
	if _, ok := got["198.51.100.40"]; ok {
		t.Error("lifted ban listed")
	}
	if bans[0].IP != "203.0.113.31" {
		t.Errorf("not newest first: %+v", bans)
	}
	if r := handlePanel(panel.Request{Command: "bans", Limit: 1}); len(r["bans"].([]panelBan)) != 1 || r["total"] != 4 {
		t.Errorf("limit: %v", r)
	}
}

func TestPanelEventsAndFindings(t *testing.T) {
	f := withFakePanel(t)
	at := func(d time.Duration) string { return f.now.Add(d).Format(time.RFC3339) }
	panelNoteEvent(api.EventRequest{Type: "ssh_brute_force", Severity: "warning", SourceIP: "203.0.113.7", OccurredAt: at(-3 * time.Hour)})
	panelNoteEvent(api.EventRequest{Type: "malware_scan_progress", Severity: "info", OccurredAt: at(-2 * time.Hour)})
	panelNoteEvent(api.EventRequest{Type: "malware_realtime", Severity: "critical", OccurredAt: at(-2 * time.Hour),
		Details: map[string]string{"file_path": "/home/alice/public_html/x.php", "name": "PHP webshell"}})
	panelNoteEvent(api.EventRequest{Type: "integrity_change", Severity: "warning", OccurredAt: at(-time.Hour),
		Details: map[string]string{"file": "/etc/passwd"}})
	panelNoteEvent(api.EventRequest{Type: "quarantine_completed", Severity: "info", OccurredAt: at(-30 * time.Minute),
		Details: map[string]string{"file": "/home/alice/public_html/x.php"}})

	ev := handlePanel(panel.Request{Command: "events", Limit: 50})["events"].([]panelEventOut)
	if len(ev) != 4 || ev[0].Type != "quarantine_completed" || ev[3].SourceIP != "203.0.113.7" {
		t.Errorf("events: %+v", ev)
	}
	since := f.now.Add(-90 * time.Minute).Format(time.RFC3339)
	if ev := handlePanel(panel.Request{Command: "events", Limit: 50, Since: since})["events"].([]panelEventOut); len(ev) != 2 {
		t.Errorf("since: %+v", ev)
	}
	if ev := handlePanel(panel.Request{Command: "events", Limit: 1})["events"].([]panelEventOut); len(ev) != 1 {
		t.Errorf("limit: %+v", ev)
	}

	f.now = f.now.Add(time.Minute)
	panelNoteScanFindings([]malware.Finding{
		{FilePath: "/home/bob/public_html/y.php", Name: "Obfuscated eval", Severity: "high"},
		{FilePath: "/tmp/.x", SignatureID: "ROOTKIT_EXEC_IN_TMP", Severity: "critical"},
	})
	fs := handlePanel(panel.Request{Command: "findings", Limit: 50})["findings"].([]panelFinding)
	byPath := map[string]panelFinding{}
	for _, f := range fs {
		byPath[f.Path] = f
	}
	if len(fs) != 3 || fs[0].Path != "/home/bob/public_html/y.php" {
		t.Fatalf("findings: %+v", fs)
	}
	if x := byPath["/home/alice/public_html/x.php"]; x.Status != "quarantined" || x.Kind != "malware" || x.Severity != "critical" {
		t.Errorf("quarantined finding: %+v", x)
	}
	if p := byPath["/etc/passwd"]; p.Kind != "integrity" || p.Status != "detected" {
		t.Errorf("integrity finding: %+v", p)
	}
	// Seen again by the next scan: one entry, first detection kept.
	f.now = f.now.Add(time.Hour)
	panelNoteScanFindings([]malware.Finding{{FilePath: "/home/bob/public_html/y.php", Name: "Obfuscated eval", Severity: "high"}})
	fs = handlePanel(panel.Request{Command: "findings", Limit: 50})["findings"].([]panelFinding)
	if len(fs) != 3 || fs[0].Detected == fs[0].LastSeen {
		t.Errorf("repeat finding: %+v", fs)
	}
}

func TestPanelSitesAndScan(t *testing.T) {
	f := withFakePanel(t)
	base := t.TempDir()
	alice := filepath.Join(base, "home/alice/public_html")
	bob := filepath.Join(base, "home/bob/site")
	other := filepath.Join(base, "srv/other")
	for _, d := range []string{alice, bob, other} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(base, "alice-link")
	if err := os.Symlink(alice, link); err != nil {
		t.Fatal(err)
	}
	f.sites = []preflight.Site{
		{Account: "alice", Domain: "alice.com", Kind: "main", DocumentRoot: alice},
		{Account: "bob", Domain: "bob.org", Kind: "main", DocumentRoot: bob},
		{Account: "carol", Domain: "carol.io", Kind: "main"},
	}
	f.roots = []malware.WebRoot{{Path: filepath.Join(base, "home/alice")}, {Path: other}}
	on := true
	panelState.view.malwareScan = &on

	r := handlePanel(panel.Request{Command: "sites"})
	sites := r["sites"].([]panelSite)
	if len(sites) != 3 || !sites[0].Covered || sites[1].Covered || sites[2].Covered || r["malware_scan_enabled"] != true || r["control_panel"] != "cpanel" {
		t.Errorf("sites: %v", r)
	}

	if r := handlePanel(panel.Request{Command: "scan", Path: filepath.Join(base, "home"), Actor: "root"}); r["error"] != panel.ErrUnknownPath {
		t.Errorf("not a document root: %v", r)
	}
	if r := handlePanel(panel.Request{Command: "scan", Path: filepath.Join(base, "nope"), Actor: "root"}); r["error"] != panel.ErrUnknownPath {
		t.Errorf("missing path: %v", r)
	}
	r = handlePanel(panel.Request{Command: "scan", Path: link, Actor: "root"})
	if !r.Succeeded() || r["queued"] != true {
		t.Fatalf("scan: %v", r)
	}
	// The scan starts in the background.
	for i := 0; i < 100 && len(f.scans()) == 0; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	resolved, _ := filepath.EvalSymlinks(alice)
	if sc := f.scans(); len(sc) != 1 || sc[0].Path != resolved || sc[0].Domain != "alice.com" {
		t.Errorf("scanned: %+v", sc)
	}
	if ev := f.reported[len(f.reported)-1]; ev.Type != "panel_scan" || ev.Details["path"] != resolved || ev.Details["actor"] != "root" {
		t.Errorf("event: %+v", ev)
	}
	// A known web root that is no site's document root is accepted too.
	if r := handlePanel(panel.Request{Command: "scan", Path: other, Actor: "root"}); !r.Succeeded() {
		t.Errorf("web root: %v", r)
	}
	f.scanning = true
	if r := handlePanel(panel.Request{Command: "scan", Path: bob, Actor: "root"}); r["error"] != panel.ErrScanRunning {
		t.Errorf("scan running: %v", r)
	}
}

func TestPanelCommandWithoutAgent(t *testing.T) {
	withFakePanel(t)
	if r := runPanelCommand(panel.Request{Command: "status"}); !r.Succeeded() || r["agent_running"] != false || r["version"] != version {
		t.Errorf("status: %v", r)
	}
	if r := runPanelCommand(panel.Request{Command: "coexistence"}); !r.Succeeded() || r["agent_running"] != false || r["mode"] != preflight.ModeCoexist {
		t.Errorf("coexistence: %v", r)
	}
	if r := runPanelCommand(panel.Request{Command: "sites"}); !r.Succeeded() || r["agent_running"] != false {
		t.Errorf("sites: %v", r)
	}
	for _, cmd := range []string{"bans", "unban", "events"} {
		r := runPanelCommand(panel.Request{Command: cmd, IP: "203.0.113.7", Actor: "root"})
		if r.Succeeded() || r["error"] != panel.ErrAgentNotRunning || r["agent_running"] != false {
			t.Errorf("%s: %v", cmd, r)
		}
	}
	panelEuid = func() int { return 1000 }
	if r := runPanelCommand(panel.Request{Command: "status"}); r["error"] != panel.ErrNotRoot {
		t.Errorf("non-root: %v", r)
	}
	// Every answer is one JSON object with ok.
	b, err := json.Marshal(runPanelCommand(panel.Request{Command: "status"}))
	if err != nil || !strings.HasPrefix(string(b), "{") || !strings.Contains(string(b), `"ok":false`) {
		t.Errorf("json: %s %v", b, err)
	}
}

func TestPanelUnknownCommand(t *testing.T) {
	withFakePanel(t)
	if r := handlePanel(panel.Request{Command: "reboot"}); r["error"] != panel.ErrUnknownCommand {
		t.Errorf("got %v", r)
	}
}

func TestSystemTree(t *testing.T) {
	for p, refused := range map[string]bool{
		"/":                                    true,
		"/home":                                true,
		"/etc/nginx":                           true,
		"/root/site":                           true,
		"/var/lib/mysql":                       true,
		"/home/alice/public_html":              false,
		"/var/www/vhosts/example.com/httpdocs": false,
		"/var/lib/docker/volumes/wp/_data":     false,
		"/usr/share/nginx/html":                false,
	} {
		if got := systemTree(p) != ""; got != refused {
			t.Errorf("systemTree(%q) refused=%v, want %v", p, got, refused)
		}
	}
}

func TestPanelScanSymlinkedDocumentRootRefused(t *testing.T) {
	f := withFakePanel(t)
	link := filepath.Join(t.TempDir(), "public_html")
	if err := os.Symlink("/", link); err != nil {
		t.Fatal(err)
	}
	f.sites = []preflight.Site{{Account: "mallory", Domain: "m.example", Kind: "main", DocumentRoot: link}}
	f.roots = []malware.WebRoot{{Path: "/"}}
	if r := handlePanel(panel.Request{Command: "scan", Path: link, Actor: "root"}); r["error"] != panel.ErrUnknownPath {
		t.Errorf("scan of / through a symlink: %v", r)
	}
	if sites := handlePanel(panel.Request{Command: "sites"})["sites"].([]panelSite); sites[0].Covered {
		t.Errorf("symlink to / counted as covered: %+v", sites)
	}
	if len(f.scans()) != 0 {
		t.Errorf("scan started: %+v", f.scans())
	}
}

func TestPanelOutboxKeepsOrder(t *testing.T) {
	f := withFakePanel(t)
	syncWith(nil)
	f.reportErr = errors.New("down")
	handlePanel(panel.Request{Command: "allow", IP: "198.51.100.4", Actor: "root"})
	f.reportErr = nil
	r := handlePanel(panel.Request{Command: "disallow", IP: "198.51.100.4", Actor: "root"})
	if r["reported"] != true || panelOutboxLen() != 0 {
		t.Fatalf("disallow: %v, outbox %d", r, panelOutboxLen())
	}
	var types []string
	for _, e := range f.reported {
		types = append(types, e.Type)
	}
	if !reflect.DeepEqual(types, []string{"panel_allow", "panel_disallow"}) {
		t.Errorf("order: %v", types)
	}
}

func TestPanelSaveFailureChangesNothing(t *testing.T) {
	f := withFakePanel(t)
	syncWith([]api.Ban{{ID: 1, IPAddress: "203.0.113.7"}})
	f.banned["203.0.113.7"] = true
	blocker := filepath.Join(t.TempDir(), "file")
	os.WriteFile(blocker, nil, 0o600)
	panelStatePath = filepath.Join(blocker, "panel-state.json") // parent is a file
	if r := handlePanel(panel.Request{Command: "unban", IP: "203.0.113.7", Actor: "root"}); r["error"] != panel.ErrInternal {
		t.Errorf("unban: %v", r)
	}
	if len(f.unbanned) != 0 || len(panelState.p.Lifted) != 0 || len(f.reported) != 0 {
		t.Errorf("changed anyway: fw %v lifted %v reported %v", f.unbanned, panelState.p.Lifted, f.reported)
	}
	if r := handlePanel(panel.Request{Command: "allow", IP: "198.51.100.4", Actor: "root"}); r["error"] != panel.ErrInternal || len(panelAllowedIPs()) != 0 {
		t.Errorf("allow: %v %v", r, panelAllowedIPs())
	}
}

func TestPanelAdoptWindow(t *testing.T) {
	f := withFakePanel(t)
	syncWith(nil)
	f.banned["203.0.113.8"] = true
	handlePanel(panel.Request{Command: "unban", IP: "203.0.113.8", Actor: "root"})
	// The dashboard records the ban a little late.
	f.now = f.now.Add(10 * time.Minute)
	syncWith(nil)
	if got := syncWith([]api.Ban{{ID: 9, IPAddress: "203.0.113.8"}}); len(got) != 0 {
		t.Errorf("late dashboard ban applied: %v", got)
	}
	// A lift that never matched anything ends after the window.
	f.banned["203.0.113.9"] = true
	handlePanel(panel.Request{Command: "unban", IP: "203.0.113.9", Actor: "root"})
	f.now = f.now.Add(2 * time.Hour)
	syncWith(nil)
	if got := syncWith([]api.Ban{{ID: 10, IPAddress: "203.0.113.9"}}); len(got) != 1 {
		t.Errorf("ban after the window suppressed: %v", got)
	}
}

func TestCleanText(t *testing.T) {
	if got := cleanText("evil\n<script>\x1b[31m", 100); got != "evil?<script>?[31m" {
		t.Errorf("got %q", got)
	}
	if got := cleanText("àààà", 5); got != "àà" {
		t.Errorf("cut inside a rune: %q", got)
	}
}

func TestPanelUnbanPermanentBanCappedAt30Days(t *testing.T) {
	f := withFakePanel(t)
	bans := []api.Ban{{ID: 7, IPAddress: "198.51.100.30", Source: "automode"}}
	syncWith(bans)
	r := handlePanel(panel.Request{Command: "unban", IP: "198.51.100.30", Actor: "root"})
	if !r.Succeeded() || r["source"] != "automode" || r["lifted_until"] != "2026-11-15T12:00:00Z" {
		t.Fatalf("unban: %v", r)
	}
	f.now = f.now.Add(29 * 24 * time.Hour)
	if got := syncWith(bans); len(got) != 0 {
		t.Errorf("day 29: %v", got)
	}
	// The dashboard still sends it after 30 days: enforced again.
	f.now = f.now.Add(2 * 24 * time.Hour)
	if got := syncWith(bans); len(got) != 1 {
		t.Errorf("day 31: %v", got)
	}
}

func TestPanelEnabledOnlyOnCPanelPleskOrByConfig(t *testing.T) {
	for _, c := range []struct {
		panel string
		flag  bool
		want  bool
	}{
		{"cpanel", false, true}, {"plesk", false, true}, {"", false, false},
		{"directadmin", false, false}, {"hestiacp", false, false}, {"", true, true}, {"directadmin", true, true},
	} {
		if got := panelEnabledFor(c.panel, c.flag); got != c.want {
			t.Errorf("panelEnabledFor(%q, %v) = %v", c.panel, c.flag, got)
		}
	}
}

// On a host without cPanel/WHM or Plesk (and no "panel": true) nothing of
// the panel side runs: no state loaded, nothing copied, kept or filtered,
// even with a state file left on disk.
func TestPanelOffElsewhere(t *testing.T) {
	withFakePanel(t)
	bans := []api.Ban{{ID: 1, IPAddress: "203.0.113.7"}}
	panelState.p = panelPersisted{
		Lifted:  []liftedBan{{IP: "203.0.113.7", IDs: []int64{1}, Until: time.Now().Add(time.Hour).Unix()}},
		Allowed: []panelAllowEntry{{IP: "198.51.100.4"}},
	}
	savePanelStateLocked()
	resetPanelState()
	panelOn.Store(false)
	panelReportFn = nil

	if panelEnable("", false, func([]api.EventRequest) error { return nil }) {
		t.Fatal("enabled on a host without a panel")
	}
	if panelOn.Load() || panelReportFn != nil || len(panelState.p.Lifted) != 0 {
		t.Fatalf("state loaded: on=%v lifted=%v", panelOn.Load(), panelState.p.Lifted)
	}
	// Even with state in memory, every hook is a no-op.
	panelState.p.Lifted = []liftedBan{{IP: "203.0.113.7", IDs: []int64{1}, Until: time.Now().Add(time.Hour).Unix()}}
	panelState.p.Allowed = []panelAllowEntry{{IP: "198.51.100.4"}}
	if got := panelFilterBans(bans); len(got) != 1 {
		t.Errorf("bans filtered: %v", got)
	}
	if panelAllowedIPs() != nil || panelAllowed("198.51.100.4") || panelOutboxLen() != 0 {
		t.Error("allow list or outbox used")
	}
	panelNoteSync(&api.SyncResponse{Bans: bans})
	panelNoteEvent(api.EventRequest{Type: "ssh_brute_force", Severity: "warning"})
	panelNoteLocalBan("203.0.113.8", "x")
	panelNoteScanFindings([]malware.Finding{{FilePath: "/home/a/x.php", Severity: "high"}})
	if !panelState.view.at.IsZero() || len(panelState.events) != 0 || len(panelState.banInfo) != 0 || len(panelState.findings) != 0 {
		t.Errorf("copied while off: view=%v events=%d banInfo=%d findings=%d",
			panelState.view.at, len(panelState.events), len(panelState.banInfo), len(panelState.findings))
	}
	// cPanel/WHM or Plesk: on, with the saved state.
	if !panelEnable("plesk", false, func([]api.EventRequest) error { return nil }) || !panelOn.Load() || len(panelState.p.Lifted) != 1 {
		t.Errorf("not enabled on Plesk: on=%v lifted=%v", panelOn.Load(), panelState.p.Lifted)
	}
}
