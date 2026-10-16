package main

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/config"
	"github.com/infrafence/infrafence-agent/internal/firewall"
	"github.com/infrafence/infrafence-agent/internal/malware"
	"github.com/infrafence/infrafence-agent/internal/panel"
	"github.com/infrafence/infrafence-agent/internal/preflight"
)

// The panel side of the agent: "infrafence-agent panel <command> --json",
// run as root by the WHM and Plesk plugins, asks the running agent over
// /run/infrafence/panel.sock (internal/panel) and prints its JSON answer.
// Unban, allow and disallow go through the same firewall and allow-list
// code as the dashboard's bans and allow list, are kept across restarts
// (panelstate.go) and are reported to the dashboard as events with source
// "panel" and the panel user. They act on this server only: an unban is a
// local lift (scope "server") and never removes the ban in the dashboard or
// on the organization's other servers.

var panelSocketPath = panel.SocketPath

// Replaced in tests.
var (
	panelIsBanned      = firewall.IsBanned
	panelUnbanIP       = firewall.UnbanIP
	panelSetAllowList  = firewall.SetAllowList
	panelIsAllowListed = firewall.IsAllowListed
	panelInThreatSet   = firewall.InThreatSet
	panelOwnAddress    = func(ip string) bool { return firewall.IsLocalIP(ip) || ip == panelInfo.selfIP }
	panelRequestSync   = func(string) {}
	panelDetectSites   = preflight.DetectSites
	panelCoexistence   = preflight.DetectCoexistence
	panelDetectRoots   = func() []malware.WebRoot { return malware.DetectWebRoots(malwareCustomPaths) }
	panelClaimScan     = func() bool { return malwareScanRunning.CompareAndSwap(false, true) }
	panelStartScan     = func(malware.WebRoot, func() error) {}
	panelEuid          = os.Geteuid
	panelDetectPanelID = func() string { return preflight.DetectPanel().ID }
)

// panelInfo: who this agent is, set at startup.
var panelInfo struct {
	agentID   int64
	serverURL string
	panelID   string
	selfIP    string // public address (NAT'd clouds don't bind it locally)
}

// panelLastHeartbeat is the unix time of the last heartbeat the dashboard
// accepted.
var panelLastHeartbeat atomic.Int64

// cmdPanel is "infrafence-agent panel <command> [args] [--json]". The
// answer is always one JSON object on stdout; the exit status is 0 when it
// says ok.
func cmdPanel(args []string) {
	// stdout carries only the answer.
	log.SetOutput(io.Discard)
	req, jsonOut, resp := panel.ParseArgs(args, time.Now())
	if resp == nil {
		resp = runPanelCommand(req)
	}
	enc := json.NewEncoder(os.Stdout)
	if !jsonOut {
		enc.SetIndent("", "  ")
	}
	_ = enc.Encode(resp)
	if !resp.Succeeded() {
		os.Exit(1)
	}
}

// runPanelCommand asks the running agent. Without one, status, coexistence
// and sites are answered here (read-only); every other command fails with
// agent_not_running. Every answer says whether the agent runs.
func runPanelCommand(req panel.Request) panel.Response {
	if panelEuid() != 0 {
		return panel.Fail(panel.ErrNotRoot, "run as root")
	}
	timeout := 20 * time.Second
	if panel.Mutating[req.Command] {
		timeout = 45 * time.Second
	}
	resp, err := panel.Call(panelSocketPath, req, timeout)
	if err == nil {
		resp["agent_running"] = true
		return resp
	}
	if !errors.Is(err, panel.ErrNotRunning) {
		resp = panel.Fail(panel.ErrInternal, "the agent did not answer: %v", err)
		resp["agent_running"] = true
		return resp
	}
	switch req.Command {
	case "status":
		resp = offlineStatus()
	case "coexistence":
		resp = panelCoexistenceAnswer()
	case "sites":
		resp = panelSitesAnswer(panelDetectPanelID(), panelDetectRoots(), nil)
	default:
		resp = panel.Fail(panel.ErrAgentNotRunning, "the InfraFence agent is not running")
	}
	resp["agent_running"] = false
	return resp
}

// offlineStatus is the status when the agent is not running: what the
// config file says (never the token).
func offlineStatus() panel.Response {
	r := panel.OK(map[string]any{
		"version": version, "agent_id": nil, "dashboard_url": nil, "last_heartbeat": nil, "last_sync": nil,
		"connected": false, "plan": nil, "automode": nil, "monitor_mode": nil, "suspended": nil,
		"control_panel": orNull(panelDetectPanelID()),
	})
	if cfg, err := config.Load(); err == nil {
		r["agent_id"] = cfg.AgentID
		if u := dashboardURL(cfg.ServerURL, cfg.AgentID); u != "" {
			r["dashboard_url"] = u
		}
	}
	return r
}

// dashboardURL is this server's page on the dashboard ("Open in
// InfraFence"), or "" when the server URL is not plain http(s).
func dashboardURL(serverURL string, agentID int64) string {
	u, err := url.Parse(strings.TrimSpace(serverURL))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || agentID <= 0 {
		return ""
	}
	return strings.TrimRight(u.Scheme+"://"+u.Host+u.Path, "/") + "/servers/" + strconv.FormatInt(agentID, 10)
}

// startPanelSocket opens the socket for the plugins. A failure is logged
// and the agent runs on without it.
func startPanelSocket(client *api.Client, cfg *config.Config, panelID string, requestSync func(string)) func() {
	panelInfo.agentID, panelInfo.serverURL, panelInfo.panelID = cfg.AgentID, cfg.ServerURL, panelID
	panelInfo.selfIP = detectOutboundIP()
	panelRequestSync = requestSync
	// The scan slot is already claimed by panelScan.
	panelStartScan = func(root malware.WebRoot, verify func() error) {
		defer malwareScanRunning.Store(false)
		if err := verify(); err != nil {
			log.Printf("[panel] malware scan of %s not started: %v", root.Path, err)
			return
		}
		malwareScan(client, "medium", []malware.WebRoot{root})
	}
	srv, err := panel.Listen(panelSocketPath)
	if err != nil {
		log.Printf("[panel] socket not available: %v", err)
		return func() {}
	}
	log.Printf("[panel] listening on %s (root only)", panelSocketPath)
	go srv.Serve(handlePanel)
	return func() {
		if err := srv.Close(); err != nil {
			log.Printf("[panel] close socket: %v", err)
		}
	}
}

// handlePanel answers one validated request on the socket.
func handlePanel(req panel.Request) panel.Response {
	switch req.Command {
	case "status":
		return panelStatus()
	case "bans":
		return panelBans(req.Limit)
	case "unban":
		return panelUnban(req.IP, req.Actor)
	case "allow":
		return panelAllow(req.IP, req.Note, req.Actor)
	case "allowlist":
		return panelAllowlist()
	case "disallow":
		return panelDisallow(req.IP, req.Actor)
	case "findings":
		return panelFindings(req.Limit)
	case "events":
		return panelEvents(req.Limit, req.Since)
	case "coexistence":
		return panelCoexistenceAnswer()
	case "sites":
		panelState.Lock()
		enabled := panelState.view.malwareScan
		panelState.Unlock()
		return panelSitesAnswer(panelInfo.panelID, cachedWebRoots(), enabled)
	case "scan":
		return panelScan(req.Path, req.Actor)
	}
	return panel.Fail(panel.ErrUnknownCommand, "unknown command %q", req.Command)
}

// panelSystemDirs are never scanned from the panel; replaced in tests.
var panelSystemDirs = []string{"/etc", "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/boot", "/dev", "/proc", "/sys",
	"/run", "/root", "/var/lib", "/var/log", "/var/spool", "/var/cache", "/tmp", "/var/tmp", "/snap"}

// systemTree refuses a scan target that is not a site's own directory: a
// document root can be a symlink its owner points anywhere, so the
// resolved path is checked. Returns why, or "".
func systemTree(p string) string {
	if strings.Count(strings.Trim(p, "/"), "/") < 1 {
		return "too close to the root of the file system"
	}
	for _, d := range panelSystemDirs {
		if within(p, d) && !within(p, "/var/lib/docker/volumes") && !within(p, "/usr/share/nginx") && !within(p, "/usr/local/apache/htdocs") {
			return "a system directory"
		}
	}
	return ""
}

var sitesCache struct {
	sync.Mutex
	at    time.Time
	panel string
	sites []preflight.Site
}

// cachedSites: on Plesk listing the sites queries its database; panels may
// ask often. The detection runs outside the lock (it can take seconds), so
// a slow one never holds up the other requests.
func cachedSites(panelID string) []preflight.Site {
	sitesCache.Lock()
	if sitesCache.sites != nil && sitesCache.panel == panelID && panelNow().Sub(sitesCache.at) <= time.Minute {
		sites := sitesCache.sites
		sitesCache.Unlock()
		return sites
	}
	sitesCache.Unlock()
	sites := panelDetectSites(panelID)
	sitesCache.Lock()
	sitesCache.sites, sitesCache.panel, sitesCache.at = sites, panelID, panelNow()
	sitesCache.Unlock()
	return sites
}

// orNull: every documented key is always present (docs/panel-json.md); an
// unknown value is null, never "".
func orNull(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func rfc3339(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}

func panelStatus() panel.Response {
	panelState.Lock()
	v := panelState.view
	panelState.Unlock()
	var hb time.Time
	if ts := panelLastHeartbeat.Load(); ts > 0 {
		hb = time.Unix(ts, 0)
	}
	r := panel.OK(map[string]any{
		"version":        version,
		"agent_id":       panelInfo.agentID,
		"last_heartbeat": rfc3339(hb),
		"last_sync":      rfc3339(v.at),
		"connected":      !hb.IsZero() && panelNow().Sub(hb) < 3*time.Minute,
		"plan":           nil,
		"automode":       nil,
		"monitor_mode":   v.monitorMode,
		"suspended":      v.suspended,
		"dashboard_url":  nil,
		"control_panel":  orNull(panelInfo.panelID),
	})
	if v.plan != "" {
		r["plan"] = v.plan
	}
	if len(v.autoMode) > 0 && json.Valid(v.autoMode) && string(v.autoMode) != "null" {
		r["automode"] = v.autoMode
	}
	if u := dashboardURL(panelInfo.serverURL, panelInfo.agentID); u != "" {
		r["dashboard_url"] = u
	}
	return r
}

type panelBan struct {
	IP      string `json:"ip"`
	Reason  any    `json:"reason"`
	Source  string `json:"source"`
	Created any    `json:"created"`
	Expires any    `json:"expires"`
}

var banSources = map[string]bool{"local": true, "network": true, "automode": true, "manual": true}

// panelBans lists the active bans: the dashboard's (lifted ones left out)
// and the agent's own not synced yet. Newest first where known.
func panelBans(limit int) panel.Response {
	panelState.Lock()
	v := panelState.view
	info := make(map[string]localBan, len(panelState.banInfo))
	for k, b := range panelState.banInfo {
		info[k] = b
	}
	lifted := map[string]bool{}
	for _, l := range panelState.p.Lifted {
		lifted[l.IP] = true
	}
	panelState.Unlock()

	now := panelNow()
	var out []panelBan
	seen := map[string]bool{}
	for _, b := range panelFilterView(v.bans) {
		if seen[b.IPAddress] {
			continue
		}
		if b.ExpiresAt != nil {
			if t, err := time.Parse(time.RFC3339Nano, *b.ExpiresAt); err == nil && !t.After(now) {
				continue
			}
		}
		seen[b.IPAddress] = true
		pb := panelBan{IP: b.IPAddress, Reason: orNull(cleanText(b.Reason, 200)), Source: b.Source}
		if b.CreatedAt != "" {
			pb.Created = cleanText(b.CreatedAt, 40)
		}
		if b.ExpiresAt != nil {
			pb.Expires = *b.ExpiresAt
		}
		lb, local := info[b.IPAddress]
		pb.Source = banSource(b, local)
		if local {
			if pb.Reason == nil {
				pb.Reason = orNull(cleanText(lb.reason, 200))
			}
			if pb.Created == nil {
				pb.Created = rfc3339(lb.created)
			}
		}
		out = append(out, pb)
	}
	for ip, lb := range info {
		if !seen[ip] && !lifted[ip] && panelIsBanned(ip) {
			out = append(out, panelBan{IP: ip, Reason: orNull(cleanText(lb.reason, 200)), Source: "local", Created: rfc3339(lb.created)})
		}
	}
	slices.SortStableFunc(out, func(a, b panelBan) int {
		as, _ := a.Created.(string)
		bs, _ := b.Created.(string)
		return strings.Compare(bs, as)
	})
	total := len(out)
	if len(out) > limit {
		out = out[:limit]
	}
	if out == nil {
		out = []panelBan{}
	}
	return panel.OK(map[string]any{"bans": out, "total": total, "monitor_mode": v.monitorMode})
}

// banSource is where a ban comes from: what the dashboard says, else a
// network ban (id 0), the agent's own detection, or a dashboard ban.
func banSource(b api.Ban, local bool) string {
	switch {
	case banSources[b.Source]:
		return b.Source
	case b.ID == 0:
		return "network"
	case local:
		return "local"
	}
	return "manual"
}

// panelFilterView leaves out lifted bans without touching the saved state.
func panelFilterView(bans []api.Ban) []api.Ban {
	panelState.Lock()
	defer panelState.Unlock()
	if len(panelState.p.Lifted) == 0 {
		return bans
	}
	out := make([]api.Ban, 0, len(bans))
	for _, b := range bans {
		if slices.ContainsFunc(panelState.p.Lifted, func(l liftedBan) bool {
			return l.IP == b.IPAddress && (l.Adopt || slices.Contains(l.IDs, b.ID))
		}) {
			continue
		}
		out = append(out, b)
	}
	return out
}

func panelEventFor(typ, actor string, details map[string]string) api.EventRequest {
	d := map[string]string{"source": "panel", "actor": actor}
	if panelInfo.panelID != "" {
		d["panel"] = panelInfo.panelID
	}
	for k, v := range details {
		d[k] = v
	}
	return api.EventRequest{Type: typ, Severity: "info", Details: d, OccurredAt: panelNow().UTC().Format(time.RFC3339)}
}

// panelUnban lifts a ban on this server only: removed from the firewall now
// and left out of this server's syncs until the dashboard stops sending it
// (it expired or someone removed it there), or for at most 30 days
// (liftMaxAge), after which a ban the dashboard still sends is enforced
// again. The dashboard is told it was lifted here (panel_unban, scope
// "server"); the ban itself stays in the dashboard and on the
// organization's other servers.
func panelUnban(ip, actor string) panel.Response {
	now := panelNow()
	panelState.Lock()
	var ids []int64
	until := now.Add(liftMaxAge)
	permanent := false
	var latest time.Time
	_, local := panelState.banInfo[ip]
	source := "local" // banned by this agent, not in a sync yet
	for _, b := range panelState.view.bans {
		if b.IPAddress != ip {
			continue
		}
		if len(ids) == 0 {
			source = banSource(b, local)
		}
		ids = append(ids, b.ID)
		if b.ExpiresAt == nil {
			permanent = true
		} else if t, err := time.Parse(time.RFC3339Nano, *b.ExpiresAt); err == nil && t.After(latest) {
			latest = t
		}
	}
	if !permanent && !latest.IsZero() && latest.Before(until) {
		until = latest
	}
	alreadyLifted := slices.ContainsFunc(panelState.p.Lifted, func(l liftedBan) bool { return l.IP == ip })
	banned := panelIsBanned(ip)
	if (len(ids) == 0 && !banned) || (alreadyLifted && !banned) {
		panelState.Unlock()
		return panel.Fail(panel.ErrNotBanned, "%s is not banned by InfraFence on this server", ip)
	}
	prev := slices.Clone(panelState.p.Lifted)
	panelState.p.Lifted = slices.DeleteFunc(panelState.p.Lifted, func(l liftedBan) bool { return l.IP == ip })
	panelState.p.Lifted = append(panelState.p.Lifted, liftedBan{
		IP: ip, IDs: ids, Adopt: true, Actor: actor, LiftedAt: now.Unix(), Until: until.Unix(),
	})
	if n := len(panelState.p.Lifted) - maxLifted; n > 0 {
		panelState.p.Lifted = slices.Delete(panelState.p.Lifted, 0, n)
	}
	// Not kept across a restart means not lifted: nothing is changed.
	if err := savePanelStateLocked(); err != nil {
		panelState.p.Lifted = prev
		panelState.Unlock()
		return panel.Fail(panel.ErrInternal, "could not save the change: %v", err)
	}
	delete(panelState.banInfo, ip)
	panelState.Unlock()

	log.Printf("[panel] unban %s by %s", ip, actor)
	fwErr := panelUnbanIP(ip)
	if fwErr != nil {
		log.Printf("[panel] unban %s: %v (removed at the next sync)", ip, fwErr)
	}
	// A record of a local lift, not a request to delete anything: no ban
	// ids, and the scope says so.
	reported := panelReport([]api.EventRequest{panelEventFor("panel_unban", actor, map[string]string{
		"ip": ip, "scope": "server", "ban_source": source, "lifted_until": time.Unix(until.Unix(), 0).UTC().Format(time.RFC3339),
	})})
	// The sync re-applies everything without the lifted ban (ModSecurity
	// ban rules included).
	panelRequestSync("panel unban")
	r := panel.OK(map[string]any{
		"ip": ip, "reported": reported, "threat_feed": panelInThreatSet(ip),
		"source": source, "scope": "server", "lifted_until": rfc3339(until),
	})
	if fwErr != nil {
		r["firewall_pending"] = true
	}
	return r
}

// panelAllowSnapshot is the allow list to enforce: the dashboard's from the
// last sync plus the panel's. ok is false before the first sync (applying
// then would drop the dashboard's entries until it).
func panelAllowSnapshot() (entries []string, ok bool) {
	panelState.Lock()
	defer panelState.Unlock()
	if panelState.view.at.IsZero() {
		return nil, false
	}
	for _, w := range panelState.view.whitelists {
		if w.IPAddress != nil && *w.IPAddress != "" {
			entries = append(entries, *w.IPAddress)
		}
		if w.IPRange != nil && *w.IPRange != "" {
			entries = append(entries, *w.IPRange)
		}
	}
	for _, a := range panelState.p.Allowed {
		entries = append(entries, a.IP)
	}
	return entries, true
}

func panelApplyAllow() {
	if entries, ok := panelAllowSnapshot(); ok {
		panelSetAllowList(entries)
	}
	// The watchers, threat feeds and country blocks get it from the sync.
	panelRequestSync("panel allow list")
}

// panelAllow adds ip to this server's allow list: never banned or blocked
// by InfraFence again (it opens nothing in the host firewall).
func panelAllow(ip, note, actor string) panel.Response {
	if a, err := netip.ParseAddr(ip); err == nil && a.IsLoopback() {
		return panel.Fail(panel.ErrLoopback, "%s is a loopback address: it is never banned and can't be allow-listed", ip)
	}
	// Allowed anyway (the server's own addresses are never banned), with a
	// warning the plugin can show: usually a mistake.
	own := panelOwnAddress(ip)
	panelState.Lock()
	if slices.ContainsFunc(panelState.p.Allowed, func(a panelAllowEntry) bool { return a.IP == ip }) || panelIsAllowListed(ip) {
		panelState.Unlock()
		return panel.OK(map[string]any{"ip": ip, "already": true, "own_address": own})
	}
	if len(panelState.p.Allowed) >= maxPanelAllow {
		panelState.Unlock()
		return panel.Fail(panel.ErrBadRequest, "the panel allow list is full (%d entries)", maxPanelAllow)
	}
	panelState.p.Allowed = append(panelState.p.Allowed, panelAllowEntry{IP: ip, Note: note, Actor: actor, AddedAt: panelNow().Unix()})
	if err := savePanelStateLocked(); err != nil {
		panelState.p.Allowed = panelState.p.Allowed[:len(panelState.p.Allowed)-1]
		panelState.Unlock()
		return panel.Fail(panel.ErrInternal, "could not save the change: %v", err)
	}
	panelState.Unlock()

	log.Printf("[panel] allow %s by %s", ip, actor)
	panelApplyAllow()
	details := map[string]string{"ip": ip}
	if note != "" {
		details["note"] = note
	}
	reported := panelReport([]api.EventRequest{panelEventFor("panel_allow", actor, details)})
	return panel.OK(map[string]any{"ip": ip, "reported": reported, "banned": panelIsBanned(ip), "own_address": own})
}

func panelDisallow(ip, actor string) panel.Response {
	panelState.Lock()
	i := slices.IndexFunc(panelState.p.Allowed, func(a panelAllowEntry) bool { return a.IP == ip })
	if i < 0 {
		managed := slices.ContainsFunc(panelState.view.whitelists, func(w api.WhitelistEntry) bool {
			return w.IPAddress != nil && *w.IPAddress == ip
		})
		panelState.Unlock()
		if managed {
			return panel.Fail(panel.ErrManaged, "%s is on the organization's allow list; remove it in the InfraFence dashboard", ip)
		}
		return panel.Fail(panel.ErrNotAllowed, "%s is not on this server's allow list", ip)
	}
	prev := slices.Clone(panelState.p.Allowed)
	panelState.p.Allowed = slices.Delete(panelState.p.Allowed, i, i+1)
	if err := savePanelStateLocked(); err != nil {
		panelState.p.Allowed = prev
		panelState.Unlock()
		return panel.Fail(panel.ErrInternal, "could not save the change: %v", err)
	}
	panelState.Unlock()

	log.Printf("[panel] disallow %s by %s", ip, actor)
	panelApplyAllow()
	reported := panelReport([]api.EventRequest{panelEventFor("panel_disallow", actor, map[string]string{"ip": ip})})
	return panel.OK(map[string]any{"ip": ip, "reported": reported})
}

type panelAllowItem struct {
	Address string `json:"address"` // IP or CIDR
	Source  string `json:"source"`  // panel, dashboard
	Note    any    `json:"note"`
	Actor   any    `json:"actor"`
	Added   any    `json:"added"`
}

func panelAllowlist() panel.Response {
	panelState.Lock()
	defer panelState.Unlock()
	var out []panelAllowItem
	seen := map[string]bool{}
	for _, a := range panelState.p.Allowed {
		seen[a.IP] = true
		out = append(out, panelAllowItem{Address: a.IP, Source: "panel", Note: orNull(a.Note), Actor: orNull(a.Actor), Added: rfc3339(time.Unix(a.AddedAt, 0))})
	}
	for _, w := range panelState.view.whitelists {
		for _, addr := range []*string{w.IPAddress, w.IPRange} {
			if addr != nil && *addr != "" && !seen[*addr] {
				seen[*addr] = true
				out = append(out, panelAllowItem{Address: *addr, Source: "dashboard"})
			}
		}
	}
	if out == nil {
		out = []panelAllowItem{}
	}
	return panel.OK(map[string]any{"allowlist": out})
}

func panelFindings(limit int) panel.Response {
	panelState.Lock()
	out := append([]panelFinding(nil), panelState.findings...)
	panelState.Unlock()
	slices.SortStableFunc(out, func(a, b panelFinding) int { return strings.Compare(b.LastSeen, a.LastSeen) })
	total := len(out)
	if len(out) > limit {
		out = out[:limit]
	}
	if out == nil {
		out = []panelFinding{}
	}
	return panel.OK(map[string]any{"findings": out, "total": total})
}

// panelEventOut is one element of the events answer.
type panelEventOut struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	SourceIP any    `json:"source_ip"`
	Source   any    `json:"source"`
	Time     string `json:"time"`
}

func panelEvents(limit int, since string) panel.Response {
	var cutoff time.Time
	if since != "" {
		cutoff, _ = time.Parse(time.RFC3339, since)
	}
	panelState.Lock()
	var out []panelEvent
	for i := len(panelState.events) - 1; i >= 0 && len(out) < limit; i-- {
		e := panelState.events[i]
		if !cutoff.IsZero() {
			if t, err := time.Parse(time.RFC3339, e.Time); err == nil && t.Before(cutoff) {
				continue
			}
		}
		out = append(out, e)
	}
	panelState.Unlock()
	if out == nil {
		out = []panelEvent{}
	}
	res := make([]panelEventOut, len(out))
	for i, e := range out {
		res[i] = panelEventOut{Type: e.Type, Severity: e.Severity, SourceIP: orNull(e.SourceIP), Source: orNull(e.Source), Time: e.Time}
	}
	return panel.OK(map[string]any{"events": res})
}

func panelCoexistenceAnswer() panel.Response {
	c := panelCoexistence()
	type toolOut struct {
		ID       string   `json:"id"`
		Name     string   `json:"name"`
		Kind     string   `json:"kind"`
		Active   bool     `json:"active"`
		Version  any      `json:"version"`
		Rulesets []string `json:"rulesets"`
		Firewall bool     `json:"manages_firewall"`
		ActionID string   `json:"action_id"`
		Action   string   `json:"action"`
	}
	tools := make([]toolOut, len(c.Tools))
	for i, t := range c.Tools {
		rs := t.Rulesets
		if rs == nil {
			rs = []string{}
		}
		tools[i] = toolOut{ID: t.ID, Name: t.Name, Kind: t.Kind, Active: t.Active, Version: orNull(t.Version),
			Rulesets: rs, Firewall: t.Firewall, ActionID: t.ActionID, Action: t.Action}
	}
	return panel.OK(map[string]any{"mode": c.Mode, "tools": tools})
}

type panelSite struct {
	Account      any    `json:"account"`
	Domain       string `json:"domain"`
	Kind         string `json:"kind"`
	DocumentRoot any    `json:"document_root"`
	Covered      bool   `json:"scan_covered"`
	// Scannable: "scan" accepts this document root (panelscan.go).
	Scannable bool `json:"scannable"`
}

// panelSitesAnswer lists the sites and whether the malware scan covers each
// document root (inside one of the web roots it scans).
func panelSitesAnswer(panelID string, roots []malware.WebRoot, scanEnabled *bool) panel.Response {
	var resolved []string
	for _, r := range roots {
		if p, err := filepath.EvalSymlinks(r.Path); err == nil {
			resolved = append(resolved, p)
		}
	}
	sites := cachedSites(panelID)
	out := make([]panelSite, 0, len(sites))
	for _, s := range sites {
		ps := panelSite{Account: orNull(s.Account), Domain: s.Domain, Kind: s.Kind, DocumentRoot: orNull(s.DocumentRoot), Scannable: scannable(s)}
		if s.DocumentRoot != "" {
			if p, err := filepath.EvalSymlinks(s.DocumentRoot); err == nil && systemTree(p) == "" {
				ps.Covered = slices.ContainsFunc(resolved, func(root string) bool { return within(p, root) })
			}
		}
		out = append(out, ps)
	}
	r := panel.OK(map[string]any{"control_panel": orNull(panelID), "sites": out, "malware_scan_enabled": nil})
	if scanEnabled != nil {
		r["malware_scan_enabled"] = *scanEnabled
	}
	return r
}

func within(p, root string) bool {
	return p == root || strings.HasPrefix(p, strings.TrimSuffix(root, "/")+"/")
}

var webRootsCache struct {
	sync.Mutex
	at    time.Time
	roots []malware.WebRoot
}

// cachedWebRoots: web root detection walks the disk and logs; panels may
// ask often. Detected outside the lock, like cachedSites.
func cachedWebRoots() []malware.WebRoot {
	webRootsCache.Lock()
	if webRootsCache.roots != nil && panelNow().Sub(webRootsCache.at) <= 5*time.Minute {
		roots := webRootsCache.roots
		webRootsCache.Unlock()
		return roots
	}
	webRootsCache.Unlock()
	roots := panelDetectRoots()
	webRootsCache.Lock()
	webRootsCache.roots, webRootsCache.at = roots, panelNow()
	webRootsCache.Unlock()
	return roots
}
