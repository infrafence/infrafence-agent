package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/firewall"
	"github.com/infrafence/infrafence-agent/internal/netstate"
	"github.com/infrafence/infrafence-agent/internal/verify"
)

// Ports closed and egress blocked from the dashboard. The sync carries the
// full desired state (firewall_state) and the individual requests
// (firewall_actions), each answered with a result event. A request the agent
// has applied but the dashboard still lists as pending is kept on top of the
// state, so a sync that crosses the result event never undoes it.
//
// The agent does by itself only what is certainly safe, whatever the
// dashboard asks:
//
//   - it closes only the ports of closablePorts (databases, caches, admin
//     APIs), never 22, 80, 443, an SSH port (sshd -T, sshd's listeners, the
//     ssh.socket/sshd.socket units, the port of every SSH session open now)
//     or a port a web server listens on; a new request is also refused while
//     a public address is connected to the port (sockets and conntrack, so a
//     published container port counts too);
//   - it blocks egress only to an IPv4 address it flagged itself as a threat
//     in the last 24 hours (egress_threat_match, dns_threat_answer, or the
//     threat-feed blocklist it enforces), and never to a private, protected
//     or allow-listed address, the dashboard API, a configured DNS resolver,
//     an address logged in over SSH right now or that an SSH login came from
//     in the last 30 days, or (for a new request) an address connected to a
//     service of this server right now. A connection to an SSH port that has
//     not logged in (a brute force) protects nobody.
//
// The checks that depend on what is connected right now (and the "flagged"
// check) apply to new requests, not to what is already enforced: a restart
// never reopens a port because someone is connected through the DROP. What
// is enforced is saved (fwstate.go) and restored at startup. Every change is
// verified (verify package) and rolled back when SSH or a site stops
// answering. In monitor mode nothing changes.

var (
	fwActMu   sync.Mutex // one action at a time
	fwStateMu sync.Mutex
	fwBase    *api.FirewallState
	fwOverlay = map[int64]api.FirewallAction{}
	fwPending []api.FirewallAction
	fwMonitor bool
	fwDone    = map[int64]bool{}
	// Results not delivered yet: sent again while the request is pending,
	// instead of running it a second time.
	fwUnsent     = map[int64]api.EventRequest{}
	fwActRunning atomic.Bool

	// What the agent enforces now, after the refusals (saved in
	// fwstate.go). Guarded by appliedMu.
	appliedMu       sync.Mutex
	fwAppliedPorts  = map[int]bool{}
	fwAppliedEgress = map[string]bool{}
	// Refusals of state entries already reported: key -> reason.
	fwRefusedSent = map[string]string{}
)

// Bounds on what one dashboard state can make the agent enforce, and on the
// requests handled per sync (the rest wait for the next one).
const (
	maxClosedPorts    = 200
	maxEgressBlocked  = 1000
	maxActionsPerSync = 10
)

// closablePorts are the only ports the agent closes: database, cache and
// admin services that should never face the internet.
var closablePorts = map[int]bool{
	3306: true, 5432: true, 6379: true, 6380: true, 27017: true, 27018: true, 9200: true, 9300: true,
	11211: true, 2375: true, 2376: true, 5984: true, 8086: true, 15672: true, 5601: true, 9042: true,
	7000: true, 7001: true, 8529: true, 28015: true,
}

// verifyDomains are the sites the verifier checks (the monitored domains).
var verifyDomains atomic.Pointer[[]string]

// verifyTargets returns what a host change must not break: every SSH port
// and the monitored sites.
func verifyTargets() (sshPorts []int, domains []string) {
	if d := verifyDomains.Load(); d != nil {
		domains = *d
	}
	return netstate.SSHPorts(), domains
}

// Replaced in tests.
var (
	fwSSHPorts      = netstate.SSHPorts
	fwWebPorts      = netstate.WebPorts
	fwPublicInbound = netstate.PublicInbound
	fwSockets       = netstate.Sockets
	fwSSHSessions   = netstate.SSHSessionAddrs
	fwEgressRefusal = firewall.EgressRefusal
	fwResolvers     = configuredResolvers
	fwApply         = firewall.SetPortsEgress
	fwPorts6        = firewall.Ports6InForce
	fwListens6      = listensReachableIPv6
	fwDropConntrack = func(ports []int) {
		for _, p := range ports {
			if n := firewall.DropConntrack(p); n > 0 {
				log.Printf("[firewall] port %d: dropped the tracked connections of %d public address(es)", p, n)
			}
		}
	}
	// fwReportRefusal sends the result event of a refused state entry.
	fwReportRefusal = func(ev api.EventRequest) {
		if c := currentAPIClient.Load(); c != nil {
			if err := c.ReportEvents([]api.EventRequest{ev}); err != nil {
				log.Printf("[firewall] report refusal: %v", err)
			}
		}
	}
	fwSnapshot = func() verify.State {
		ssh, domains := verifyTargets()
		return verify.Snapshot(context.Background(), ssh, domains)
	}
	fwCheck = func(before verify.State) verify.Result { return verify.Check(context.Background(), before) }
)

// applyFirewallState records the dashboard's desired state and pending
// requests and enforces the result. In monitor mode nothing is enforced.
// A sync without firewall_state (an older dashboard) leaves the state as it
// was.
func applyFirewallState(state *api.FirewallState, pending []api.FirewallAction, monitorMode bool) {
	fwSSHPorts() // refresh the cached sshd -T outside the lock
	fwStateMu.Lock()
	if state != nil {
		fwBase = state
	}
	fwPending = append([]api.FirewallAction(nil), pending...)
	fwMonitor = monitorMode
	open := map[int64]bool{}
	for _, a := range pending {
		open[a.ID] = true
	}
	for id := range fwOverlay {
		if !open[id] {
			delete(fwOverlay, id)
		}
	}
	err := renderFirewallLocked()
	fwStateMu.Unlock()
	if err != nil {
		log.Printf("[firewall] closed ports / egress: %v", err)
	}
}

// renderFirewallLocked computes the effective state and applies it.
// fwStateMu must be held.
func renderFirewallLocked() error {
	ports, egress := renderChecked()
	skipped, err := fwApply(ports, egress)
	if len(skipped) > 0 {
		log.Printf("[firewall] egress entries not applied: %s", strings.Join(skipped, ", "))
	}
	if newly := setApplied(ports, egress, skipped); len(newly) > 0 {
		go fwDropConntrack(newly)
	}
	return err
}

// renderChecked returns the effective state without what the refusals keep
// out, and reports the refused state entries (once each). Refusals are
// final, also for state the dashboard sends; the checks for new requests
// only apply to entries not enforced yet. fwStateMu must be held.
func renderChecked() (keepPorts []int, keepEgress []string) {
	ports, egress := effectiveFirewall()
	if fwMonitor {
		return nil, nil
	}
	requested := map[string]bool{}
	for _, a := range fwOverlay {
		requested[refusalKey(a.Kind, a.Port, a.IP)] = true
	}
	appliedMu.Lock()
	appliedEgress := make(map[string]bool, len(fwAppliedEgress))
	for ip := range fwAppliedEgress {
		appliedEgress[ip] = true
	}
	appliedMu.Unlock()

	c := newFwChecks()
	refused := map[string]api.EventRequest{}
	for _, p := range ports {
		if reason, msg := portRefusal(c, p, false); reason != "" {
			log.Printf("[firewall] not closing port %d: %s", p, msg)
			if key := refusalKey("close_port", p, ""); !requested[key] {
				refused[key] = stateRefusalEvent("close_port", p, "", reason, msg)
			}
			continue
		}
		keepPorts = append(keepPorts, p)
	}
	for _, ip := range egress {
		key := refusalKey("block_egress", 0, ip)
		if reason, msg := egressRefusal(c, ip, !appliedEgress[ip] && !requested[key]); reason != "" {
			log.Printf("[firewall] not blocking egress to %s: %s", ip, msg)
			if !requested[key] {
				refused[key] = stateRefusalEvent("block_egress", 0, ip, reason, msg)
			}
			continue
		}
		keepEgress = append(keepEgress, ip)
	}
	if len(keepPorts) > maxClosedPorts {
		log.Printf("[firewall] %d closed ports requested, applying the first %d", len(keepPorts), maxClosedPorts)
		keepPorts = keepPorts[:maxClosedPorts]
	}
	if len(keepEgress) > maxEgressBlocked {
		log.Printf("[firewall] %d egress blocks requested, applying the first %d", len(keepEgress), maxEgressBlocked)
		keepEgress = keepEgress[:maxEgressBlocked]
	}
	reportStateRefusals(refused)
	return keepPorts, keepEgress
}

// setApplied records what is enforced now and saves it. It returns the
// ports that were not closed before. skipped are the firewall's own
// refusals ("ip (reason)").
func setApplied(ports []int, egress []string, skipped []string) (newly []int) {
	notApplied := map[string]bool{}
	for _, sk := range skipped {
		notApplied[strings.Fields(sk)[0]] = true
	}
	appliedMu.Lock()
	nowPorts, nowEgress := map[int]bool{}, map[string]bool{}
	for _, p := range ports {
		nowPorts[p] = true
		if !fwAppliedPorts[p] {
			newly = append(newly, p)
		}
	}
	for _, ip := range egress {
		if !notApplied[ip] {
			nowEgress[ip] = true
		}
	}
	changed := len(nowPorts) != len(fwAppliedPorts) || len(nowEgress) != len(fwAppliedEgress) || len(newly) > 0
	for ip := range nowEgress {
		if !fwAppliedEgress[ip] {
			changed = true
		}
	}
	fwAppliedPorts, fwAppliedEgress = nowPorts, nowEgress
	appliedMu.Unlock()
	if changed {
		saveFirewallState()
	}
	return newly
}

func refusalKey(kind string, port int, ip string) string {
	switch kind {
	case "close_port", "open_port":
		return "port:" + strconv.Itoa(port)
	}
	return "egress:" + ip
}

// stateRefusalEvent is the result event of a state entry the agent refuses.
// It names no action_id: the dashboard has no request to update, the event
// tells why the entry is not enforced.
func stateRefusalEvent(kind string, port int, ip, reason, msg string) api.EventRequest {
	d := map[string]string{"kind": kind, "source": "firewall_state", "status": "failed", "reason": reason, "message": "refused: " + msg}
	if port > 0 {
		d["port"], d["proto"] = strconv.Itoa(port), "tcp"
	} else {
		d["ip"] = ip
	}
	return api.EventRequest{Type: "firewall_action_failed", Severity: "warning", Details: d, OccurredAt: time.Now().UTC().Format(time.RFC3339)}
}

// reportStateRefusals sends a result event for each refused state entry not
// reported yet (or refused for another reason now), and forgets entries no
// longer refused.
func reportStateRefusals(refused map[string]api.EventRequest) {
	var send []api.EventRequest
	for key, ev := range refused {
		if fwRefusedSent[key] != ev.Details["reason"] {
			fwRefusedSent[key] = ev.Details["reason"]
			send = append(send, ev)
		}
	}
	for key := range fwRefusedSent {
		if _, ok := refused[key]; !ok {
			delete(fwRefusedSent, key)
		}
	}
	for _, ev := range send {
		go fwReportRefusal(ev)
	}
}

// effectiveFirewall is the dashboard state with the agent's own pending
// results on top, applied in request order. A close or block the dashboard
// still lists as pending and the agent has not applied (not yet, refused,
// rolled back) is left out even when the state already has it: it only
// takes effect through the checks and verification of its request.
func effectiveFirewall() (ports []int, egress []string) {
	pset, eset := map[int]bool{}, map[string]bool{}
	if fwBase != nil {
		for _, p := range fwBase.ClosedPorts {
			if p.Proto == "" || strings.EqualFold(p.Proto, "tcp") {
				pset[p.Port] = true
			}
		}
		for _, ip := range fwBase.EgressBlocked {
			if n := normIPv4(ip); n != "" {
				eset[n] = true
			}
		}
	}
	for _, a := range fwPending {
		if _, applied := fwOverlay[a.ID]; applied {
			continue
		}
		switch a.Kind {
		case "close_port":
			delete(pset, a.Port)
		case "block_egress":
			delete(eset, normIPv4(a.IP))
		}
	}
	ids := make([]int64, 0, len(fwOverlay))
	for id := range fwOverlay {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		a := fwOverlay[id]
		switch a.Kind {
		case "close_port":
			pset[a.Port] = true
		case "open_port":
			delete(pset, a.Port)
		case "block_egress":
			eset[a.IP] = true
		case "unblock_egress":
			delete(eset, a.IP)
		}
	}
	for p := range pset {
		ports = append(ports, p)
	}
	for ip := range eset {
		egress = append(egress, ip)
	}
	sort.Ints(ports)
	sort.Strings(egress)
	return ports, egress
}

// normIPv4 returns ip in canonical IPv4 form, or "" (egress blocks are IPv4
// only).
func normIPv4(ip string) string {
	if p := net.ParseIP(strings.TrimSpace(ip)); p != nil && p.To4() != nil {
		return p.To4().String()
	}
	return ""
}

// fwChecks is what the refusals look at, read once per render: sshd -T,
// the listeners, resolvers and sockets cost a process start or a /proc walk
// each.
type fwChecks struct {
	ssh, web  map[int]bool
	resolvers map[string]bool
	dashboard map[string]bool
	sessions  map[string]bool // clients of the SSH sessions logged in now
	socks     []netstate.Conn
	socksRead bool
}

func newFwChecks() *fwChecks {
	c := &fwChecks{ssh: map[int]bool{}, web: map[int]bool{}}
	for _, p := range fwSSHPorts() {
		c.ssh[p] = true
	}
	for _, p := range fwWebPorts() {
		c.web[p] = true
	}
	return c
}

func (c *fwChecks) sockets() []netstate.Conn {
	if !c.socksRead {
		c.socks, c.socksRead = fwSockets(), true
	}
	return c.socks
}

// portRefusal returns why port may not be closed, or "". With live set (a
// new request), connections open right now count too.
func portRefusal(c *fwChecks, port int, live bool) (reason, message string) {
	switch {
	case port == 22 || c.ssh[port]:
		return "ssh_port", fmt.Sprintf("port %d is an SSH port", port)
	case port == 80 || port == 443 || c.web[port]:
		return "web_port", fmt.Sprintf("port %d is a web port", port)
	case !closablePorts[port]:
		return "not_closable", fmt.Sprintf("port %d is not a database, cache or admin service port the agent closes by itself", port)
	}
	if live {
		if ips := fwPublicInbound(port); len(ips) > 0 {
			return "established_connection", fmt.Sprintf("%d public address(es) connected to port %d right now", len(ips), port)
		}
	}
	return "", ""
}

// egressRefusal returns why ip may not be blocked for egress, or "". With
// live set (a new request, or a state entry not enforced yet) the address
// must also have been flagged by this agent and not be connected to this
// server right now.
func egressRefusal(c *fwChecks, ip string, live bool) (reason, message string) {
	if r := fwEgressRefusal(ip); r != "" {
		return r, fmt.Sprintf("%s may not be blocked (%s)", ip, r)
	}
	p := net.ParseIP(ip).To4()
	s := p.String()
	if c.dashboard == nil {
		c.dashboard = fwDashboardIPs()
	}
	if c.dashboard[s] {
		return "dashboard_api", fmt.Sprintf("%s is an address of the dashboard API", ip)
	}
	if c.resolvers == nil {
		c.resolvers = fwResolvers()
	}
	if c.resolvers[s] {
		return "dns_resolver", fmt.Sprintf("%s is a DNS resolver of this server", ip)
	}
	if c.sessions == nil {
		c.sessions = map[string]bool{}
		for _, a := range fwSSHSessions() {
			c.sessions[a] = true
		}
	}
	if c.sessions[s] {
		return "ssh_client", fmt.Sprintf("%s is logged in over SSH right now", ip)
	}
	if fwSSHLoginSeen(s) {
		return "ssh_login", fmt.Sprintf("an SSH login came from %s in the last 30 days", ip)
	}
	listening := map[int]bool{}
	for _, k := range c.sockets() {
		if k.State == 0x0A {
			listening[k.LocalPort] = true
		}
	}
	for _, k := range c.sockets() {
		// A connection to an SSH port shields nobody by itself: only a
		// logged-in session does (above). A brute force keeps many
		// connections open while it guesses.
		if k.State != 0x01 || !k.RemoteIP.Equal(p) || c.ssh[k.LocalPort] {
			continue
		}
		if live && listening[k.LocalPort] {
			return "established_connection", fmt.Sprintf("%s is connected to port %d of this server right now", ip, k.LocalPort)
		}
	}
	if live && !fwFlagged(s) {
		return "not_flagged", fmt.Sprintf("%s was not flagged as a threat by this server in the last 24 hours", ip)
	}
	return "", ""
}

// applyFirewallActions handles the requests not seen before, one at a time.
// A sync arriving while requests run starts nothing: the requests it lists
// that are still new are handled at the next sync.
func applyFirewallActions(client *api.Client, actions []api.FirewallAction) {
	if !fwActRunning.CompareAndSwap(false, true) {
		return
	}
	defer fwActRunning.Store(false)
	fwActMu.Lock()
	defer fwActMu.Unlock()
	pending := map[int64]bool{}
	ran := 0
	for _, a := range actions {
		pending[a.ID] = true
		fwStateMu.Lock()
		seen := fwDone[a.ID]
		unsent, resend := fwUnsent[a.ID]
		if !seen && ran >= maxActionsPerSync {
			// Handled at a next sync.
			fwStateMu.Unlock()
			continue
		}
		fwDone[a.ID] = true
		fwStateMu.Unlock()
		var ev api.EventRequest
		switch {
		case resend:
			ev = unsent
		case seen:
			continue
		default:
			ran++
			typ, severity, details := runFirewallAction(a)
			log.Printf("[firewall] action %d %s: %s %s", a.ID, a.Kind, details["status"], details["message"])
			ev = api.EventRequest{Type: typ, Severity: severity, Details: details, OccurredAt: time.Now().UTC().Format(time.RFC3339)}
		}
		err := fwReport(client, ev)
		fwStateMu.Lock()
		if err != nil {
			log.Printf("[firewall] action %d: result not delivered, sent again at the next sync: %v", a.ID, err)
			fwUnsent[a.ID] = ev
		} else {
			delete(fwUnsent, a.ID)
		}
		fwStateMu.Unlock()
	}
	// Requests the dashboard no longer lists are settled.
	fwStateMu.Lock()
	for id := range fwDone {
		if !pending[id] {
			delete(fwDone, id)
			delete(fwUnsent, id)
		}
	}
	fwStateMu.Unlock()
}

// Replaced in tests. Sent outside the event queue: a result not delivered
// is sent again at the next sync.
var fwReport = func(client *api.Client, ev api.EventRequest) error {
	if client == nil {
		return nil
	}
	return client.DeliverEvents([]api.EventRequest{ev})
}

// runFirewallAction applies one request and returns its result event.
func runFirewallAction(a api.FirewallAction) (typ, severity string, details map[string]string) {
	details = map[string]string{"action_id": strconv.FormatInt(a.ID, 10), "kind": a.Kind}
	result := func(status, reason, msg string, v *verify.Result) (string, string, map[string]string) {
		details["status"] = status
		details["message"] = msg
		if reason != "" {
			details["reason"] = reason
		}
		if v != nil {
			details["verify"] = verifyJSON(*v)
		}
		switch status {
		case "done":
			return "firewall_action_done", "info", details
		case "rolled_back":
			return "firewall_action_rolled_back", "warning", details
		}
		return "firewall_action_failed", "warning", details
	}

	switch a.Kind {
	case "close_port", "open_port":
		proto := strings.ToLower(a.Proto)
		if proto == "" {
			proto = "tcp"
		}
		details["port"], details["proto"] = strconv.Itoa(a.Port), proto
		if a.Port < 1 || a.Port > 65535 {
			return result("failed", "invalid", "invalid port", nil)
		}
		if proto != "tcp" {
			return result("failed", "unsupported_proto", "only TCP ports can be closed", nil)
		}
	case "block_egress", "unblock_egress":
		details["ip"] = a.IP
		p := net.ParseIP(strings.TrimSpace(a.IP))
		if p == nil {
			return result("failed", "invalid", "invalid address", nil)
		}
		if p.To4() == nil {
			return result("failed", "ipv6_unsupported", "egress blocks are IPv4 only", nil)
		}
		a.IP = p.To4().String()
		details["ip"] = a.IP
	default:
		return result("failed", "unsupported_kind", "unknown firewall action "+a.Kind, nil)
	}

	fwStateMu.Lock()
	monitorMode := fwMonitor
	ports, egress := effectiveFirewall()
	fwStateMu.Unlock()
	if monitorMode {
		return result("skipped", "monitor_mode", "monitor mode: nothing changed", nil)
	}

	// Refusals, and requests that are already in force.
	checks := newFwChecks()
	switch a.Kind {
	case "close_port":
		if reason, msg := portRefusal(checks, a.Port, true); reason != "" {
			return result("failed", reason, "refused: "+msg, nil)
		}
		if containsInt(ports, a.Port) && firewallHasPort(a.Port) {
			if ipv6Exposed(a.Port) {
				typ, sev, d := result("done", "", ipv6ExposedMessage, nil)
				b, _ := json.Marshal(map[string]any{"details": "already closed, nothing changed", "ipv6_exposed": true})
				d["verify"] = string(b)
				return typ, sev, d
			}
			return result("done", "", fmt.Sprintf("port %d already closed", a.Port), nil)
		}
	case "open_port":
		if !containsInt(ports, a.Port) && !firewallHasPort(a.Port) {
			return result("done", "", fmt.Sprintf("port %d is not closed", a.Port), nil)
		}
	case "block_egress":
		if reason, msg := egressRefusal(checks, a.IP, true); reason != "" {
			return result("failed", reason, "refused: "+msg, nil)
		}
		if containsStr(egress, a.IP) && firewallHasEgress(a.IP) {
			return result("done", "", a.IP+" already blocked", nil)
		}
	case "unblock_egress":
		if !containsStr(egress, a.IP) && !firewallHasEgress(a.IP) {
			return result("done", "", a.IP+" is not blocked", nil)
		}
	}

	before := fwSnapshot()
	fwStateMu.Lock()
	fwOverlay[a.ID] = a
	err := renderFirewallLocked()
	fwStateMu.Unlock()
	if err == nil {
		err = checkInForce(a)
	}
	if err != nil {
		undoFirewallAction(a.ID)
		return result("failed", "apply_failed", err.Error(), nil)
	}
	v := fwCheck(before)
	if !v.OK() {
		if uerr := undoFirewallAction(a.ID); uerr != nil {
			return result("failed", "rollback_failed", "verification failed ("+v.Details+") and the rollback failed: "+uerr.Error(), &v)
		}
		return result("rolled_back", "verify_failed", "rolled back: "+v.Details, &v)
	}
	if a.Kind == "close_port" && ipv6Exposed(a.Port) {
		typ, sev, d := result("done", "", ipv6ExposedMessage, nil)
		d["verify"] = verifyJSONWith(v, map[string]any{"ipv6_exposed": true})
		return typ, sev, d
	}
	return result("done", "", doneMessage(a), &v)
}

// ipv6ExposedMessage: the port is closed over IPv4, but ip6tables is missing
// or refused the rules, something listens on a public IPv6 address of the
// socket table ([::] included, a dual-stack socket too) and the host has a
// public IPv6 address. An IPv4-only listener, or a host without public IPv6,
// is not reachable over IPv6.
const ipv6ExposedMessage = "IPv4 only: still reachable over IPv6"

// listensReachableIPv6: something listens on port over IPv6 and the host has
// a public IPv6 address to be reached on.
func listensReachableIPv6(port int) bool {
	return netstate.ListensPublicIPv6(port) && netstate.HasPublicIPv6()
}

func ipv6Exposed(port int) bool {
	if closed, ok := fwPorts6(); ok && containsInt(closed, port) {
		return false
	}
	return fwListens6(port)
}

// verifyJSONWith is verifyJSON with extra fields.
func verifyJSONWith(v verify.Result, extra map[string]any) string {
	m := map[string]any{"ssh_ok": v.SSHOK, "sites_ok": v.SitesOK, "details": v.Details}
	for k, x := range extra {
		m[k] = x
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// undoFirewallAction drops a request from the overlay and re-applies.
func undoFirewallAction(id int64) error {
	fwStateMu.Lock()
	defer fwStateMu.Unlock()
	delete(fwOverlay, id)
	return renderFirewallLocked()
}

// checkInForce confirms the request reached the firewall (a refusal at
// render time, e.g. a port that became an SSH port, leaves it out).
func checkInForce(a api.FirewallAction) error {
	switch a.Kind {
	case "close_port":
		if !firewallHasPort(a.Port) {
			return fmt.Errorf("port %d was not closed", a.Port)
		}
	case "open_port":
		if firewallHasPort(a.Port) {
			return fmt.Errorf("port %d is still closed", a.Port)
		}
	case "block_egress":
		if !firewallHasEgress(a.IP) {
			return fmt.Errorf("%s was not blocked", a.IP)
		}
	case "unblock_egress":
		if firewallHasEgress(a.IP) {
			return fmt.Errorf("%s is still blocked", a.IP)
		}
	}
	return nil
}

// Replaced in tests.
var fwInForce = firewall.PortsEgress

func firewallHasPort(port int) bool {
	ports, _ := fwInForce()
	return containsInt(ports, port)
}

func firewallHasEgress(ip string) bool {
	_, egress := fwInForce()
	return containsStr(egress, ip)
}

func doneMessage(a api.FirewallAction) string {
	switch a.Kind {
	case "close_port":
		return fmt.Sprintf("port %d/tcp closed to public addresses", a.Port)
	case "open_port":
		return fmt.Sprintf("port %d/tcp open again", a.Port)
	case "block_egress":
		return "connections to " + a.IP + " blocked"
	}
	return "connections to " + a.IP + " allowed again"
}

func containsInt(s []int, v int) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
