package main

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/firewall"
	"github.com/infrafence/infrafence-agent/internal/monitor"
)

// What the closed-port and egress code keeps across restarts, in
// /var/lib/infrafence/firewall-state.json (0600, replaced atomically):
//
//   - the ports closed and the addresses blocked for egress, as last
//     enforced: loaded at startup before the first firewall setup, so they
//     stay closed/blocked across a restart and while the dashboard cannot be
//     reached (re-checked through the same refusals first);
//   - the addresses this agent flagged as a threat (egress_threat_match,
//     dns_threat_answer), for 24 hours: egress is only ever blocked to one;
//   - the addresses SSH logins came from (session events and the login
//     records), for 30 days: never blocked.

var fwStatePath = "/var/lib/infrafence/firewall-state.json"

const (
	flaggedFor   = 24 * time.Hour
	sshLoginFor  = 30 * 24 * time.Hour
	maxFlagged   = 5000
	maxSSHLogins = 1000
	// A known address is written again only after this long.
	memoRefresh = time.Hour
)

type fwPersisted struct {
	ClosedPorts   []int            `json:"closed_ports"`
	EgressBlocked []string         `json:"egress_blocked"`
	Flagged       map[string]int64 `json:"flagged,omitempty"`    // address -> unix time last flagged
	SSHLogins     map[string]int64 `json:"ssh_logins,omitempty"` // address -> unix time of the last login
}

var (
	memoMu    sync.Mutex
	flagged   = map[string]int64{}
	sshLogins = map[string]int64{}
)

// Replaced in tests.
var fwNow = time.Now

// noteEgressEvent remembers, from every event the agent reports, the
// addresses it flagged as a threat and the addresses SSH logins came from.
func noteEgressEvent(e api.EventRequest) {
	switch {
	case e.Type == "egress_threat_match" || e.Type == "dns_threat_answer":
		if ip := normIPv4(e.SourceIP); ip != "" {
			noteAddr(flagged, ip, maxFlagged)
		}
	case e.Type == "ssh_session" || e.Type == "system_audit" && e.Details["operation"] == "ssh_login":
		ip := e.SourceIP
		if ip == "" {
			ip = e.Details["ip"]
		}
		if p := net.ParseIP(strings.TrimSpace(ip)); p != nil {
			noteAddr(sshLogins, p.String(), maxSSHLogins)
		}
	}
}

func noteAddr(m map[string]int64, ip string, max int) { noteAddrs(m, []string{ip}, max) }

// noteAddrs records the addresses as seen now and saves the state when one
// is new or was last written more than memoRefresh ago.
func noteAddrs(m map[string]int64, ips []string, max int) {
	now := fwNow().Unix()
	changed := false
	memoMu.Lock()
	for _, ip := range ips {
		if last, known := m[ip]; known && now-last < int64(memoRefresh/time.Second) {
			continue
		}
		m[ip] = now
		changed = true
	}
	if len(m) > max {
		dropOldest(m, len(m)-max)
	}
	memoMu.Unlock()
	if changed {
		saveFirewallState()
	}
}

// watchSSHLogins adds, at startup and every hour, the addresses of the SSH
// logins the login records (wtmp, wtmpdb) list for the last 30 days: the
// session tracker only sees logins while it is turned on.
func watchSSHLogins() {
	for {
		if ips := parseLastIPs(lastLogins()); len(ips) > 0 {
			noteAddrs(sshLogins, ips, maxSSHLogins)
		}
		time.Sleep(time.Hour)
	}
}

// lastLogins is replaced in tests.
var lastLogins = func() string {
	if _, err := exec.LookPath("last"); err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "last", "-i", "--since", "-30days").Output()
	return string(out)
}

// parseLastIPs reads the address column of `last -i` ("root pts/0
// 198.51.100.7 Mon Oct 12 10:00 still logged in"); local logins show
// 0.0.0.0 or ::.
func parseLastIPs(out string) []string {
	seen := map[string]bool{}
	var ips []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		p := net.ParseIP(f[2])
		if p == nil || p.IsUnspecified() || p.IsLoopback() || seen[p.String()] {
			continue
		}
		seen[p.String()] = true
		ips = append(ips, p.String())
	}
	return ips
}

func dropOldest(m map[string]int64, n int) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return m[keys[i]] < m[keys[j]] })
	for _, k := range keys[:n] {
		delete(m, k)
	}
}

func seenWithin(m map[string]int64, ip string, d time.Duration) bool {
	memoMu.Lock()
	defer memoMu.Unlock()
	t, ok := m[ip]
	return ok && fwNow().Sub(time.Unix(t, 0)) < d
}

// Replaced in tests.
var (
	fwFlagged = func(ip string) bool {
		return seenWithin(flagged, ip, flaggedFor) || firewall.InThreatSet(ip)
	}
	fwSSHLoginSeen = func(ip string) bool { return seenWithin(sshLogins, ip, sshLoginFor) }
)

// saveFirewallState writes the persisted state. Callers must not hold
// memoMu; fwStateMu may be held.
var saveFirewallState = func() {
	st := fwPersisted{Flagged: map[string]int64{}, SSHLogins: map[string]int64{}}
	appliedMu.Lock()
	for p := range fwAppliedPorts {
		st.ClosedPorts = append(st.ClosedPorts, p)
	}
	for ip := range fwAppliedEgress {
		st.EgressBlocked = append(st.EgressBlocked, ip)
	}
	appliedMu.Unlock()
	sort.Ints(st.ClosedPorts)
	sort.Strings(st.EgressBlocked)
	now := fwNow()
	memoMu.Lock()
	for ip, t := range flagged {
		if now.Sub(time.Unix(t, 0)) < flaggedFor {
			st.Flagged[ip] = t
		}
	}
	for ip, t := range sshLogins {
		if now.Sub(time.Unix(t, 0)) < sshLoginFor {
			st.SSHLogins[ip] = t
		}
	}
	memoMu.Unlock()
	if err := writeFileAtomic(fwStatePath, st); err != nil {
		log.Printf("[firewall] save %s: %v", fwStatePath, err)
	}
}

func writeFileAtomic(path string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Chmod(0600)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}

// loadFirewallState reads the persisted state, re-checks the ports and
// egress blocks through the same refusals as the dashboard's state (the
// checks that only apply to new requests excepted) and hands what passes to
// the firewall, to be applied by its first setup. Call it before
// firewall.Init.
func loadFirewallState() {
	data, err := os.ReadFile(fwStatePath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[firewall] read %s: %v", fwStatePath, err)
		}
		return
	}
	var st fwPersisted
	if err := json.Unmarshal(data, &st); err != nil {
		log.Printf("[firewall] %s is not valid, ignored: %v", fwStatePath, err)
		return
	}
	memoMu.Lock()
	for ip, t := range st.Flagged {
		if p := normIPv4(ip); p != "" {
			flagged[p] = t
		}
	}
	for ip, t := range st.SSHLogins {
		if p := net.ParseIP(ip); p != nil {
			sshLogins[p.String()] = t
		}
	}
	memoMu.Unlock()

	state := &api.FirewallState{EgressBlocked: st.EgressBlocked}
	for _, p := range st.ClosedPorts {
		state.ClosedPorts = append(state.ClosedPorts, api.PortProto{Port: p, Proto: "tcp"})
	}
	fwStateMu.Lock()
	defer fwStateMu.Unlock()
	appliedMu.Lock()
	for _, p := range st.ClosedPorts {
		fwAppliedPorts[p] = true
	}
	for _, ip := range st.EgressBlocked {
		if n := normIPv4(ip); n != "" {
			fwAppliedEgress[n] = true
		}
	}
	appliedMu.Unlock()
	fwBase = state
	ports, egress := renderChecked()
	skipped := firewall.LoadPortsEgress(ports, egress)
	if len(skipped) > 0 {
		log.Printf("[firewall] saved egress entries not applied: %s", strings.Join(skipped, ", "))
	}
	setApplied(ports, egress, skipped)
	if len(ports)+len(egress) > 0 {
		log.Printf("[firewall] restored from %s: %d closed port(s), %d egress block(s)", fwStatePath, len(ports), len(egress))
	}
}

// dashboardIPs are the addresses of the dashboard API: resolved at startup
// and every 10 minutes, plus every address the API client connected to.
var (
	dashMu       sync.Mutex
	dashboardIPs = map[string]bool{}
)

// Replaced in tests.
var fwDashboardIPs = func() map[string]bool {
	out := map[string]bool{}
	dashMu.Lock()
	for ip := range dashboardIPs {
		out[ip] = true
	}
	dashMu.Unlock()
	if c := currentAPIClient.Load(); c != nil {
		for _, ip := range c.PeerIPs() {
			out[ip] = true
		}
	}
	return out
}

// watchDashboardAddrs resolves the API host now and every 10 minutes; every
// address it ever had stays protected (bans and egress blocks).
func watchDashboardAddrs(serverURL string) {
	u, err := url.Parse(serverURL)
	if err != nil || u.Hostname() == "" {
		return
	}
	resolve := func() {
		var ips []string
		if ip := net.ParseIP(u.Hostname()); ip != nil {
			ips = []string{ip.String()}
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			addrs, err := net.DefaultResolver.LookupHost(ctx, u.Hostname())
			cancel()
			if err != nil {
				return
			}
			ips = addrs
		}
		if c := currentAPIClient.Load(); c != nil {
			ips = append(ips, c.PeerIPs()...)
		}
		var added []string
		dashMu.Lock()
		for _, ip := range ips {
			if p := net.ParseIP(ip); p != nil && !dashboardIPs[p.String()] {
				dashboardIPs[p.String()] = true
				added = append(added, p.String())
			}
		}
		dashMu.Unlock()
		if len(added) > 0 {
			firewall.AddProtectedIPs(added...)
		}
	}
	resolve()
	for range time.Tick(10 * time.Minute) {
		resolve()
	}
}

// configuredResolvers adds to the resolv.conf files the upstream servers
// systemd-resolved uses (resolvectl), which /etc/resolv.conf hides behind
// its local stub.
func configuredResolvers() map[string]bool {
	out := monitor.ConfiguredResolvers()
	for ip := range parseResolvectl(resolvectlDNS()) {
		out[ip] = true
	}
	return out
}

// resolvectlDNS is replaced in tests.
var resolvectlDNS = func() string {
	if _, err := exec.LookPath("resolvectl"); err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "resolvectl", "dns").Output()
	return string(out)
}

// parseResolvectl reads "Global: 1.1.1.1#one.one.one.one" and
// "Link 2 (eth0): 192.0.2.53 fe80::1%eth0" lines.
func parseResolvectl(out string) map[string]bool {
	ips := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		_, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		// "Link 2 (eth0): ..." — the first colon ends the label (an IPv6
		// address has colons but never comes before it).
		for _, w := range strings.Fields(rest) {
			w, _, _ = strings.Cut(w, "#")
			w, _, _ = strings.Cut(w, "%")
			if p := net.ParseIP(w); p != nil {
				ips[p.String()] = true
			}
		}
	}
	return ips
}
