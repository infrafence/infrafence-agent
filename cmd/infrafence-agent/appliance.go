package main

// Appliance mode: the agent on an OPNsense firewall (FreeBSD build).
//
// It starts none of the server agent's goroutines. What runs: register,
// heartbeat, sync, realtime push, the pf tables (internal/pf) and the
// OPNsense log readers (internal/opnsense). It never changes the
// firewall's configuration: it only fills its own three pf tables, which
// the os-infrafence plugin declares (External aliases) and references
// from block-only rules. Without them it blocks nothing and reports
// detect-only.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/config"
	"github.com/infrafence/infrafence-agent/internal/geoip"
	"github.com/infrafence/infrafence-agent/internal/opnsense"
	"github.com/infrafence/infrafence-agent/internal/pf"
	"github.com/infrafence/infrafence-agent/internal/platform"
	"github.com/infrafence/infrafence-agent/internal/scanwatch"
	"github.com/infrafence/infrafence-agent/internal/ws"
)

// Paths of the appliance build (FreeBSD hier(7): state in /var/db, runtime
// files in /var/run). Variables so the tests can move them.
var (
	applianceStateDir = "/var/db/infrafence"
	applianceRunDir   = "/var/run/infrafence"
	applianceConfXML  = opnsense.ConfigPath
	applianceGeoIPDir = "/usr/local/share/GeoIP/alias"
	appliancePfctl    = "/sbin/pfctl"
)

func applianceStatusPath() string { return filepath.Join(applianceRunDir, "status.json") }
func appliancePidPath() string    { return filepath.Join(applianceRunDir, "agent.pid") }
func applianceBansPath() string   { return filepath.Join(applianceStateDir, "pf-state.json") }
func applianceLoginsPath() string { return filepath.Join(applianceStateDir, "admin-logins.json") }

// applianceCapabilities: what the dashboard may show and offer for this
// agent; everything else (WAF, malware, hardening, packages, ports,
// egress, rules, self-update) is hidden.
var applianceCapabilities = []string{
	"bans", "network_bans", "allowlist", "threat_feed", "geoblock",
	"brute_force", "port_scan", "ids", "fw_blocks", "findings", "mode_switch",
}

const (
	applianceBanFor       = 24 * time.Hour // local bans, as on servers
	applianceLoginExempt  = 30 * 24 * time.Hour
	applianceIDSPerHour   = 600 // ids_alert events at most per hour
	applianceIDSDedup     = 10 * time.Minute
	applianceSummaryEvery = 5 * time.Minute
	applianceChecksEvery  = 6 * time.Hour
)

// appliance is the running agent's state.
type appliance struct {
	cfg    *config.Config
	client *api.Client
	info   platform.Info
	ctl    *pf.Ctl
	store  *pf.Store
	guard  *opnsense.Guard
	agg    *opnsense.Aggregator
	scans  *scanwatch.Analyzer
	bf     *opnsense.Counter
	geo    *geoip.Lookup
	geoUpd *geoip.Updater
	syncs  *syncRunner
	now    func() time.Time

	mu            sync.Mutex
	conf          *opnsense.Config
	confMod       time.Time
	dashIPs       []string
	dashResolved  time.Time
	liveRoutes    bool // read the routing table and DNS (off in tests)
	allow         []string
	countries     []string
	geoSource     string
	threat        []string
	threatOn      bool
	scanOn        bool
	scanBan       bool
	logins        map[string]time.Time
	findings      []opnsense.Finding
	firmware      *opnsense.Firmware
	lastBlocks    *opnsense.BlockSummary
	lastHeartbeat time.Time
	lastSync      time.Time
	lastSyncErr   string
	updateAvail   string
	pfEnabled     bool
	protection    string // "active", "learning", "detect_only"
	protWhy       string
	idsSent       int
	idsWindow     time.Time
	idsDropped    int
	idsSeen       map[string]time.Time
	spoofSent     int
	spoofWindow   time.Time
	gwCache       []string
	gwAt          time.Time
}

func newAppliance(cfg *config.Config, client *api.Client, run pf.Runner) *appliance {
	a := &appliance{cfg: cfg, client: client, now: time.Now, guard: opnsense.NewGuard(),
		bf: opnsense.NewCounter(5, 10*time.Minute), logins: map[string]time.Time{}, idsSeen: map[string]time.Time{},
		scanOn: true}
	a.ctl = pf.NewCtl(run)
	a.store = pf.NewStore(a.ctl, a.guard, applianceBansPath())
	a.agg = opnsense.NewAggregator(nil, a.now())
	a.scans = scanwatch.NewAnalyzer(func(ip net.IP) bool { return a.store.Why(ip.String()) != "" })
	return a
}

// runAppliance is "infrafence-agent start" on FreeBSD.
func runAppliance() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v\nRegister first (Services › InfraFence in the OPNsense GUI).", err)
	}
	info := platform.Detect("/", platform.FreeBSDKernel)
	if info.Kind != platform.KindOPNsense {
		log.Printf("[appliance] not an OPNsense host: running on plain FreeBSD pf (tables %s must be declared by your ruleset)", strings.Join(pf.Tables, ", "))
	}
	for _, d := range []string{applianceStateDir, applianceRunDir} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			log.Fatalf("[appliance] %s: %v", d, err)
		}
	}
	// The SIGHUP handler before the pid file: "appliance mode" signals the
	// pid in it, and an unhandled SIGHUP would kill the agent.
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	_ = os.WriteFile(appliancePidPath(), []byte(strconv.Itoa(os.Getpid())+"\n"), 0o640)

	client := api.New(cfg.ServerURL, cfg.AgentToken)
	currentAPIClient.Store(client)
	client.SetVersion(version)
	client.SetEventSpool(filepath.Join(applianceStateDir, "unsent-events.json"))
	a := newAppliance(cfg, client, pf.ExecRunner(appliancePfctl))
	a.info = info
	a.liveRoutes = true
	client.SetEventEnricher(func(e *api.EventRequest) {
		var country func(string) string
		if g := geoLookup.Load(); g != nil {
			country = g.Country
		}
		enrichEvent(e, country)
	})
	log.Printf("Starting InfraFence agent v%s, appliance mode (%s %s, agent_id=%d)", version, info.Product, info.Version, cfg.AgentID)

	a.geo = geoip.New(os.Getenv("GEOIP_DB_PATH"))
	geoLookup.Store(a.geo)
	a.loadLogins()
	a.resolveDashboard()
	a.refreshConfig(true)
	if n := a.store.Load(); n > 0 {
		log.Printf("[pf] %d bans restored from %s", n, applianceBansPath())
	}
	a.guardTick()

	a.syncs = newSyncRunner(a.sync)
	go a.syncs.Loop(context.Background())
	push := &pushListener{runner: a.syncs}
	a.startGeoUpdater()
	_ = a.syncs.Now("initial")

	if cfg.ReverbURL != "" {
		wsClient := ws.New(cfg.ReverbURL, cfg.ReverbAppKey, cfg.AuthEndpoint, cfg.AgentToken, cfg.AgentID, a.reverbHandlers())
		wsClient.SetGate(client.Gate())
		go wsClient.Run()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.every(ctx, 60*time.Second, func() { a.heartbeat(push) })
	go a.every(ctx, 60*time.Second, a.guardTick)
	go a.every(ctx, 30*time.Second, func() { a.expire(a.now()) })
	go a.every(ctx, applianceSummaryEvery, func() { a.reportBlocks(a.now()) })
	go a.every(ctx, 5*time.Minute, func() { _ = a.syncs.Now("periodic") })
	go a.every(ctx, 10*time.Minute, func() { now := a.now(); a.bf.Prune(now); a.scans.Prune(now) })
	go func() {
		time.Sleep(2 * time.Minute)
		a.runChecks(ctx)
		a.every(ctx, applianceChecksEvery, func() { a.runChecks(ctx) })
	}()
	a.startLogReaders(ctx)
	a.writeStatus()
	a.heartbeat(push)

	for s := range sig {
		if s == syscall.SIGHUP {
			// "infrafence-agent appliance mode" after a mode change, or a
			// plugin reconfigure: sync and re-read config.xml now.
			a.refreshConfig(true)
			if a.syncs != nil {
				a.syncs.Request("SIGHUP")
			}
			continue
		}
		break
	}
	log.Println("Shutting down (the pf tables keep their contents)...")
	cancel()
	a.saveLogins()
	fctx, fcancel := context.WithTimeout(context.Background(), eventFlushTimeout)
	defer fcancel()
	if err := client.CloseEvents(fctx); err != nil {
		log.Printf("[api] shutdown: events not delivered: %v", err)
	}
	_ = os.Remove(appliancePidPath())
}

func (a *appliance) every(ctx context.Context, d time.Duration, fn func()) {
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fn()
		}
	}
}

// resolveDashboard protects the dashboard's addresses: banning them would
// cut the agent off.
func (a *appliance) resolveDashboard() {
	u, err := url.Parse(a.cfg.ServerURL)
	if err != nil {
		return
	}
	ips, err := net.LookupHost(u.Hostname())
	if err != nil {
		log.Printf("[appliance] could not resolve %s: %v", u.Hostname(), err)
		return
	}
	a.mu.Lock()
	a.dashIPs, a.dashResolved = ips, a.now()
	a.mu.Unlock()
}

// refreshConfig re-reads config.xml when it changed (force: always) and
// rebuilds the protected addresses.
func (a *appliance) refreshConfig(force bool) {
	st, err := os.Stat(applianceConfXML)
	var conf *opnsense.Config
	a.mu.Lock()
	changed := err == nil && (force || !st.ModTime().Equal(a.confMod))
	conf = a.conf
	a.mu.Unlock()
	if changed {
		c, err := opnsense.LoadConfig(applianceConfXML)
		if err != nil {
			log.Printf("[appliance] %s: %v (keeping the last good one)", applianceConfXML, err)
		} else {
			conf = c
			a.mu.Lock()
			a.conf, a.confMod = c, st.ModTime()
			a.mu.Unlock()
		}
	}
	entries := opnsense.GuardEntries(conf, opnsense.OwnAddresses())
	for _, gw := range a.gateways() {
		entries = append(entries, opnsense.GuardEntry{CIDR: gw, Why: "a gateway of this firewall"})
	}
	a.mu.Lock()
	for _, ip := range a.dashIPs {
		entries = append(entries, opnsense.GuardEntry{CIDR: ip, Why: "the InfraFence dashboard"})
	}
	now := a.now()
	for ip, t := range a.logins {
		if now.Sub(t) < applianceLoginExempt {
			entries = append(entries, opnsense.GuardEntry{CIDR: ip, Why: "an administrator logged in from this address in the last 30 days"})
		}
	}
	a.mu.Unlock()
	a.guard.Set(entries)
	if conf != nil {
		var devs []string
		for _, n := range conf.ExternalNames() {
			if it, ok := conf.Interface(n); ok && it.Device != "" {
				devs = append(devs, it.Device)
			}
		}
		a.agg.SetDevices(devs)
	}
}

// gateways are the live default routes' next hops (tests: none).
func (a *appliance) gateways() []string {
	if !a.liveRoutes {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.gwAt.IsZero() || a.now().Sub(a.gwAt) > time.Minute {
		a.gwCache, a.gwAt = opnsense.DefaultGateways(), a.now()
	}
	return a.gwCache
}

// guardTick checks pf and the tables, refilling what drifted.
func (a *appliance) guardTick() {
	a.mu.Lock()
	resolve := a.liveRoutes && (len(a.dashIPs) == 0 || a.now().Sub(a.dashResolved) > 30*time.Minute)
	a.mu.Unlock()
	if resolve {
		a.resolveDashboard()
	}
	a.refreshConfig(false)
	enabled, err := a.ctl.Enabled()
	if err != nil {
		log.Printf("[pf] %v", err)
	}
	repaired, err := a.store.Ensure()
	state, why := "active", ""
	switch {
	case !enabled:
		state, why = "detect_only", "pf is disabled (Firewall › Settings › Advanced: Disable Firewall)"
	case err == pf.ErrNoTables:
		state, why = "detect_only", "no loaded rule uses the InfraFence tables: enable os-infrafence (Services › InfraFence) or reload the filter"
	case err != nil:
		state, why = "detect_only", err.Error()
	case a.store.Monitor():
		state = "learning"
	}
	a.mu.Lock()
	prev := a.protection
	a.protection, a.protWhy, a.pfEnabled = state, why, enabled
	a.mu.Unlock()
	if len(repaired) > 0 {
		log.Printf("[pf] refilled %s", strings.Join(repaired, ", "))
	}
	if prev != state || len(repaired) > 0 {
		a.writeStatus() // the GUI's Status tab sees it at once
	}
	if prev != state && (state == "detect_only" || prev == "detect_only") {
		sev := "warning"
		if state != "detect_only" {
			sev = "info"
		}
		log.Printf("[appliance] protection %s %s", state, why)
		a.report(api.EventRequest{Type: "appliance_protection", Severity: sev,
			Details: map[string]string{"state": state, "reason": why, "previous": prev}})
	}
	if len(repaired) > 0 && prev != "" && state == "active" {
		a.report(api.EventRequest{Type: "appliance_protection", Severity: "info",
			Details: map[string]string{"state": "repaired", "tables": strings.Join(repaired, ",")}})
	}
}

func (a *appliance) report(e api.EventRequest) {
	if e.OccurredAt == "" {
		e.OccurredAt = a.now().UTC().Format(time.RFC3339)
	}
	if err := a.client.ReportEvents([]api.EventRequest{e}); err != nil {
		log.Printf("[api] event %s not queued: %v", e.Type, err)
	}
}

// sync applies the dashboard's configuration.
func (a *appliance) sync() error {
	resp, err := a.client.Sync()
	if err != nil {
		if wait, busy := retryLater(err); busy {
			// 429: the dashboard asks to come back later. Not an error,
			// never a refusal: retried at the time it gave.
			log.Printf("[sync] the dashboard is busy (429): next sync in %s", wait.Round(time.Second))
			if a.syncs != nil {
				a.syncs.ScheduleAt(a.now().Add(wait), "retry after 429")
			}
			return nil
		}
		a.mu.Lock()
		a.lastSyncErr = err.Error()
		a.mu.Unlock()
		a.writeStatus()
		return err
	}
	c := resp.Config
	learning := c.MonitorMode || c.Suspended
	if learning != a.store.Monitor() {
		if learning {
			log.Printf("[appliance] Learning mode: the InfraFence tables are emptied, nothing is blocked")
		} else {
			log.Printf("[appliance] Full protection")
		}
	}
	a.store.SetMonitor(learning)
	a.mu.Lock()
	if a.protection != "detect_only" {
		a.protection = map[bool]string{true: "learning", false: "active"}[learning]
	}
	a.mu.Unlock()
	a.bf.Set(c.BFThreshold, time.Duration(c.BFWindow)*time.Second)

	var allow []string
	for _, w := range resp.Whitelists {
		if w.IPAddress != nil {
			allow = append(allow, *w.IPAddress)
		}
		if w.IPRange != nil {
			allow = append(allow, *w.IPRange)
		}
	}
	a.store.SetAllowList(allow)

	var bans []pf.Ban
	for _, b := range resp.Bans {
		pb := pf.Ban{IP: b.IPAddress, Reason: b.Reason}
		if b.ExpiresAt != nil {
			if t, ok := parseBanExpiry(*b.ExpiresAt); ok {
				pb.Expires = t
			}
		}
		bans = append(bans, pb)
	}
	added, removed := a.store.SyncBans(bans)
	if added+removed > 0 {
		log.Printf("[sync] bans: %d added, %d removed", added, removed)
	}

	threatOn := c.MonitorConfig != nil && c.MonitorConfig.BlockThreatFeeds
	var threat []string
	for _, t := range resp.ThreatFeed {
		switch {
		case t.CIDR != nil && *t.CIDR != "":
			threat = append(threat, *t.CIDR)
		case t.IP != nil && *t.IP != "":
			threat = append(threat, *t.IP)
		}
	}
	if threatOn {
		_ = a.store.SetSet(pf.TableThreat, threat)
	} else {
		_ = a.store.SetSet(pf.TableThreat, nil)
	}

	scanOn := c.MonitorConfig == nil || c.MonitorConfig.PortScanDetection == nil || *c.MonitorConfig.PortScanDetection
	scanBan := c.MonitorConfig != nil && c.MonitorConfig.PortScanBan

	countries := normCountries(c.BlockedCountries)
	a.mu.Lock()
	a.allow, a.threat, a.threatOn, a.scanOn, a.scanBan = allow, threat, threatOn, scanOn, scanBan
	geoChanged := strings.Join(countries, ",") != strings.Join(a.countries, ",")
	a.countries = countries
	a.lastSync, a.lastSyncErr = a.now(), ""
	a.mu.Unlock()
	if geoChanged || a.geoSourceIs("") {
		a.applyCountries()
	}
	a.writeStatus()
	return nil
}

func (a *appliance) geoSourceIs(s string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.geoSource == s && len(a.countries) > 0
}

func normCountries(in []string) []string {
	var out []string
	for _, c := range in {
		c = strings.ToUpper(strings.TrimSpace(c))
		if len(c) == 2 && c[0] >= 'A' && c[0] <= 'Z' && c[1] >= 'A' && c[1] <= 'Z' {
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out
}

// applyCountries fills the country table from OPNsense's own GeoIP alias
// data (Firewall › Aliases › GeoIP settings, IPv4 and IPv6) when it is
// there, else from the agent's country database (IPv4 only), downloaded
// from the dashboard while a country is blocked.
func (a *appliance) applyCountries() {
	a.mu.Lock()
	countries := append([]string(nil), a.countries...)
	a.mu.Unlock()
	var entries []string
	source := "none"
	if len(countries) > 0 {
		if list, ok := readGeoIPAlias(applianceGeoIPDir, countries); ok {
			entries, source = list, "opnsense-geoip"
		} else if a.geo != nil {
			for _, cc := range countries {
				cidrs, err := a.geo.ExtractCIDRs(cc)
				if err != nil {
					continue
				}
				entries = append(entries, cidrs...)
			}
			if len(entries) > 0 {
				source = "infrafence-geoip"
			} else {
				source = ""
			}
		}
	}
	if a.geoUpd != nil {
		a.geoUpd.Want(len(countries) > 0 && source != "opnsense-geoip")
	}
	if err := a.store.SetSet(pf.TableGeo, entries); err != nil {
		log.Printf("[geo] %v", err)
	}
	a.mu.Lock()
	a.geoSource = source
	a.mu.Unlock()
	if len(countries) > 0 {
		log.Printf("[geo] %d countries blocked (%d networks, source %s)", len(countries), len(entries), source)
	}
}

// readGeoIPAlias reads OPNsense's per-country files (CC-IPv4, CC-IPv6);
// ok when every country has at least one.
func readGeoIPAlias(dir string, countries []string) ([]string, bool) {
	var out []string
	for _, cc := range countries {
		found := false
		for _, proto := range []string{"IPv4", "IPv6"} {
			data, err := os.ReadFile(filepath.Join(dir, cc+"-"+proto))
			if err != nil {
				continue
			}
			found = true
			for _, l := range strings.Split(string(data), "\n") {
				if l = strings.TrimSpace(l); l != "" {
					out = append(out, l)
				}
			}
		}
		if !found {
			return nil, false
		}
	}
	return out, true
}

func (a *appliance) startGeoUpdater() {
	if os.Getenv("GEOIP_DB_PATH") != "" || a.geo == nil {
		return
	}
	fetch := func(ctx context.Context, etag string, w io.Writer, maxBytes int64) (bool, time.Duration, error) {
		d, err := a.client.DownloadGeoIP(ctx, etag, w, maxBytes)
		if err != nil {
			_, retryAfter := api.HTTPStatus(err)
			return false, retryAfter, err
		}
		return d.NotModified, 0, nil
	}
	a.geoUpd = geoip.NewUpdater(a.geo, filepath.Join(applianceStateDir, "country.mmdb"), fetch, a.applyCountries)
	go a.geoUpd.Run(context.Background())
}

func (a *appliance) expire(now time.Time) {
	if gone := a.store.Expire(now); len(gone) > 0 {
		log.Printf("[pf] %d bans expired", len(gone))
	}
}

// banAndReport bans ip for a detection here, or says why not, and reports
// the attack as an event either way.
func (a *appliance) banAndReport(ip, reason, service string, count int, details map[string]string) {
	d := map[string]string{"reason": reason, "attempts": strconv.Itoa(count)}
	if service != "" {
		d["service"] = service
	}
	for k, v := range details {
		d[k] = v
	}
	// A port scan was already reported as port_scan: only brute force gets
	// its own event here.
	evType := "brute_force"
	quiet := reason == "port_scan"
	if why := a.store.Why(ip); why != "" {
		d["action"], d["not_banned"] = "not_banned", why
		if !quiet {
			a.report(api.EventRequest{Type: evType, Severity: "critical", SourceIP: ip, Details: d})
		}
		return
	}
	if a.store.Monitor() {
		d["action"], d["mode"] = "would_ban", "learning"
		log.Printf("[appliance] Learning: would ban %s (%s, %d)", ip, reason, count)
		if !quiet {
			a.report(api.EventRequest{Type: evType, Severity: "critical", SourceIP: ip, Details: d})
		}
		return
	}
	expires := a.now().Add(applianceBanFor)
	added, why, err := a.store.Ban(ip, expires, reason, "local")
	if err != nil {
		log.Printf("[pf] ban %s: %v", ip, err)
	}
	if !added {
		if why != "" && !quiet {
			d["action"], d["not_banned"] = "not_banned", why
			a.report(api.EventRequest{Type: evType, Severity: "critical", SourceIP: ip, Details: d})
		}
		return
	}
	log.Printf("[pf] banned %s: %s (count=%d)", ip, reason, count)
	d["action"] = "banned"
	if !quiet {
		a.report(api.EventRequest{Type: evType, Severity: "critical", SourceIP: ip, Details: d})
	}
	exp := expires.UTC().Format(time.RFC3339)
	a.reportBan(api.BanRequest{IPAddress: ip, Reason: reason, BanCount: count, ExpiresAt: &exp}, 0)
}

// retryLater: err is a 429 ("too many requests"), with the wait the
// dashboard asked for (Retry-After; 1 minute without one, at most 30).
func retryLater(err error) (time.Duration, bool) {
	code, wait := api.HTTPStatus(err)
	if code != 429 {
		return 0, false
	}
	if wait <= 0 {
		wait = time.Minute
	}
	return min(wait, 30*time.Minute), true
}

// reportBan reports a local ban; after a 429 it tries again when the
// dashboard said (three tries at most: the ban is kept here regardless).
func (a *appliance) reportBan(b api.BanRequest, try int) {
	err := a.client.ReportBan(b)
	if err == nil || api.IsHeld(err) {
		return
	}
	if wait, busy := retryLater(err); busy && try < 2 {
		log.Printf("[api] ban %s: the dashboard is busy (429), reported again in %s", b.IPAddress, wait.Round(time.Second))
		time.AfterFunc(wait, func() { a.reportBan(b, try+1) })
		return
	}
	log.Printf("[api] ban %s not reported (kept locally until it expires): %v", b.IPAddress, err)
}

// counterKey counts IPv6 failures per /64 (one host owns a whole /64:
// counting per address would let it spread its attempts).
func counterKey(ip net.IP) string {
	if ip.To4() == nil {
		return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
	}
	return ip.String()
}

// spoofQuota allows 100 unauthenticated-source events an hour.
func (a *appliance) spoofQuota(now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if now.Sub(a.spoofWindow) >= time.Hour {
		a.spoofWindow, a.spoofSent = now, 0
	}
	if a.spoofSent >= 100 {
		return false
	}
	a.spoofSent++
	return true
}

// onAuth handles a login attempt from the logs.
func (a *appliance) onAuth(ev opnsense.AuthEvent) {
	now := a.now()
	ip := net.ParseIP(ev.IP)
	if ip == nil {
		return
	}
	if ev.Result == "success" {
		if pf.Reserved(ip) != "" {
			return // a LAN login: nothing to remember or report
		}
		guessed := a.bf.Failures(counterKey(ip), now) >= 2
		a.mu.Lock()
		_, known := a.logins[ev.IP]
		if !guessed {
			a.logins[ev.IP] = now
		}
		a.mu.Unlock()
		if !guessed {
			a.saveLogins()
			a.refreshConfig(false)
		}
		if !known || guessed {
			sev := "info"
			d := map[string]string{"service": ev.Service, "user": ev.User, "new_address": strconv.FormatBool(!known)}
			if guessed {
				sev = "critical"
				d["after_failures"] = strconv.Itoa(a.bf.Failures(counterKey(ip), now))
			}
			a.report(api.EventRequest{Type: "admin_login", Severity: sev, SourceIP: ev.IP, Details: d})
		}
		return
	}
	if ev.Spoofable {
		// Unauthenticated UDP: anyone can forge the source. Reported at
		// the threshold (at most 100 an hour), never banned, flagged so the
		// dashboard keeps it out of reputation and network bans.
		if n := a.bf.Fail("spoofable|"+counterKey(ip), now); n > 0 && a.spoofQuota(now) {
			a.report(api.EventRequest{Type: "brute_force", Severity: "warning", SourceIP: ev.IP, Details: map[string]string{
				"reason": ev.Reason, "service": ev.Service, "attempts": strconv.Itoa(n), "unauthenticated_source": "true",
				"action": "not_banned", "not_banned": "pre-authentication UDP: the source address can be forged"}})
		}
		return
	}
	if n := a.bf.Fail(counterKey(ip), now); n > 0 {
		d := map[string]string{}
		if ev.User != "" {
			d["user"] = ev.User
		}
		a.banAndReport(ev.IP, ev.Reason, ev.Service, n, d)
	}
}

// onFilter handles one filterlog record: summary counts and port scans.
func (a *appliance) onFilter(r opnsense.FilterRecord) {
	if !a.agg.Add(r) || r.DstPort <= 0 {
		return
	}
	a.mu.Lock()
	scanOn, scanBan := a.scanOn, a.scanBan
	a.mu.Unlock()
	if !scanOn {
		return
	}
	for _, s := range a.scans.Observe(net.ParseIP(r.Src), uint16(r.DstPort), a.now()) {
		d := s.Details()
		d["detection"] = "filterlog"
		d["interface"] = r.Interface
		// Blocked packets never completed a handshake: the source can be
		// forged, so a scan is reported, never banned here (unlike the
		// server agent's port_scan_ban, which sees accepted SYNs only).
		if scanBan {
			d["not_banned"] = "blocked packets: the source address can be forged"
		}
		a.report(api.EventRequest{Type: "port_scan", Severity: "warning", SourceIP: s.IP, Details: d})
	}
}

// onIDS reports a Suricata alert, deduplicated per source and signature
// and capped per hour.
func (a *appliance) onIDS(al opnsense.IDSAlert) {
	now := a.now()
	key := al.SrcIP + "|" + strconv.FormatInt(al.Alert.SID, 10)
	a.mu.Lock()
	if t, ok := a.idsSeen[key]; ok && now.Sub(t) < applianceIDSDedup {
		a.mu.Unlock()
		return
	}
	if now.Sub(a.idsWindow) >= time.Hour {
		a.idsWindow, a.idsSent = now, 0
		for k, t := range a.idsSeen {
			if now.Sub(t) >= applianceIDSDedup {
				delete(a.idsSeen, k)
			}
		}
	}
	if a.idsSent >= applianceIDSPerHour || len(a.idsSeen) >= 20000 {
		a.idsDropped++
		a.mu.Unlock()
		return
	}
	a.idsSent++
	a.idsSeen[key] = now
	a.mu.Unlock()
	d := map[string]string{
		"signature":    truncateRunes(al.Alert.Signature, 200),
		"signature_id": strconv.FormatInt(al.Alert.SID, 10),
		"category":     truncateRunes(al.Alert.Category, 100),
		"ids_action":   al.Alert.Action,
		"dest_ip":      al.DestIP,
		"interface":    al.Interface,
		"engine":       "suricata",
	}
	if al.Alert.Rev > 0 {
		d["rev"] = strconv.Itoa(al.Alert.Rev)
	}
	ev := api.EventRequest{Type: "ids_alert", Severity: al.SeverityName(), SourceIP: al.SrcIP, Protocol: strings.ToLower(al.Proto), Details: d}
	if al.SrcPort > 0 {
		p := al.SrcPort
		ev.SourcePort = &p
	}
	if al.DestPort > 0 {
		p := al.DestPort
		ev.TargetPort = &p
	}
	a.report(ev)
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

// reportBlocks sends the fw_blocks summary of the last window.
func (a *appliance) reportBlocks(now time.Time) {
	s, ok := a.agg.Take(now)
	if !ok {
		return
	}
	a.mu.Lock()
	a.lastBlocks = &s
	a.mu.Unlock()
	join := func(list []opnsense.KeyCount) string {
		parts := make([]string, len(list))
		for i, k := range list {
			parts[i] = k.Key + "=" + strconv.Itoa(k.Count)
		}
		return strings.Join(parts, ",")
	}
	d := map[string]string{"from": s.From, "to": s.To, "blocked": strconv.Itoa(s.Blocked),
		"distinct_sources": strconv.Itoa(s.DistinctSources), "top_sources": join(s.TopSources), "top_ports": join(s.TopPorts)}
	if s.Truncated {
		d["truncated"] = "true"
	}
	a.report(api.EventRequest{Type: "fw_blocks", Severity: "info", Details: d})
}

// runChecks refreshes the configuration findings (read-only).
func (a *appliance) runChecks(ctx context.Context) {
	a.refreshConfig(true)
	a.mu.Lock()
	conf := a.conf
	a.mu.Unlock()
	if conf == nil {
		return
	}
	var fwp *opnsense.Firmware
	if fw, err := opnsense.ReadFirmware(ctx); err == nil {
		fwp = &fw
	} else {
		log.Printf("[checks] firmware status: %v", err)
	}
	findings := opnsense.Check(conf, fwp)
	a.mu.Lock()
	a.findings, a.firmware = findings, fwp
	a.mu.Unlock()
	log.Printf("[checks] %d findings", len(findings))
	a.writeStatus()
}

func (a *appliance) startLogReaders(ctx context.Context) {
	poll := time.Second
	go opnsense.Tail(ctx, opnsense.LogFilter, poll, func(l string) {
		if r, ok := opnsense.ParseFilterLog(l); ok {
			a.onFilter(r)
		}
	})
	for _, p := range []string{opnsense.LogAudit, opnsense.LogOpenVPN, opnsense.LogWireGuard} {
		go opnsense.Tail(ctx, p, poll, func(l string) {
			if ev, ok := opnsense.ParseAuth(l); ok {
				a.onAuth(ev)
			}
		})
	}
	go opnsense.Tail(ctx, opnsense.EveJSON, poll, func(l string) {
		if al, ok := opnsense.ParseEve(l); ok {
			a.onIDS(al)
		}
	})
}

func (a *appliance) reverbHandlers() ws.Handlers {
	return ws.Handlers{
		OnBanCreated: func(p ws.BanCreatedPayload) {
			var exp time.Time
			if p.ExpiresAt != nil {
				exp, _ = parseBanExpiry(*p.ExpiresAt)
			}
			if _, why, err := a.store.Ban(p.IPAddress, exp, "dashboard", "dashboard"); why != "" || err != nil {
				log.Printf("[reverb] ban %s not applied: %s %v", p.IPAddress, why, err)
			}
		},
		OnBanRemoved: func(p ws.BanRemovedPayload) {
			_, _ = a.store.Unban(p.IPAddress)
		},
		OnSyncRequested: func(ws.SyncRequestedPayload) { a.syncs.Request("reverb") },
	}
}

// applianceInfo is the heartbeat's "appliance" object (see the dashboard
// contract).
type applianceInfo struct {
	Product    string                 `json:"product"`
	Version    string                 `json:"version,omitempty"`
	Kernel     string                 `json:"kernel,omitempty"`
	Arch       string                 `json:"arch"`
	Mode       string                 `json:"mode"`       // protect, monitor
	Protection string                 `json:"protection"` // active, learning, detect_only
	Reason     string                 `json:"protection_reason,omitempty"`
	PFEnabled  bool                   `json:"pf_enabled"`
	Tables     pf.Status              `json:"tables"`
	Interfaces []opnsense.Interface   `json:"interfaces,omitempty"`
	WANIPs     []string               `json:"wan_ips,omitempty"`
	IDSEnabled bool                   `json:"ids_enabled"`
	IPSMode    bool                   `json:"ips_mode"`
	HA         bool                   `json:"ha"`
	GeoSource  string                 `json:"geo_source,omitempty"`
	Countries  []string               `json:"blocked_countries,omitempty"`
	Firmware   *opnsense.Firmware     `json:"firmware,omitempty"`
	Findings   []opnsense.Finding     `json:"findings"`
	FWBlocks   *opnsense.BlockSummary `json:"fw_blocks,omitempty"`
	IDSDropped int                    `json:"ids_alerts_dropped,omitempty"`
	Update     string                 `json:"update_available,omitempty"`
}

func (a *appliance) applianceState() applianceInfo {
	st := a.store.Status()
	a.mu.Lock()
	defer a.mu.Unlock()
	info := applianceInfo{Product: a.info.Product, Version: a.info.Version, Kernel: a.info.Kernel, Arch: runtime.GOARCH,
		Mode: "protect", Protection: a.protection, Reason: a.protWhy, PFEnabled: a.pfEnabled, Tables: st,
		GeoSource: a.geoSource, Countries: a.countries, Firmware: a.firmware, Findings: a.findings,
		FWBlocks: a.lastBlocks, IDSDropped: a.idsDropped, Update: a.updateAvail}
	if info.Product == "" {
		info.Product = "FreeBSD"
	}
	if info.Findings == nil {
		info.Findings = []opnsense.Finding{}
	}
	if st.Monitor {
		info.Mode = "monitor"
	}
	if c := a.conf; c != nil {
		info.IDSEnabled, info.IPSMode, info.HA = c.IDSEnabled, c.IPSMode, c.CARP
		info.Interfaces = c.Interfaces
		for _, it := range c.Interfaces {
			if it.External {
				if ip, _, err := net.ParseCIDR(it.IPv4); err == nil {
					info.WANIPs = append(info.WANIPs, ip.String())
				}
			}
		}
	}
	return info
}

func (a *appliance) heartbeat(push *pushListener) {
	st := a.applianceState()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	depth, dropped := a.client.EventQueueStats()
	m := readApplianceMetrics()
	req := api.HeartbeatRequest{
		Status: "online", Version: version, Timestamp: a.now().UTC().Format(time.RFC3339), IPAddress: detectOutboundIP(),
		FirewallMode: "pf", BanCapacity: st.Tables.Limit, ActiveBans: st.Tables.ActiveBans,
		Kind: platform.KindOPNsense, Capabilities: applianceCapabilities, Appliance: st,
		Metrics: &m.SystemMetrics,
		Runtime: &api.RuntimeStats{GoroutineCount: runtime.NumGoroutine(), HeapAllocBytes: ms.HeapAlloc, HeapSysBytes: ms.HeapSys,
			RSSBytes: m.RSS, UptimeSeconds: m.Uptime, EventQueueLen: depth, EventDropped: dropped},
	}
	resp, err := a.client.Heartbeat(req)
	if err != nil {
		if wait, busy := retryLater(err); busy {
			log.Printf("[heartbeat] the dashboard is busy (429): next heartbeat as usual (asked %s)", wait.Round(time.Second))
		} else if !api.IsHeld(err) {
			log.Printf("[heartbeat] error: %v", err)
		}
		a.writeStatus()
		return
	}
	a.mu.Lock()
	a.lastHeartbeat = a.now()
	if resp.LatestAgentVersion != nil && *resp.LatestAgentVersion != "" && *resp.LatestAgentVersion != version {
		// pkg owns the binary: updates come through System › Firmware.
		a.updateAvail = *resp.LatestAgentVersion
	} else {
		a.updateAvail = ""
	}
	a.mu.Unlock()
	if a.syncs != nil {
		a.syncs.ObserveVersion(resp.ConfigVersion)
	}
	if push != nil {
		push.Apply(resp.Realtime)
	}
	a.writeStatus()
}

// applianceStatus is status.json, read by "appliance status" (the GUI's
// Status tab). No secrets.
type applianceStatus struct {
	Registered    bool          `json:"registered"`
	Running       bool          `json:"running"`
	AgentID       int64         `json:"agent_id,omitempty"`
	Version       string        `json:"version"`
	Dashboard     string        `json:"dashboard,omitempty"`
	LastHeartbeat string        `json:"last_heartbeat,omitempty"`
	LastSync      string        `json:"last_sync,omitempty"`
	LastSyncError string        `json:"last_sync_error,omitempty"`
	UpdatedAt     string        `json:"updated_at"`
	PID           int           `json:"pid,omitempty"`
	Appliance     applianceInfo `json:"appliance"`
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func (a *appliance) writeStatus() {
	st := a.applianceState()
	a.mu.Lock()
	s := applianceStatus{Registered: true, Running: true, AgentID: a.cfg.AgentID, Version: version, Dashboard: a.cfg.ServerURL,
		LastHeartbeat: fmtTime(a.lastHeartbeat), LastSync: fmtTime(a.lastSync), LastSyncError: a.lastSyncErr,
		UpdatedAt: fmtTime(a.now()), PID: os.Getpid(), Appliance: st}
	a.mu.Unlock()
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return
	}
	if err := applianceWrite(applianceStatusPath(), data, 0o640); err != nil {
		log.Printf("[appliance] status: %v", err)
	}
}

func applianceWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (a *appliance) loadLogins() {
	data, err := os.ReadFile(applianceLoginsPath())
	if err != nil {
		return
	}
	var m map[string]time.Time
	if json.Unmarshal(data, &m) != nil {
		return
	}
	now := a.now()
	a.mu.Lock()
	defer a.mu.Unlock()
	for ip, t := range m {
		if net.ParseIP(ip) != nil && now.Sub(t) < applianceLoginExempt {
			a.logins[ip] = t
		}
	}
}

func (a *appliance) saveLogins() {
	a.mu.Lock()
	now := a.now()
	for ip, t := range a.logins {
		if now.Sub(t) >= applianceLoginExempt {
			delete(a.logins, ip)
		}
	}
	data, err := json.Marshal(a.logins)
	a.mu.Unlock()
	if err == nil {
		_ = applianceWrite(applianceLoginsPath(), data, 0o600)
	}
}

// ---- CLI: infrafence-agent appliance <command> (for the plugin) ----

func cmdAppliance(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: infrafence-agent appliance status|bans|findings [--json] | mode <protect|monitor> [--actor USER] | flush")
		os.Exit(2)
	}
	out := func(v any) {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(v)
	}
	switch args[0] {
	case "status":
		out(readApplianceStatus())
	case "findings":
		out(readApplianceStatus().Appliance.Findings)
	case "bans":
		var saved struct {
			Bans []pf.Ban `json:"bans"`
		}
		if data, err := os.ReadFile(applianceBansPath()); err == nil {
			_ = json.Unmarshal(data, &saved)
		}
		if saved.Bans == nil {
			saved.Bans = []pf.Ban{}
		}
		out(saved.Bans)
	case "mode":
		if len(args) < 2 || (args[1] != "protect" && args[1] != "monitor") {
			out(map[string]string{"status": "error", "message": "mode must be protect or monitor"})
			os.Exit(2)
		}
		actor := "opnsense-gui"
		for i := 2; i+1 < len(args); i++ {
			if args[i] == "--actor" && validActor(args[i+1]) {
				actor = args[i+1]
			}
		}
		res, code := applianceSetMode(args[1], actor)
		out(res)
		os.Exit(code)
	case "flush":
		// Uninstall: empty the agent's own tables (never another one).
		ctl := pf.NewCtl(pf.ExecRunner(appliancePfctl))
		for _, t := range pf.Tables {
			if err := ctl.Replace(t, nil); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown appliance command %q\n", args[0])
		os.Exit(2)
	}
}

func validActor(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r == '-' || r == '_' || r == '.' || r == '@' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return false
		}
	}
	return true
}

func readApplianceStatus() applianceStatus {
	st := applianceStatus{Version: version, Appliance: applianceInfo{Findings: []opnsense.Finding{}}}
	cfg, err := config.Load()
	if err != nil {
		return st
	}
	st.Registered, st.AgentID, st.Dashboard = true, cfg.AgentID, cfg.ServerURL
	data, err := os.ReadFile(applianceStatusPath())
	if err == nil {
		var saved applianceStatus
		if json.Unmarshal(data, &saved) == nil {
			st = saved
			st.Registered = true
		}
	}
	st.Running = st.PID > 0 && processAlive(st.PID)
	if st.Appliance.Findings == nil {
		st.Appliance.Findings = []opnsense.Finding{}
	}
	return st
}

func processAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}

func applianceSetMode(mode, actor string) (map[string]string, int) {
	cfg, err := config.Load()
	if err != nil {
		return map[string]string{"status": "error", "message": "not registered"}, 1
	}
	client := api.New(cfg.ServerURL, cfg.AgentToken)
	client.SetVersion(version)
	err = client.SetMode(api.ModeRequest{Mode: mode, Actor: actor, Source: "opnsense-gui"})
	switch {
	case func() bool { _, busy := retryLater(err); return busy }():
		wait, _ := retryLater(err)
		return map[string]string{"status": "retry_later", "message": fmt.Sprintf("Too many mode changes for now: try again in %s.", wait.Round(time.Second))}, 1
	case api.IsNotFound(err):
		return map[string]string{"status": "unsupported", "message": "This dashboard cannot change the mode from here yet: change it in the InfraFence dashboard."}, 1
	case err != nil:
		return map[string]string{"status": "error", "message": err.Error()}, 1
	}
	// The agent applies it at its next sync: ask for one now.
	if pid := applianceAgentPID(); pid > 0 {
		if p, err := os.FindProcess(pid); err == nil {
			_ = p.Signal(syscall.SIGHUP)
		}
	}
	return map[string]string{"status": "ok", "mode": mode}, 0
}

// applianceAgentPID is the running agent's pid from its pid file, checked
// to be "infrafence-agent start" (a stale file's pid may be reused by an
// unrelated process); 0 when none.
func applianceAgentPID() int {
	data, err := os.ReadFile(appliancePidPath())
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 1 {
		return 0
	}
	out, err := exec.Command("/bin/ps", "-p", strconv.Itoa(pid), "-o", "command=").Output()
	if err != nil || !strings.Contains(string(out), "infrafence-agent start") {
		return 0
	}
	return pid
}
