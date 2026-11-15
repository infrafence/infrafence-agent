package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/config"
	"github.com/infrafence/infrafence-agent/internal/router/dnsblock"
	"github.com/infrafence/infrafence-agent/internal/router/fw"
	"github.com/infrafence/infrafence-agent/internal/router/guard"
	"github.com/infrafence/infrafence-agent/internal/router/lan"
	"github.com/infrafence/infrafence-agent/internal/router/sysinfo"
)

// Intervals (variables: the e2e test shortens them through the
// environment, see applyTestIntervals).
var (
	heartbeatEvery = 60 * time.Second
	syncEvery      = 5 * time.Minute
	hitsEvery      = 60 * time.Second
	watchdogEvery  = 60 * time.Second
	conntrackEvery = 5 * time.Minute
	devicesEvery   = 5 * time.Minute
	reportDevEvery = 15 * time.Minute
	statusEvery    = 30 * time.Second
	listEvery      = 6 * time.Hour // re-check the domain list even without a new ETag
	dnsMinRestart  = 5 * time.Minute
)

// c2DNSTTL is how long an address a C2 domain resolved to stays in the C2
// set.
const c2DNSTTL = time.Hour

type agent struct {
	cfg    *config.Config
	set    settings
	client *api.Client
	info   sysinfo.Info
	guard  *guard.Guard
	fw     *fw.Manager // nil: no usable firewall (detect only)
	dns    *dnsblock.Blocker
	inv    *lan.Inventory
	find   *findings
	start  time.Time
	pokeCh chan struct{}
	syncCh chan struct{}

	mu            sync.Mutex
	fwOK          bool
	mode          fw.Mode
	suspended     bool
	synced        bool
	configVersion string
	shareNames    bool
	lanIf         string
	lanNets       []netip.Prefix
	dnsCapturing  bool
	dnsActive     bool
	dnsErr        string
	listETag      string
	listURL       string
	listChecked   time.Time
	listFailETag  string    // a list that failed to load (too few domains...)
	listFailAt    time.Time // not fetched again for an hour
	// retryAt: when a rate-limited (429) request may be sent again.
	retryAt         map[string]time.Time
	lastHeartbeat   time.Time
	lastSync        time.Time
	lastError       string
	caps            struct{ bans, c2, domains int }
	c2Sources       map[netip.Prefix]string // C2 prefix -> feed name (for events)
	c2FromSync      []fw.Element            // the dashboard's C2 list
	c2FromDNS       map[netip.Addr]dnsC2    // addresses C2 domains resolved to
	ruleAcked       map[int64]bool          // rule IDs acknowledged this run
	devicesNotFound time.Time               // the dashboard has no device endpoint (404)
}

type dnsC2 struct {
	expires time.Time
	domain  string
}

func newAgent(cfg *config.Config, set settings) (*agent, error) {
	info := sysinfo.Detect()
	secret, err := lan.LoadSecret(secretPath)
	if err != nil {
		return nil, fmt.Errorf("device key secret: %w", err)
	}
	a := &agent{
		cfg:       cfg,
		set:       set,
		client:    api.New(cfg.ServerURL, cfg.AgentToken),
		info:      info,
		guard:     guard.New(),
		dns:       dnsblock.New(stateDir),
		inv:       lan.NewInventory(secret),
		start:     time.Now(),
		pokeCh:    make(chan struct{}, 1),
		syncCh:    make(chan struct{}, 1),
		c2Sources: map[netip.Prefix]string{},
		c2FromDNS: map[netip.Addr]dnsC2{},
		ruleAcked: map[int64]bool{},
		retryAt:   map[string]time.Time{},
		mode:      fw.Learning,
	}
	a.client.SetVersion(version)
	if err := os.MkdirAll(stateDir, 0o700); err == nil {
		a.client.SetEventSpool(filepath.Join(stateDir, "events.spool"))
	}
	a.find = newFindings(a.client, a.inv, time.Now)
	b, c2, d := sysinfo.DefaultCaps(info.MemTotal)
	a.caps.bans = minPositive(b, set.MaxBans)
	a.caps.c2 = c2
	a.caps.domains = minPositive(d, set.MaxDomains, oldDnsmasqCap(info))
	a.dns.Protected = protectedNames(cfg.ServerURL)
	a.dns.MinRestart = dnsMinRestart
	if be := chooseBackend(info); be != nil {
		a.fw = fw.NewManager(be, fw.Caps{Bans: a.caps.bans, C2: a.caps.c2})
	}
	a.lanIf = lanInterface(set)
	a.lanNets = lanPrefixes(a.lanIf)
	a.inv.LANIf = a.lanIf
	return a, nil
}

// protectedNames are domains never blocked: the dashboard and where the
// router gets its packages and time.
func protectedNames(server string) []string {
	out := []string{"infrafence.com", "openwrt.org", "pool.ntp.org", "gl-inet.com", "gl-inet.cn", "goodcloud.xyz"}
	if u, err := url.Parse(server); err == nil && u.Hostname() != "" {
		out = append(out, u.Hostname())
	}
	return out
}

func (a *agent) poke() {
	select {
	case a.pokeCh <- struct{}{}:
	default:
	}
}

func (a *agent) requestSync() {
	select {
	case a.syncCh <- struct{}{}:
	default:
	}
}

func (a *agent) run(ctx context.Context) {
	log.Printf("[agent] infrafence-router %s on %s (%s, %s, %s), firewall %s", version, a.info.Release, a.info.Model, a.info.Arch, runtime.GOARCH, a.backendName())
	if a.fw == nil {
		log.Printf("[firewall] no usable backend (fw4+nftables or fw3+ipset): detection only")
	}
	a.refreshGuard()
	// The last sync if procd restarted the agent (tmpfs, under a day
	// old), else Learning until the first sync says otherwise: after a
	// reboot an unreachable dashboard never leaves the router blocking
	// with stale settings.
	if a.restoreCache() {
		a.fwOK = true
	} else if a.fw != nil {
		err := a.fw.SetMode(fw.Learning)
		if err != nil {
			log.Printf("[firewall] create rules: %v", err)
		}
		a.fwOK = err == nil
	}
	a.inv.Refresh()
	if a.set.DNSCapture && a.lanIf != "" {
		go a.captureDNS(ctx)
	}
	go a.loop(ctx, "watchdog", watchdogEvery, a.watchdog)
	go a.loop(ctx, "hits", hitsEvery, a.pollHits)
	go a.loop(ctx, "conntrack", conntrackEvery, a.scanConntrack)
	go a.loop(ctx, "devices", devicesEvery, func() { a.inv.Refresh(); a.refreshGuard() })
	go a.loop(ctx, "device-report", reportDevEvery, a.reportDevices)
	go a.loop(ctx, "findings", time.Minute, a.find.flush)
	go a.loop(ctx, "status", statusEvery, a.writeStatus)

	a.heartbeat()
	a.sync()
	a.writeStatus()
	hb := time.NewTicker(heartbeatEvery)
	sy := time.NewTicker(syncEvery)
	dn := time.NewTicker(30 * time.Second)
	defer hb.Stop()
	defer sy.Stop()
	defer dn.Stop()
	for {
		select {
		case <-ctx.Done():
			a.shutdown()
			return
		case <-hb.C:
			a.heartbeat()
			a.deadMan()
		case <-sy.C:
			a.sync()
		case <-a.syncCh:
			a.sync()
		case <-a.pokeCh:
			st := loadSettings()
			a.mu.Lock()
			a.set = st
			a.mu.Unlock()
			a.refreshGuard()
			a.watchdog()
			a.applyDNS()
			// An interface came up or the firewall changed: re-check the
			// lists against the new addresses.
			a.requestSync()
		case <-dn.C:
			a.applyDNS()
		}
	}
}

// loop runs fn every interval, recovering from a panic (one failing check
// must not stop the agent).
func (a *agent) loop(ctx context.Context, name string, every time.Duration, fn func()) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			func() {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("[%s] panic: %v", name, r)
					}
				}()
				fn()
			}()
		}
	}
}

// shutdown flushes events. The firewall rules stay: procd's stop runs
// `infrafence-router cleanup` (a restart keeps them, so there is no gap).
func (a *agent) shutdown() {
	a.find.flush()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = a.client.CloseEvents(ctx)
	a.writeStatus()
}

func (a *agent) backendName() string {
	if a.fw == nil {
		return "none"
	}
	return a.fw.Backend()
}

// refreshGuard re-reads the addresses the router must keep reaching.
func (a *agent) refreshGuard() {
	var p []netip.Prefix
	p = append(p, guard.LocalAddresses()...)
	p = append(p, guard.Gateways()...)
	p = append(p, guard.Resolvers()...)
	p = append(p, guard.Peers()...)
	p = append(p, guard.Hosts(a.client.PeerIPs())...)
	a.guard.SetProtected(p)
	a.mu.Lock()
	a.lanNets = lanPrefixes(a.lanIf)
	a.mu.Unlock()
}

func (a *agent) isLAN(ip netip.Addr) bool {
	ip = ip.Unmap()
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, n := range a.lanNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// isRouter says whether the address is one of the router's own.
func isRouter(ip netip.Addr) bool {
	for _, p := range guard.LocalAddresses() {
		if p.Addr() == ip.Unmap() {
			return true
		}
	}
	return false
}

func (a *agent) watchdog() {
	if a.fw == nil {
		return
	}
	reset, err := a.fw.Ensure()
	a.mu.Lock()
	a.fwOK = err == nil
	a.mu.Unlock()
	if err != nil {
		log.Printf("[firewall] watchdog: %v", err)
		a.setError("firewall: " + err.Error())
		return
	}
	if reset {
		log.Printf("[firewall] our rules were gone (ruleset flushed?): restored")
		a.find.firewallReset(a.backendName())
	}
}

func (a *agent) setError(s string) {
	a.mu.Lock()
	a.lastError = s
	a.mu.Unlock()
}

func (a *agent) heartbeat() {
	a.mu.Lock()
	mode := a.mode
	a.mu.Unlock()
	bans, feed, c2 := 0, 0, 0
	if a.fw != nil {
		bans, feed, c2 = a.fw.Counts()
	}
	depth, dropped := a.client.EventQueueStats()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	req := api.HeartbeatRequest{
		Status:       "online",
		Version:      version,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		IPAddress:    primaryAddress(),
		Metrics:      metrics(a.info),
		FirewallMode: a.backendName(),
		BanCapacity:  a.caps.bans,
		ActiveBans:   bans,
		Runtime: &api.RuntimeStats{
			GoroutineCount: runtime.NumGoroutine(),
			HeapAllocBytes: ms.HeapAlloc,
			HeapSysBytes:   ms.HeapSys,
			RSSBytes:       rss(),
			UptimeSeconds:  int64(time.Since(a.start).Seconds()),
			EventQueueLen:  depth,
			EventDropped:   dropped,
		},
		Kind:       api.AgentKindRouter,
		RouterInfo: a.routerInfo(mode, feed, c2),
	}
	if !a.due("heartbeat") {
		return
	}
	resp, err := a.client.Heartbeat(req)
	if a.rateLimited("heartbeat", err) {
		return
	}
	if err != nil {
		if !api.IsHeld(err) {
			log.Printf("[api] heartbeat: %v", err)
		}
		a.setError("dashboard: " + err.Error())
		return
	}
	a.mu.Lock()
	a.lastHeartbeat = time.Now()
	changed := resp.ConfigVersion != "" && resp.ConfigVersion != a.configVersion
	a.configVersion = resp.ConfigVersion
	a.lastError = ""
	a.mu.Unlock()
	if changed {
		a.requestSync()
	}
}

func (a *agent) routerInfo(mode fw.Mode, feed, c2 int) *api.RouterInfo {
	a.mu.Lock()
	defer a.mu.Unlock()
	n, _ := a.dns.Count()
	ok := a.fwOK
	dnsState := "off"
	switch {
	case !dnsblock.Available():
		dnsState = "unavailable"
	case !a.set.DNSBlocking:
		dnsState = "off"
	case a.dnsActive:
		dnsState = "active"
	case mode == fw.Learning:
		dnsState = "learning"
	}
	return &api.RouterInfo{
		Mode:             mode.String(),
		Firewall:         a.info.Firewall,
		FirewallBackend:  a.backendName(),
		FirewallOK:       ok,
		FlowOffloading:   a.info.FlowOffload,
		FlowOffloadingHW: a.info.FlowOffloadHW,
		DNSCapture:       a.dnsCapturing,
		DNSBlocking:      dnsState,
		BlockedDomains:   n,
		DomainListETag:   a.listETag,
		C2Entries:        c2,
		FeedEntries:      feed,
		BanCapacity:      a.caps.bans,
		DomainCapacity:   a.caps.domains,
		LANDevices:       a.inv.Len(),
		FlaggedDevices:   a.find.flaggedCount(),
		Board:            a.info.Board,
		Model:            a.info.Model,
		Release:          a.info.Release,
		Target:           a.info.Target,
		Arch:             a.info.Arch,
		PackageManager:   a.info.PackageManager,
		Vendor:           a.info.Vendor,
		OverlayFree:      a.info.OverlayFree,
		Coexisting:       a.info.Coexisting,
		Capabilities:     capabilities(a.info),
	}
}

// sync fetches the configuration and lists and applies them.
func (a *agent) sync() {
	if !a.due("sync") {
		return
	}
	s, err := a.client.SyncRouter()
	if a.rateLimited("sync", err) {
		return
	}
	if err != nil {
		if !api.IsHeld(err) {
			log.Printf("[api] sync: %v", err)
		}
		a.setError("sync: " + err.Error())
		return
	}
	now := time.Now()
	mode := fw.Full
	if s.Config.MonitorMode || s.Config.Suspended {
		mode = fw.Learning
	}
	// Whitelist first: nothing whitelisted reaches the firewall.
	var allow []netip.Prefix
	for _, w := range s.Whitelists {
		for _, v := range []*string{w.IPAddress, w.IPRange} {
			if v != nil && *v != "" {
				if p, err := guard.Parse(*v); err == nil {
					allow = append(allow, p)
				}
			}
		}
	}
	a.guard.SetAllow(allow)
	a.refreshGuard()

	rs := s.Router
	if rs == nil {
		rs = &api.RouterSync{}
	}
	a.mu.Lock()
	a.mode = mode
	a.suspended = s.Config.Suspended
	a.synced = true
	a.lastSync = now
	a.shareNames = rs.ShareDeviceNames && a.set.DeviceNames != "never"
	if rs.MaxBans > 0 {
		b, _, _ := sysinfo.DefaultCaps(a.info.MemTotal)
		a.caps.bans = minPositive(b, a.set.MaxBans, rs.MaxBans)
	}
	if rs.MaxDomains > 0 {
		_, _, d := sysinfo.DefaultCaps(a.info.MemTotal)
		a.caps.domains = minPositive(d, a.set.MaxDomains, rs.MaxDomains, oldDnsmasqCap(a.info))
	}
	caps := a.caps
	a.mu.Unlock()
	a.find.setShareNames(a.shareNames)
	a.find.setMode(mode)

	bans := a.bans(s, now)
	feed := a.entries(s.ThreatFeed, "threat feed")
	c2 := a.entries(rs.C2, "C2 list")
	a.mu.Lock()
	a.c2FromSync = c2
	a.c2Sources = map[netip.Prefix]string{}
	for _, e := range rs.C2 {
		for _, v := range []*string{e.IP, e.CIDR} {
			if v != nil {
				if p, err := guard.Parse(*v); err == nil {
					a.c2Sources[p] = e.Source
				}
			}
		}
	}
	a.mu.Unlock()
	if a.fw != nil {
		a.fw.SetCaps(fw.Caps{Bans: caps.bans, C2: caps.c2})
		var errs []error
		if err := a.fw.SetMode(mode); err != nil {
			errs = append(errs, err)
		}
		errs = append(errs, a.fw.Set(fw.KindBan, bans), a.fw.Set(fw.KindFeed, feed), a.fw.Set(fw.KindC2, a.allC2(now)))
		if err := errors.Join(errs...); err != nil {
			log.Printf("[firewall] apply: %v", err)
			a.setError("firewall: " + err.Error())
		}
		if n := a.fw.Dropped(fw.KindBan); n > 0 {
			log.Printf("[firewall] %d bans over the cap of %d per address family were left out", n, caps.bans)
		}
		a.dropOffloaded(bans)
	}
	a.ackRules(s.Rules)
	a.syncDomainList(rs.DomainList, caps.domains)
	a.applyDNS()
	a.mu.Lock()
	cache := &syncCache{Mode: mode.String(), Suspended: s.Config.Suspended, ShareNames: rs.ShareDeviceNames,
		ListURL: a.listURL, ListETag: a.listETag,
		Bans: toCached(bans, nil), Feed: toCached(feed, nil), C2: toCached(c2, a.c2Sources)}
	a.mu.Unlock()
	saveCache(cache)
	b, f, c := 0, 0, 0
	if a.fw != nil {
		b, f, c = a.fw.Counts()
	}
	n, _ := a.dns.Count()
	log.Printf("[sync] mode %s: %d bans, %d feed, %d C2, %d domains", mode, b, f, c, n)
	a.writeStatus()
}

// bans are the dashboard's bans and IP block rules, unexpired and allowed
// by the guard.
func (a *agent) bans(s *api.RouterSyncResponse, now time.Time) []fw.Element {
	var out []fw.Element
	refused := 0
	for _, b := range s.Bans {
		p, err := guard.Parse(b.IPAddress)
		if err != nil {
			continue
		}
		var exp time.Time
		if b.ExpiresAt != nil && *b.ExpiresAt != "" {
			t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(*b.ExpiresAt))
			if err != nil {
				continue // an expiry we can't read: the dashboard lifts it at a later sync
			}
			if !t.After(now) {
				continue
			}
			exp = t
		}
		if err := a.guard.Check(p); err != nil {
			refused++
			continue
		}
		out = append(out, fw.Element{Prefix: p, Expires: exp})
	}
	for _, r := range s.Rules {
		if p, ok := blockRule(r); ok {
			if err := a.guard.Check(p); err != nil {
				refused++
				continue
			}
			out = append(out, fw.Element{Prefix: p})
		}
	}
	if refused > 0 {
		log.Printf("[guard] %d bans not applied (local, reserved, whitelisted or needed by the router)", refused)
	}
	return out
}

// blockRule is a rule the router enforces: block, whole address or range,
// any protocol and port.
func blockRule(r api.Rule) (netip.Prefix, bool) {
	if r.Type != "block" || r.Port != nil || r.CountryCode != nil && *r.CountryCode != "" {
		return netip.Prefix{}, false
	}
	// A whole-address block only: "tcp" alone would become a block of
	// every protocol.
	switch strings.ToLower(r.Protocol) {
	case "", "all", "any":
	default:
		return netip.Prefix{}, false
	}
	if r.Status != "pending" && r.Status != "synced" && r.Status != "applied" && r.Status != "active" {
		return netip.Prefix{}, false
	}
	for _, v := range []*string{r.IPAddress, r.IPRange} {
		if v != nil && *v != "" {
			if p, err := guard.Parse(*v); err == nil {
				return p, true
			}
		}
	}
	return netip.Prefix{}, false
}

// ackRules acknowledges pending rules once: applied (IP block rules) or
// failed with the reason (what a router does not enforce).
func (a *agent) ackRules(rules []api.Rule) {
	for _, r := range rules {
		if r.Status != "pending" || a.ruleAcked[r.ID] {
			continue
		}
		req := api.RuleAckRequest{Status: "applied"}
		if p, ok := blockRule(r); !ok {
			msg := "not supported on routers: only block rules for an address or range, without port or country"
			req = api.RuleAckRequest{Status: "failed", ErrorMessage: &msg}
		} else if err := a.guard.Check(p); err != nil {
			msg := err.Error()
			req = api.RuleAckRequest{Status: "failed", ErrorMessage: &msg}
		} else if a.fw == nil {
			msg := "no usable firewall on this router (install ipset and kmod-ipt-ipset on fw3)"
			req = api.RuleAckRequest{Status: "failed", ErrorMessage: &msg}
		}
		if !a.due("ack") {
			return
		}
		if err := a.client.AckRule(r.ID, req); err != nil {
			if a.rateLimited("ack", err) {
				return
			}
			if !api.IsHeld(err) {
				log.Printf("[api] ack rule %d: %v", r.ID, err)
			}
			continue
		}
		a.ruleAcked[r.ID] = true
	}
}

func (a *agent) entries(list []api.ThreatEntry, what string) []fw.Element {
	var out []fw.Element
	refused := 0
	for _, e := range list {
		for _, v := range []*string{e.IP, e.CIDR} {
			if v == nil || *v == "" {
				continue
			}
			p, err := guard.Parse(*v)
			if err != nil {
				continue
			}
			if err := a.guard.Check(p); err != nil {
				refused++
				continue
			}
			out = append(out, fw.Element{Prefix: p})
		}
	}
	if refused > 0 {
		log.Printf("[guard] %d %s entries not applied (local, reserved, whitelisted or needed by the router)", refused, what)
	}
	return out
}

// allC2 is the dashboard's C2 list plus the addresses C2 domains resolved
// to (DNS capture), unexpired.
func (a *agent) allC2(now time.Time) []fw.Element {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := append([]fw.Element(nil), a.c2FromSync...)
	for ip, d := range a.c2FromDNS {
		if !d.expires.After(now) {
			delete(a.c2FromDNS, ip)
			continue
		}
		out = append(out, fw.Element{Prefix: netip.PrefixFrom(ip, ip.BitLen()), Expires: d.expires})
	}
	return out
}

// dropOffloaded deletes the conntrack entries of newly banned single
// addresses: with flow offloading an established flow skips the forward
// hook, so a ban alone would not cut it.
func (a *agent) dropOffloaded(bans []fw.Element) {
	if !a.info.HasConntrack || !a.info.FlowOffload {
		return
	}
	n := 0
	for _, b := range bans {
		if n >= 50 || b.Prefix.Bits() != b.Prefix.Addr().BitLen() {
			continue
		}
		_ = runQuiet("conntrack", "-D", "-s", b.Prefix.Addr().String())
		n++
	}
}

// syncDomainList downloads the domain list when its ETag changed.
func (a *agent) syncDomainList(dl *api.DomainList, max int) {
	if dl == nil || dl.URL == "" {
		// No list for this router (no InfraFence Home, or it ended): one
		// loaded earlier goes.
		if a.dns.Index() != nil {
			if err := a.dns.Clear(); err != nil {
				log.Printf("[dns] remove the domain list: %v", err)
			}
			a.mu.Lock()
			a.listETag, a.listURL = "", ""
			a.mu.Unlock()
			log.Printf("[dns] the dashboard sends no domain list: removed")
		}
		return
	}
	if !a.due("domain-list") {
		return
	}
	a.mu.Lock()
	same := dl.ETag != "" && dl.ETag == a.listETag && dl.URL == a.listURL && time.Since(a.listChecked) < listEvery ||
		dl.ETag != "" && dl.ETag == a.listFailETag && time.Since(a.listFailAt) < time.Hour
	etag := a.listETag
	if dl.URL != a.listURL {
		etag = ""
	}
	a.mu.Unlock()
	if same {
		return
	}
	var n int
	newTag, err := a.client.FetchDomainList(context.Background(), dl.URL, etag, func(r io.Reader) error {
		var err error
		// A list far smaller than announced is a broken download (a
		// captive portal, a proxy): the current list stays.
		// An announced empty list (count 0, ETag "not-included": a router
		// without InfraFence Home) is accepted as empty.
		n, err = a.dns.Load(r, max, min(dl.Count/2, max), dl.Count == 0 || dl.ETag == `"not-included"`)
		return err
	})
	a.mu.Lock()
	a.listChecked = time.Now()
	a.mu.Unlock()
	if errors.Is(err, api.ErrNotModified) {
		return
	}
	if a.rateLimited("domain-list", err) {
		return
	}
	if err != nil {
		log.Printf("[dns] domain list: %v", err)
		a.setError("domain list: " + err.Error())
		a.mu.Lock()
		a.listFailETag, a.listFailAt = dl.ETag, time.Now()
		a.mu.Unlock()
		return
	}
	if newTag == "" {
		newTag = dl.ETag
	}
	a.mu.Lock()
	a.listETag, a.listURL = newTag, dl.URL
	a.mu.Unlock()
	_, dropped := a.dns.Count()
	log.Printf("[dns] domain list loaded: %d domains (%d over the cap of %d left out)", n, dropped, max)
}

// applyDNS links the list into dnsmasq in Full protection only.
func (a *agent) applyDNS() {
	a.mu.Lock()
	full := a.synced && a.mode == fw.Full && !a.suspended && a.set.DNSBlocking
	a.mu.Unlock()
	if !dnsblock.Available() {
		return
	}
	a.dns.SetFull(full)
	active, err := a.dns.Apply()
	a.mu.Lock()
	a.dnsActive = active
	if err != nil {
		a.dnsErr = err.Error()
	} else {
		a.dnsErr = ""
	}
	a.mu.Unlock()
	if err != nil {
		log.Printf("[dns] %v", err)
	}
}

// pollHits reports the (device, C2) pairs the kernel recorded.
func (a *agent) pollHits() {
	if a.fw == nil {
		return
	}
	hits, err := a.fw.Hits()
	if err != nil {
		log.Printf("[c2] list hits: %v", err)
		return
	}
	for _, h := range hits {
		a.find.c2Hit(h, a.c2Source(h.Dst), isRouter(h.Src))
	}
}

func (a *agent) c2Source(ip netip.Addr) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if d, ok := a.c2FromDNS[ip]; ok {
		return "dns:" + d.domain
	}
	best := ""
	bits := -1
	for p, s := range a.c2Sources {
		if p.Contains(ip) && p.Bits() > bits {
			best, bits = s, p.Bits()
		}
	}
	return best
}

func (a *agent) scanConntrack() {
	fs, _, err := lan.ScanConntrack("/proc/net/nf_conntrack", a.isLAN)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("[conntrack] %v", err)
		}
		return
	}
	for _, f := range fs {
		a.find.conntrack(f)
	}
}

// captureDNS watches the LAN's DNS traffic until ctx ends, restarting the
// capture after an error (interface recreated by a network restart).
func (a *agent) captureDNS(ctx context.Context) {
	dga := newDGATracker(time.Now)
	for ctx.Err() == nil {
		a.mu.Lock()
		a.dnsCapturing = true
		ifname := a.lanIf
		a.mu.Unlock()
		err := lan.CaptureDNS(ctx, ifname, func(p lan.DNSPacket) { a.onDNS(p, dga) })
		a.mu.Lock()
		a.dnsCapturing = false
		a.mu.Unlock()
		if ctx.Err() != nil {
			return
		}
		log.Printf("[dns] capture on %s: %v (retrying in 30 s)", ifname, err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
		a.mu.Lock()
		a.lanIf = lanInterface(a.set)
		a.mu.Unlock()
		a.refreshGuard()
	}
}

func (a *agent) onDNS(p lan.DNSPacket, dga *dgaTracker) {
	ix := a.dns.Index()
	switch {
	case !p.Response && p.DstPort == 53 && a.isLAN(p.Src) && !isRouter(p.Src):
		if d, cat := ix.Lookup(p.Name); d != "" {
			a.mu.Lock()
			blocking := a.dnsActive
			a.mu.Unlock()
			a.find.listedLookup(p.Src, p.Name, d, cat, blocking)
		}
	case p.Response && p.SrcPort == 53 && a.isLAN(p.Dst) && !isRouter(p.Dst) && p.Outgoing:
		if p.NXDomain && lan.RandomLooking(p.Name) {
			if n, ex, ok := dga.add(p.Dst, p.Name); ok {
				a.find.dga(p.Dst, n, ex)
			}
		}
		// A listed C2/malware domain that still resolved (Learning mode,
		// or a resolver other than dnsmasq): its addresses join the C2 set
		// so connections to them are seen (and dropped in Full).
		if len(p.Answers) > 0 && a.fw != nil && p.Outgoing {
			if d, cat := ix.Lookup(p.Name); d != "" && (cat == dnsblock.CatC2 || cat == dnsblock.CatMalware || cat == dnsblock.CatMiner) {
				a.addDNSC2(d, p.Answers)
			}
		}
	}
}

func (a *agent) addDNSC2(domain string, ips []netip.Addr) {
	now := time.Now()
	var add []fw.Element
	a.mu.Lock()
	for _, ip := range ips {
		ip = ip.Unmap()
		if !lan.Public(ip) {
			continue
		}
		if d, ok := a.c2FromDNS[ip]; ok && d.expires.Sub(now) > c2DNSTTL/2 {
			continue
		}
		if len(a.c2FromDNS) >= 4096 {
			break
		}
		p := netip.PrefixFrom(ip, ip.BitLen())
		if a.guard.Check(p) != nil {
			continue
		}
		a.c2FromDNS[ip] = dnsC2{expires: now.Add(c2DNSTTL), domain: domain}
		add = append(add, fw.Element{Prefix: p, Expires: now.Add(c2DNSTTL)})
	}
	a.mu.Unlock()
	if len(add) == 0 {
		return
	}
	if err := a.fw.Add(fw.KindC2, add); err != nil {
		log.Printf("[c2] add resolved addresses of %s: %v", domain, err)
	}
}

// reportDevices sends the LAN inventory (hashed keys; names only when the
// organization opted in).
func (a *agent) reportDevices() {
	a.mu.Lock()
	if !a.devicesNotFound.IsZero() && time.Since(a.devicesNotFound) < 6*time.Hour {
		a.mu.Unlock()
		return
	}
	share := a.shareNames
	a.mu.Unlock()
	devs := a.inv.List()
	req := api.RouterDevicesRequest{Total: len(devs), NamesSent: share, ScannedAt: time.Now().UTC().Format(time.RFC3339)}
	for i, d := range devs {
		if i >= 512 {
			break
		}
		rd := api.RouterDevice{
			DeviceKey: d.Key,
			MACVendor: d.OUI,
			Random:    d.Random,
			FirstSeen: d.FirstSeen.UTC().Format(time.RFC3339),
			LastSeen:  d.LastSeen.UTC().Format(time.RFC3339),
		}
		if d.IP.IsValid() {
			rd.IP = d.IP.String()
		}
		if d.IPv6.IsValid() {
			rd.IPv6 = d.IPv6.String()
		}
		if share {
			rd.Name = d.Name
		}
		rd.Findings = a.find.deviceFindings(d.Key)
		rd.Flagged = len(rd.Findings) > 0
		req.Devices = append(req.Devices, rd)
	}
	sort.SliceStable(req.Devices, func(i, j int) bool { return req.Devices[i].Flagged && !req.Devices[j].Flagged })
	if !a.due("devices") {
		return
	}
	err := a.client.ReportRouterDevices(req)
	if a.rateLimited("devices", err) {
		return
	}
	if api.IsNotFound(err) {
		a.mu.Lock()
		a.devicesNotFound = time.Now()
		a.mu.Unlock()
		return
	}
	if err != nil && !api.IsHeld(err) {
		log.Printf("[api] device report: %v", err)
	}
}

// deadManAfter: without a successful sync for this long, Full protection
// falls back to Learning. A list entry that cut the router off its
// dashboard (or a dashboard gone for good) must not keep blocking forever.
const deadManAfter = 24 * time.Hour

func (a *agent) deadMan() {
	a.mu.Lock()
	stale := a.synced && a.mode == fw.Full && !a.lastSync.IsZero() && time.Since(a.lastSync) > deadManAfter
	if stale {
		a.mode = fw.Learning
	}
	a.mu.Unlock()
	if !stale {
		return
	}
	log.Printf("[agent] no sync with the dashboard for %s: Full protection suspended (Learning) until the next sync", deadManAfter)
	a.setError("no sync for 24 h: Learning until the dashboard answers")
	a.find.setMode(fw.Learning)
	if a.fw != nil {
		if err := a.fw.SetMode(fw.Learning); err != nil {
			log.Printf("[firewall] %v", err)
		}
	}
	a.applyDNS()
}

// oldDnsmasqCap limits the list on dnsmasq before 2.86 (OpenWrt 21.02),
// whose per-query cost grows with the number of local= entries.
func oldDnsmasqCap(info sysinfo.Info) int {
	if sysinfo.OldDnsmasq(info.Dnsmasq) {
		return 20000
	}
	return 0
}

// due says whether a request kind may be sent (not inside a 429's
// Retry-After).
func (a *agent) due(kind string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return time.Now().After(a.retryAt[kind])
}

// rateLimited handles a 429: the request is tried again after the
// Retry-After (at least a minute, at most an hour; 5 minutes when the
// reply gives none). Logged, never shown as an error, never a refusal.
func (a *agent) rateLimited(kind string, err error) bool {
	wait, ok := api.RateLimited(err)
	if !ok {
		return false
	}
	if wait <= 0 {
		wait = 5 * time.Minute
	}
	wait = min(max(wait, time.Minute), time.Hour)
	a.mu.Lock()
	a.retryAt[kind] = time.Now().Add(wait)
	a.mu.Unlock()
	log.Printf("[api] %s rate limited by the dashboard: next try in %s", kind, wait.Round(time.Second))
	return true
}
