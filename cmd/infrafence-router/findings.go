package main

import (
	"fmt"
	"log"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/router/dnsblock"
	"github.com/infrafence/infrafence-agent/internal/router/fw"
	"github.com/infrafence/infrafence-agent/internal/router/lan"
)

// Event types a router sends (see the dashboard contract).
const (
	evC2       = "lan_device_c2"
	evMiner    = "lan_device_miner"
	evDGA      = "lan_device_dga"
	evScanning = "lan_device_scanning"
	evBlocked  = "blocked_domain"
	evFWReset  = "router_firewall_reset"
)

// Cooldowns: one event per device and finding per period.
var (
	c2Cooldown        = time.Hour
	conntrackCooldown = 6 * time.Hour
	blockedWindow     = time.Hour
	flaggedFor        = 24 * time.Hour
)

// findings turns observations into events, de-duplicated and aggregated so
// a busy household never floods the dashboard (never one event per query).
type findings struct {
	client *api.Client
	inv    *lan.Inventory
	now    func() time.Time

	mu       sync.Mutex
	share    bool
	mode     fw.Mode
	reported map[string]time.Time
	// hitPackets: last packet count seen per (device, C2) pair.
	hitPackets map[string]uint64
	blocked    map[string]*blockedAgg // per device key
	flagged    map[string]map[string]time.Time
	send       func([]api.EventRequest) // tests
	// Rate limit: at most eventBurst events, refilled at eventRate per
	// minute (a LAN device forging lookups from many addresses must not
	// flood the dashboard or the router's memory).
	tokens   float64
	lastFill time.Time
	limited  uint64
}

const (
	eventBurst  = 60
	eventRate   = 30 // per minute
	maxReported = 20000
)

// emit sends events within the rate limit.
func (f *findings) emit(evs []api.EventRequest) {
	if len(evs) == 0 {
		return
	}
	now := f.now()
	f.mu.Lock()
	if f.lastFill.IsZero() {
		f.tokens, f.lastFill = eventBurst, now
	}
	f.tokens = min(eventBurst, f.tokens+now.Sub(f.lastFill).Minutes()*eventRate)
	f.lastFill = now
	keep := evs[:0:0]
	for _, e := range evs {
		if f.tokens < 1 {
			f.limited++
			continue
		}
		f.tokens--
		keep = append(keep, e)
	}
	limited := f.limited
	f.mu.Unlock()
	if len(keep) < len(evs) && limited%100 == uint64(len(evs)-len(keep)) {
		log.Printf("[events] rate limit: %d events dropped so far", limited)
	}
	if len(keep) > 0 {
		f.send(keep)
	}
}

type blockedAgg struct {
	device   lan.Device
	known    bool
	start    time.Time
	count    int // lookups after the first (reported at the window's end)
	domains  map[string]bool
	cats     map[string]bool
	blocking bool
}

func newFindings(c *api.Client, inv *lan.Inventory, now func() time.Time) *findings {
	f := &findings{
		client:     c,
		inv:        inv,
		now:        now,
		reported:   map[string]time.Time{},
		hitPackets: map[string]uint64{},
		blocked:    map[string]*blockedAgg{},
		flagged:    map[string]map[string]time.Time{},
	}
	f.send = func(evs []api.EventRequest) {
		if err := c.ReportEvents(evs); err != nil {
			log.Printf("[events] queue: %v", err)
		}
	}
	return f
}

func (f *findings) setShareNames(v bool) {
	f.mu.Lock()
	f.share = v
	f.mu.Unlock()
}

func (f *findings) setMode(m fw.Mode) {
	f.mu.Lock()
	f.mode = m
	f.mu.Unlock()
}

// due says whether key may be reported again (and records it).
func (f *findings) due(key string, cooldown time.Duration, now time.Time) bool {
	if t, ok := f.reported[key]; ok && now.Sub(t) < cooldown {
		return false
	}
	if len(f.reported) >= maxReported {
		for k, t := range f.reported {
			if now.Sub(t) > cooldown {
				delete(f.reported, k)
			}
		}
		if len(f.reported) >= maxReported {
			return false // full of recent keys: report nothing new until they age
		}
	}
	f.reported[key] = now
	return true
}

// deviceDetails are a device's fields in an event.
func (f *findings) deviceDetails(d lan.Device, known bool) map[string]string {
	m := map[string]string{"device_key": d.Key}
	if d.IP.IsValid() {
		m["device_ip"] = d.IP.String()
	}
	if d.OUI != "" {
		m["device_mac_oui"] = d.OUI
	}
	if d.Random {
		m["device_randomized_mac"] = "true"
	}
	if f.share && d.Name != "" {
		m["device_name"] = d.Name
	}
	if !known {
		m["device_known"] = "false"
	}
	return m
}

func (f *findings) action() string {
	if f.mode == fw.Full {
		return "blocked"
	}
	return "would_block"
}

func (f *findings) flag(key, typ string, now time.Time) {
	m := f.flagged[key]
	if m == nil {
		if len(f.flagged) >= 2048 {
			return
		}
		m = map[string]time.Time{}
		f.flagged[key] = m
	}
	m[typ] = now
}

func event(typ, sev, remote string, d map[string]string, now time.Time) api.EventRequest {
	return api.EventRequest{Type: typ, Severity: sev, SourceIP: remote, Details: d, OccurredAt: now.UTC().Format(time.RFC3339)}
}

// c2Hit: the kernel saw a LAN device (or the router) reach a C2 address.
func (f *findings) c2Hit(h fw.Hit, source string, fromRouter bool) {
	now := f.now()
	dev, known := f.inv.Lookup(h.Src)
	f.mu.Lock()
	key := h.Src.String() + ">" + h.Dst.String()
	last, seen := f.hitPackets[key]
	f.hitPackets[key] = h.Packets
	if len(f.hitPackets) > 8192 {
		f.hitPackets = map[string]uint64{key: h.Packets}
	}
	// Report a pair once per cooldown, and again later only if it is still
	// sending (the kernel keeps a pair for an hour).
	if seen && h.Packets > 0 && h.Packets <= last || !f.due("c2:"+key, c2Cooldown, now) {
		f.mu.Unlock()
		return
	}
	d := f.deviceDetails(dev, known)
	if fromRouter {
		d = map[string]string{"device": "router", "device_ip": h.Src.String()}
	}
	d["remote_ip"] = h.Dst.String()
	d["action"] = f.action()
	d["detected_by"] = "firewall"
	if h.Packets > 0 {
		d["packets"] = strconv.FormatUint(h.Packets, 10)
	}
	if source != "" {
		d["c2_source"] = source
	}
	f.flag(dev.Key, evC2, now)
	f.mu.Unlock()
	f.emit([]api.EventRequest{event(evC2, "critical", h.Dst.String(), d, now)})
}

// listedLookup: a LAN device looked up a listed domain. Miner and C2
// domains raise their own findings; every listed lookup counts toward the
// device's hourly blocked_domain event.
func (f *findings) listedLookup(src netip.Addr, name, listed string, cat dnsblock.Category, blocking bool) {
	now := f.now()
	dev, known := f.inv.Lookup(src)
	var out []api.EventRequest
	f.mu.Lock()
	switch cat {
	case dnsblock.CatMiner, dnsblock.CatC2:
		typ := evMiner
		if cat == dnsblock.CatC2 {
			typ = evC2
		}
		if f.due(typ+":dns:"+dev.Key+":"+listed, c2Cooldown, now) {
			d := f.deviceDetails(dev, known)
			d["domain"] = name
			d["listed_domain"] = listed
			d["category"] = cat.String()
			d["detected_by"] = "dns"
			d["action"] = actionDNS(blocking)
			sev := "warning"
			if cat == dnsblock.CatC2 {
				sev = "critical"
			}
			out = append(out, event(typ, sev, "", d, now))
			f.flag(dev.Key, typ, now)
		}
	}
	agg := f.blocked[dev.Key]
	if agg != nil && now.Sub(agg.start) >= blockedWindow {
		out = append(out, f.closeBlocked(agg, now)...)
		delete(f.blocked, dev.Key)
		agg = nil
	}
	if agg == nil {
		if len(f.blocked) >= 1024 {
			f.mu.Unlock()
			f.emit(out)
			return
		}
		agg = &blockedAgg{device: dev, known: known, start: now, domains: map[string]bool{listed: true}, cats: map[string]bool{cat.String(): true}, blocking: blocking}
		f.blocked[dev.Key] = agg
		// The first listed lookup of the window is reported at once.
		d := f.deviceDetails(dev, known)
		d["domain"] = name
		d["listed_domain"] = listed
		d["category"] = cat.String()
		d["count"] = "1"
		d["action"] = actionDNS(blocking)
		d["window"] = "first"
		out = append(out, event(evBlocked, "info", "", d, now))
		f.flag(dev.Key, evBlocked, now)
	} else {
		agg.count++
		if len(agg.domains) < 5 {
			agg.domains[listed] = true
		}
		agg.cats[cat.String()] = true
		agg.blocking = agg.blocking || blocking
	}
	f.mu.Unlock()
	f.emit(out)
}

func actionDNS(blocking bool) string {
	if blocking {
		return "blocked"
	}
	return "would_block"
}

// closeBlocked is the summary of a device's window: the lookups after the
// first one (nothing when there were none).
func (f *findings) closeBlocked(agg *blockedAgg, now time.Time) []api.EventRequest {
	if agg.count == 0 {
		return nil
	}
	d := f.deviceDetails(agg.device, agg.known)
	d["count"] = strconv.Itoa(agg.count)
	d["domains"] = strings.Join(sortedKeys(agg.domains), ", ")
	d["categories"] = strings.Join(sortedKeys(agg.cats), ", ")
	d["action"] = actionDNS(agg.blocking)
	d["window"] = "summary"
	d["window_start"] = agg.start.UTC().Format(time.RFC3339)
	d["window_seconds"] = strconv.Itoa(int(now.Sub(agg.start).Seconds()))
	return []api.EventRequest{event(evBlocked, "info", "", d, now)}
}

// flush closes the blocked-domain windows that ended.
func (f *findings) flush() {
	now := f.now()
	var out []api.EventRequest
	f.mu.Lock()
	for k, agg := range f.blocked {
		if now.Sub(agg.start) >= blockedWindow {
			out = append(out, f.closeBlocked(agg, now)...)
			delete(f.blocked, k)
		}
	}
	for k, m := range f.flagged {
		for t, at := range m {
			if now.Sub(at) > flaggedFor {
				delete(m, t)
			}
		}
		if len(m) == 0 {
			delete(f.flagged, k)
		}
	}
	f.mu.Unlock()
	f.emit(out)
}

func (f *findings) dga(src netip.Addr, n int, examples []string) {
	now := f.now()
	dev, known := f.inv.Lookup(src)
	f.mu.Lock()
	if !f.due("dga:"+dev.Key, c2Cooldown, now) {
		f.mu.Unlock()
		return
	}
	d := f.deviceDetails(dev, known)
	// No example names: they are not listed domains, and only listed
	// domains leave the router.
	d["nonexistent_domains"] = strconv.Itoa(n)
	d["window"] = dgaWindow.String()
	d["detected_by"] = "dns"
	f.flag(dev.Key, evDGA, now)
	f.mu.Unlock()
	f.emit([]api.EventRequest{event(evDGA, "warning", "", d, now)})
}

func (f *findings) conntrack(c lan.Finding) {
	now := f.now()
	dev, known := f.inv.Lookup(c.Device)
	typ, reason := evScanning, c.Kind
	if c.Kind == lan.FindMinerPort {
		typ = evMiner
	}
	f.mu.Lock()
	if !f.due(fmt.Sprintf("ct:%s:%s:%d", dev.Key, c.Kind, c.Port), conntrackCooldown, now) {
		f.mu.Unlock()
		return
	}
	d := f.deviceDetails(dev, known)
	d["reason"] = reason
	d["remote_port"] = strconv.Itoa(c.Port)
	d["remote_hosts"] = strconv.Itoa(c.Count)
	d["detected_by"] = "conntrack"
	if c.Example.IsValid() {
		d["remote_ip"] = c.Example.String()
	}
	f.flag(dev.Key, typ, now)
	f.mu.Unlock()
	f.emit([]api.EventRequest{event(typ, "warning", c.Example.String(), d, now)})
}

func (f *findings) firewallReset(backend string) {
	now := f.now()
	f.mu.Lock()
	if !f.due("fwreset", 10*time.Minute, now) {
		f.mu.Unlock()
		return
	}
	f.mu.Unlock()
	f.emit([]api.EventRequest{event(evFWReset, "warning", "", map[string]string{
		"backend": backend,
		"note":    "the InfraFence firewall rules were removed by another program (ruleset flush?) and were restored",
	}, now)})
}

func (f *findings) flaggedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for k, m := range f.flagged {
		if k != "" && hasFinding(m) {
			n++
		}
	}
	return n
}

// hasFinding: anything but blocked lookups flags a device (a blocked
// lookup is the protection working, not an infection).
func hasFinding(m map[string]time.Time) bool {
	for t := range m {
		if t != evBlocked {
			return true
		}
	}
	return false
}

func (f *findings) deviceFindings(key string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.flagged[key]
	if !hasFinding(m) {
		return nil
	}
	return sortedKeys(func() map[string]bool {
		out := map[string]bool{}
		for t := range m {
			out[t] = true
		}
		return out
	}())
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// dgaTracker counts each device's random-looking non-existent names.
var (
	dgaWindow   = 5 * time.Minute
	dgaDistinct = 20
)

type dgaTracker struct {
	now  func() time.Time
	seen map[netip.Addr]map[string]time.Time
}

func newDGATracker(now func() time.Time) *dgaTracker {
	return &dgaTracker{now: now, seen: map[netip.Addr]map[string]time.Time{}}
}

// add records a name; ok when the device reached the threshold.
func (t *dgaTracker) add(dev netip.Addr, name string) (int, []string, bool) {
	const perDevice = 64
	now := t.now()
	m := t.seen[dev]
	if m == nil {
		if len(t.seen) >= 1024 {
			for k, v := range t.seen {
				if len(v) == 0 {
					delete(t.seen, k)
				}
			}
			if len(t.seen) >= 1024 {
				return 0, nil, false
			}
		}
		m = map[string]time.Time{}
		t.seen[dev] = m
	}
	for k, at := range m {
		if now.Sub(at) > dgaWindow {
			delete(m, k)
		}
	}
	if len(m) < perDevice {
		m[lan.BaseDomain(name)] = now
	}
	if len(m) < dgaDistinct {
		return len(m), nil, false
	}
	ex := make([]string, 0, len(m))
	for k := range m {
		ex = append(ex, k)
	}
	sort.Strings(ex)
	if len(ex) > 5 {
		ex = ex[:5]
	}
	n := len(m)
	t.seen[dev] = map[string]time.Time{}
	return n, ex, true
}
