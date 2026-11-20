package watcher

import (
	"encoding/json"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// http_flood: the plain request volume of one address, counted across every
// access log the watcher reads (all vhosts, cPanel domlogs, nginx, Apache,
// LiteSpeed together). The connection count of internal/monitor/flood.go
// misses it: with keep-alive a single connection carries thousands of
// requests.
//
// It is a direct threshold rule with its own ban durations, not a score:
// a flood is a volume problem, not an attack pattern. Through addScore it
// would wait for the score to reach the block level (and the scored ban's
// duration is the dashboard's escalation, 24 h at the first ban), while a
// flood has to stop within the minute it crosses the threshold, and its
// first ban is short (30 minutes) because a misbehaving client (a broken
// script, an uptime checker set too tight) is more common than an attacker.

const (
	httpFloodType = "http_flood"
	// httpFloodDefault requests in the window (10 per second for a minute),
	// waf_config.thresholds["http_flood"] overrides it.
	httpFloodDefault = 600
	// httpFloodMin and httpFloodMax bound the threshold from the dashboard
	// (its settings page enforces the same range, an API write may not): a
	// value outside is clamped, so a typo cannot ban ordinary visitors.
	httpFloodMin = 120
	httpFloodMax = 10000

	// The window is floodBuckets buckets of floodBucketSecs: 60 s, slid in
	// 5 s steps (the count covers the last 55 to 60 seconds).
	floodBucketSecs = 5
	floodBuckets    = 12
	floodWindowSecs = floodBucketSecs * floodBuckets

	// floodMaxIPs bounds the addresses counted at once (≈100 bytes each);
	// at the cap a new address is not counted until idle ones are pruned.
	floodMaxIPs = 50000
	// floodMaxSamples bounds the addresses whose hosts, paths and statuses
	// are recorded, from a quarter of the threshold on: the top hosts, paths
	// and status mix of an event count the requests from then
	// (sampled_requests).
	floodMaxSamples = 1024
	floodTopSlots   = 16
	floodMaxField   = 256

	floodMaxStrikes = 10000
	floodMaxNotes   = 4096
	// floodPruneEvery: at the cap, idle addresses are pruned at most this often.
	floodPruneEvery = 5 * time.Second
	// floodStrikeMemory: a ban within this time of the previous one is the
	// next step of floodBanSteps.
	floodStrikeMemory = 24 * time.Hour
	// floodReportEvery: a flood that is only reported (Learning,
	// detect-only, DNS unavailable) is reported once per address in it.
	floodReportEvery = time.Hour
	// floodCDNReportEvery: the CDN edge event, once per log file.
	floodCDNReportEvery = 24 * time.Hour
	// floodExemptQuiet: an exempt address is not checked again for this
	// many buckets (one hour).
	floodExemptQuiet = 720
)

// floodBanSteps: first ban, again within 24 h, a third time (and later).
var floodBanSteps = []time.Duration{30 * time.Minute, 6 * time.Hour, 24 * time.Hour}

// floodBacklogBytes: a log chunk read at once beyond this is a backlog
// (about 40,000 lines in half a second), not counted.
const floodBacklogBytes = 8 << 20

// floodStatic: a request http_flood does not count, a static file served
// as such (by its extension, answered below 400). Not by path prefix, and
// not a PHP script with a static-looking PATH_INFO: those run code.
func floodStatic(uriLower string, status int) bool {
	if status >= 400 || strings.Contains(uriLower, ".php") {
		return false
	}
	path := uriLower
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	for _, ext := range staticExtensions {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

// setFloodBacklog marks the lines of logPath being processed as a backlog.
func (w *WebWatcher) setFloodBacklog(logPath string, on bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if on {
		w.floodBacklog[logPath] = true
	} else {
		delete(w.floodBacklog, logPath)
	}
}

// floodNow is replaced in tests.
var floodNow = time.Now

// TimedBanFunc bans ip for duration (the ban carries its own expiry).
type TimedBanFunc func(ip, reason string, duration time.Duration)

// floodCounter counts one address' requests per bucket. Two slots keep the
// web servers apart: a request that passes nginx in front of Apache is
// logged by both, so the flood count is the larger slot, not the sum.
type floodCounter struct {
	last   uint32 // bucket number of the newest bucket
	quiet  uint32 // no new crossing before this bucket number
	tag    [2]uint8
	sum    [2]uint32
	b      [2][floodBuckets]uint16
	sample *floodSample
}

// add counts one request in bucket from the server tag and returns the
// count of the window. O(1): at most floodBuckets buckets are cleared.
func (c *floodCounter) add(bucket uint32, tag uint8) uint32 {
	if bucket > c.last {
		gap := bucket - c.last
		if gap >= floodBuckets {
			c.b, c.sum = [2][floodBuckets]uint16{}, [2]uint32{}
		} else {
			for i := uint32(1); i <= gap; i++ {
				idx := (c.last + i) % floodBuckets
				for s := range c.b {
					c.sum[s] -= uint32(c.b[s][idx])
					c.b[s][idx] = 0
				}
			}
		}
		c.last = bucket
	}
	// (A clock that went back counts in the newest bucket.)
	slot := 0
	switch {
	case c.tag[0] == 0:
		c.tag[0] = tag
	case c.tag[0] == tag:
	case c.tag[1] == 0:
		c.tag[1], slot = tag, 1
	default:
		slot = 1 // a third web server counts with the second
	}
	idx := c.last % floodBuckets
	if c.b[slot][idx] < 0xffff {
		c.b[slot][idx]++
		c.sum[slot]++
	}
	return max(c.sum[0], c.sum[1])
}

// idle: no request for a whole window, and no quiet period running.
func (c *floodCounter) idle(bucket uint32) bool {
	return bucket >= c.last+floodBuckets && bucket >= c.quiet
}

// serverTag numbers the web server of a log for floodCounter (0 is unused).
func serverTag(server string) uint8 {
	switch server {
	case "nginx":
		return 2
	case "apache":
		return 3
	case "litespeed":
		return 4
	case "caddy":
		return 5
	case "traefik":
		return 6
	case "haproxy":
		return 7
	}
	return 1
}

// floodTop counts up to floodTopSlots distinct values; later ones are not
// kept (the top 3 of a flood are among the first values it sends).
type floodTop struct {
	names  [floodTopSlots]string
	counts [floodTopSlots]uint32
}

func (t *floodTop) add(s string) {
	if s == "" {
		return
	}
	for i := range t.names {
		switch t.names[i] {
		case s:
			t.counts[i]++
			return
		case "":
			// A copy: s points into the log line.
			t.names[i], t.counts[i] = strings.Clone(s), 1
			return
		}
	}
}

// top is the n most frequent values with their counts, as a JSON object
// ({"example.com":451}): event details are strings.
func (t *floodTop) top(n int) string {
	idx := make([]int, 0, floodTopSlots)
	for i, s := range t.names {
		if s != "" {
			idx = append(idx, i)
		}
	}
	sort.SliceStable(idx, func(a, b int) bool { return t.counts[idx[a]] > t.counts[idx[b]] })
	out := make(map[string]uint32, n)
	for _, i := range idx {
		if len(out) == n {
			break
		}
		out[t.names[i]] = t.counts[i]
	}
	return floodJSON(out)
}

// floodJSON encodes an event detail object (never fails for these maps).
func floodJSON(m map[string]uint32) string {
	b, err := json.Marshal(m)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// first is the most frequent value.
func (t *floodTop) first() string {
	best := -1
	for i, s := range t.names {
		if s != "" && (best < 0 || t.counts[i] > t.counts[best]) {
			best = i
		}
	}
	if best < 0 {
		return ""
	}
	return t.names[best]
}

// floodSample is what an address near the threshold requests.
type floodSample struct {
	hosts, paths, agents floodTop
	status               [6]uint32 // 1xx..5xx at 1..5, anything else at 0
}

func (s *floodSample) record(host string, e *accessLogEntry) {
	s.hosts.add(floodClean(host))
	path := e.uri
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	s.paths.add(floodClean(path))
	s.agents.add(floodClean(e.userAgent))
	k := e.status / 100
	if k < 1 || k > 5 {
		k = 0
	}
	s.status[k]++
}

// sampled is the number of requests recorded.
func (s *floodSample) sampled() uint32 {
	var n uint32
	for _, c := range s.status {
		n += c
	}
	return n
}

// statusMix is the requests per status class as a JSON object
// ({"2xx":580,"4xx":20}; "other" for a status the log did not have).
func (s *floodSample) statusMix() string {
	out := map[string]uint32{}
	for k := 1; k <= 5; k++ {
		if s.status[k] > 0 {
			out[strconv.Itoa(k)+"xx"] = s.status[k]
		}
	}
	if s.status[0] > 0 {
		out["other"] = s.status[0]
	}
	return floodJSON(out)
}

// floodClean bounds a logged value for an event: at most floodMaxField
// bytes of valid UTF-8, control, format (bidi overrides, zero-width) and
// line separator characters replaced. Returns s itself when it is printable
// ASCII (no allocation on the hot path).
func floodClean(s string) string {
	clean := len(s) <= floodMaxField
	for i := 0; clean && i < len(s); i++ {
		clean = s[i] >= 0x20 && s[i] < 0x7f
	}
	if clean {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
			r = '?'
		}
		if b.Len()+utf8.RuneLen(r) > floodMaxField {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// floodStrike is the ban history of one address.
type floodStrike struct {
	n        int       // bans in a row, each within floodStrikeMemory of the previous one's end
	active   bool      // the last ban is still in force (w.banned)
	until    time.Time // the last ban's end
	reported time.Time // the last report-only event
	// undecided: the last crossing whose crawler claim DNS could not decide.
	undecided time.Time
}

type floodState struct {
	ips        map[string]*floodCounter
	samples    int
	lastPrune  time.Time
	fullLogged time.Time
	strikes    map[string]*floodStrike
	// notes: exempt addresses already logged ("reason ip").
	notes map[string]bool
	// clampLogged: the out-of-range threshold last logged.
	clampLogged int
	// cdnReported: log file → last CDN edge event.
	cdnReported map[string]time.Time
}

func newFloodState() *floodState {
	return &floodState{
		ips:         make(map[string]*floodCounter),
		strikes:     make(map[string]*floodStrike),
		notes:       make(map[string]bool),
		cdnReported: make(map[string]time.Time),
	}
}

func (f *floodState) drop(ip string) {
	if c := f.ips[ip]; c != nil {
		if c.sample != nil {
			f.samples--
		}
		delete(f.ips, ip)
	}
}

// floodEvictProbe: counters looked at to make room at the cap.
const floodEvictProbe = 8

// evictLow makes room at the cap: of a few counters (the map's random
// iteration order), the one with the fewest requests goes, unless all have
// a quarter of the threshold or more. So addresses sending one request a
// minute cannot keep a flooder from being counted.
func (f *floodState) evictLow(keepFrom uint32) bool {
	victim, low, seen := "", uint32(0), 0
	for ip, c := range f.ips {
		if n := max(c.sum[0], c.sum[1]); victim == "" || n < low {
			victim, low = ip, n
		}
		if seen++; seen == floodEvictProbe {
			break
		}
	}
	if victim == "" || low >= keepFrom {
		return false
	}
	f.drop(victim)
	return true
}

// prune drops the addresses idle for a whole window and the ban history
// older than floodStrikeMemory.
func (f *floodState) prune(now time.Time) {
	f.lastPrune = now
	bucket := uint32(now.Unix() / floodBucketSecs)
	for ip, c := range f.ips {
		if c.idle(bucket) {
			f.drop(ip)
		}
	}
	for ip, s := range f.strikes {
		if !s.active && now.Sub(s.until) > floodStrikeMemory && now.Sub(s.reported) > floodReportEvery && now.Sub(s.undecided) > floodReportEvery {
			delete(f.strikes, ip)
		}
	}
	for k, t := range f.cdnReported {
		if now.Sub(t) > floodCDNReportEvery {
			delete(f.cdnReported, k)
		}
	}
}

// floodStrike is the ban history of ip, created when missing. Bounded: when
// full, the history is dropped, which only makes the next bans shorter (the
// addresses still banned are counted again, their bans end in the
// firewall). Must be called with w.mu held.
func (w *WebWatcher) floodStrike(ip string) *floodStrike {
	f := w.flood
	s := f.strikes[ip]
	if s == nil {
		if len(f.strikes) >= floodMaxStrikes {
			f.prune(floodNow())
			if len(f.strikes) >= floodMaxStrikes {
				for k, old := range f.strikes {
					if old.active && w.scoredActions[k] == "" {
						delete(w.banned, k)
					}
				}
				f.strikes = make(map[string]*floodStrike)
			}
		}
		s = &floodStrike{}
		f.strikes[ip] = s
	}
	return s
}

// SetOnTimedBan sets the callback for bans with their own duration
// (http_flood). Without it those bans go through onBan.
func (w *WebWatcher) SetOnTimedBan(fn TimedBanFunc) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.onTimedBan = fn
}

// SetNeverBan sets a check for addresses that must never be banned beyond
// the ones the watcher knows (the server's own addresses, the protected
// ones of the firewall).
func (w *WebWatcher) SetNeverBan(fn func(ip string) bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.neverBan = fn
}

// floodThreshold is the requests per minute that make a flood. Must be
// called with w.mu held.
func (w *WebWatcher) floodThreshold() int {
	v := w.wafThreshold(httpFloodType, httpFloodDefault)
	c := min(max(v, httpFloodMin), httpFloodMax)
	if c != v && w.flood.clampLogged != v {
		w.flood.clampLogged = v
		log.Printf("[webwatcher] http_flood threshold %d is outside %d-%d requests per minute: %d is used", v, httpFloodMin, httpFloodMax, c)
	}
	return c
}

// countFlood counts a request of ip (static resources excluded by the
// caller) and acts when the address crosses the threshold. O(1) per line.
// Must be called with w.mu held.
func (w *WebWatcher) countFlood(ip, logPath, line, server string, e *accessLogEntry) {
	if w.flood == nil {
		w.flood = newFloodState()
	}
	f := w.flood
	now := floodNow()
	c := f.ips[ip]
	if c == nil {
		if len(f.ips) >= floodMaxIPs {
			if now.Sub(f.lastPrune) >= floodPruneEvery {
				f.prune(now)
			}
			if len(f.ips) >= floodMaxIPs && !f.evictLow(uint32(w.floodThreshold()/4)) {
				if now.Sub(f.fullLogged) >= 10*time.Minute {
					f.fullLogged = now
					log.Printf("[webwatcher] http_flood: %d addresses counted at once, new ones are not counted until idle ones expire", floodMaxIPs)
				}
				return
			}
		}
		c = &floodCounter{}
		f.ips[ip] = c
	}
	bucket := uint32(now.Unix() / floodBucketSecs)
	n := c.add(bucket, serverTag(server))
	threshold := w.floodThreshold()
	if c.sample == nil && n >= uint32(threshold/4) && f.samples < floodMaxSamples {
		c.sample = &floodSample{}
		f.samples++
	}
	if c.sample != nil {
		c.sample.record(w.floodHost(logPath, e), e)
	}
	if n < uint32(threshold) || bucket < c.quiet {
		return
	}
	c.quiet = bucket + floodBuckets
	details := w.floodDetails(e, c, n, threshold)
	if c.sample != nil {
		c.sample = nil
		f.samples--
	}
	w.floodCrossed(ip, logPath, line, e.userAgent, c, bucket, details)
}

// floodHost is the site a request was for.
func (w *WebWatcher) floodHost(logPath string, e *accessLogEntry) string {
	if e.domain != "" {
		return e.domain
	}
	if d := w.domainMap[logPath]; len(d) > 0 {
		return d[0]
	}
	return ""
}

func (w *WebWatcher) floodDetails(e *accessLogEntry, c *floodCounter, n uint32, threshold int) map[string]string {
	d := map[string]string{
		"requests":       strconv.FormatUint(uint64(n), 10),
		"window_seconds": strconv.Itoa(floodWindowSecs),
		"threshold":      strconv.Itoa(threshold),
		"method":         floodClean(e.method),
		"uri":            floodClean(e.uri),
		"user_agent":     floodClean(e.userAgent),
	}
	if s := c.sample; s != nil {
		d["top_hosts"] = s.hosts.top(3)
		d["top_paths"] = s.paths.top(3)
		d["status_mix"] = s.statusMix()
		d["sampled_requests"] = strconv.FormatUint(uint64(s.sampled()), 10)
		if ua := s.agents.first(); ua != "" {
			d["user_agent"] = ua
		}
		if h := s.hosts.first(); h != "" {
			d["domain"] = h
		}
	}
	return d
}

// floodCrossed decides what a crossing does: an exempt address is logged
// once, a CDN edge reported once per log file, a search engine crawler
// verified first, anything else banned or reported (floodAct). Must be
// called with w.mu held.
func (w *WebWatcher) floodCrossed(ip, logPath, line, ua string, c *floodCounter, bucket uint32, d map[string]string) {
	exempt := ""
	switch {
	case w.isWhitelisted(ip):
		exempt = "whitelisted"
	case floodReserved(ip):
		exempt = "private_address"
	case w.neverBan != nil && w.neverBan(ip):
		exempt = "protected_address"
	}
	if exempt != "" {
		c.quiet = bucket + floodExemptQuiet
		w.floodNote(ip, exempt, d)
		return
	}
	if cdn := cdnProvider(ip); cdn != "" {
		c.quiet = bucket + floodExemptQuiet
		w.floodCDN(ip, cdn, logPath, line, d)
		return
	}
	if slug := crawlerSlug(ua); slug != "" {
		// The flood is acted on once FCrDNS has decided: the real crawler
		// is never banned (it would drop the sites from search results).
		w.withBotVerdict(ip, slug, func(v fcrdnsVerdict, hostname string) {
			if hostname != "" {
				d["fcrdns_hostname"] = floodClean(hostname)
			}
			switch v {
			case fcrdnsVerified:
				d["fcrdns_verified"] = "true"
				if fc := w.flood.ips[ip]; fc != nil {
					fc.quiet = max(fc.quiet, bucket+floodExemptQuiet)
				}
				w.floodNote(ip, "verified_crawler", d)
			case fcrdnsImpostor:
				d["fcrdns_verified"] = "false"
				w.floodAct(ip, logPath, line, d, "")
			default:
				// DNS could not decide. The User-Agent is the client's and its
				// reverse DNS may be made to fail on purpose: only the first
				// crossing is spared, a flood still going on within the hour
				// is banned.
				d["fcrdns_verified"] = "unknown"
				s := w.floodStrike(ip)
				now := floodNow()
				again := !s.undecided.IsZero() && now.Sub(s.undecided) <= floodReportEvery
				s.undecided = now
				if again {
					w.floodAct(ip, logPath, line, d, "")
				} else {
					w.floodAct(ip, logPath, line, d, "dns_unavailable")
				}
			}
		})
		return
	}
	w.floodAct(ip, logPath, line, d, "")
}

// floodAct bans a flood, or only reports it: in Learning, when the type is
// detect-only, or for notBanned. One event per ban, and one per
// floodReportEvery when not banned. Must be called with w.mu held.
func (w *WebWatcher) floodAct(ip, logPath, line string, d map[string]string, notBanned string) {
	if w.banned[ip] {
		return
	}
	f := w.flood
	now := floodNow()
	switch {
	case notBanned != "":
	case w.monitorMode:
		notBanned = "learning"
	case w.isDetectOnly(httpFloodType):
		notBanned = "detect_only"
	}
	s := w.floodStrike(ip)
	if notBanned != "" {
		if !s.reported.IsZero() && now.Sub(s.reported) < floodReportEvery {
			return
		}
		s.reported = now
		d["action"], d["not_banned"] = "reported", notBanned
		log.Printf("[webwatcher] %s: %s requests in %ds (http_flood threshold %s) — reported, not banned (%s)", ip, d["requests"], floodWindowSecs, d["threshold"], notBanned)
		go w.onEvent(ip, httpFloodType, "warning", w.enrichDetails(logPath, line, "", d))
		return
	}

	if s.n > 0 && now.Sub(s.until) <= floodStrikeMemory {
		s.n++
	} else {
		s.n = 1
	}
	// The ban itself may still be refused by the ban path (protection
	// switched off, already banned): neverBan has ruled out the addresses it
	// refuses, so the event says what was asked.
	step := min(s.n, len(floodBanSteps))
	dur := floodBanSteps[step-1]
	s.active, s.until = true, now.Add(dur)
	w.banned[ip] = true
	f.drop(ip)

	d["action"] = "banned"
	d["ban_level"] = strconv.Itoa(step)
	d["ban_seconds"] = strconv.Itoa(int(dur.Seconds()))
	d["ban_until"] = s.until.UTC().Format(time.RFC3339)
	log.Printf("[webwatcher] %s: %s requests in %ds (http_flood threshold %s) — banned for %s (step %d)", ip, d["requests"], floodWindowSecs, d["threshold"], dur, step)
	if w.onTimedBan != nil {
		go w.onTimedBan(ip, httpFloodType, dur)
	} else {
		go w.onBan(ip, httpFloodType, 1)
	}
	go w.onEvent(ip, httpFloodType, "critical", w.enrichDetails(logPath, line, "", d))
}

// floodNote logs once that an exempt address crossed the threshold.
func (w *WebWatcher) floodNote(ip, why string, d map[string]string) {
	f := w.flood
	key := why + " " + ip
	if f.notes[key] {
		return
	}
	if len(f.notes) >= floodMaxNotes {
		f.notes = make(map[string]bool)
	}
	f.notes[key] = true
	log.Printf("[webwatcher] %s: %s requests in %ds (http_flood threshold %s) — never banned: %s", ip, d["requests"], floodWindowSecs, d["threshold"], why)
}

// floodCDN reports, once per log file a day, that a flood came from a CDN
// edge: the visitor behind it is not in the log, and the edge is never
// banned.
func (w *WebWatcher) floodCDN(ip, cdn, logPath, line string, d map[string]string) {
	w.floodNote(ip, "cdn_edge ("+cdn+")", d)
	f := w.flood
	now := floodNow()
	if t, ok := f.cdnReported[logPath]; ok && now.Sub(t) < floodCDNReportEvery {
		return
	}
	f.cdnReported[logPath] = now
	d["action"], d["not_banned"], d["cdn"] = "reported", "cdn_edge", cdn
	d["hint"] = "The access log records the " + cdn + " edge address, not the visitor's: the real client is hidden behind the proxy, so a flood cannot be banned. Log the visitor's address (Apache mod_remoteip, nginx real_ip, LiteSpeed \"Use Client IP in Header\")."
	go w.onEvent(ip, httpFloodType, "warning", w.enrichDetails(logPath, line, "", d))
}

// floodReserved: addresses that are never a remote client (loopback,
// private, link-local, CGNAT, unspecified, multicast).
func floodReserved(ip string) bool {
	a := net.ParseIP(ip)
	if a == nil {
		return true // not an address: fail safe
	}
	if isPrivateIP(ip) || a.IsUnspecified() || a.IsMulticast() {
		return true
	}
	return cgnatNet.Contains(a)
}

var cgnatNet = &net.IPNet{IP: net.IPv4(100, 64, 0, 0).To4(), Mask: net.CIDRMask(10, 32)}

// crawlerUA maps a User-Agent token to the search engine crawler it claims
// (the slugs of knownBotDomains that searchEngineSlugs never bans).
var crawlerUA = []struct{ token, slug string }{
	{"googlebot", "googlebot"},
	{"google-inspectiontool", "googlebot"},
	{"googleother", "googlebot"},
	{"adsbot-google", "google-adsbot"},
	{"mediapartners-google", "google-mediabot"},
	{"feedfetcher-google", "google-feedfetch"},
	{"bingbot", "bingbot"},
	{"msnbot", "msnbot"},
	{"bingpreview", "bingpreview"},
	{"yahoo! slurp", "yahoo-slurp"},
	{"duckduckbot", "duckduckbot"},
	{"applebot", "applebot"},
}

// crawlerSlug is the search engine crawler ua claims, "" for none.
func crawlerSlug(ua string) string {
	l := strings.ToLower(ua)
	for _, c := range crawlerUA {
		if strings.Contains(l, c.token) {
			return c.slug
		}
	}
	return ""
}

// pruneFlood drops idle counters and old ban history, and lets an address
// whose http_flood ban ended be counted again. Takes w.mu.
func (w *WebWatcher) pruneFlood() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.flood == nil {
		return
	}
	now := floodNow()
	for ip, s := range w.flood.strikes {
		if s.active && now.After(s.until) && w.scoredActions[ip] == "" {
			delete(w.banned, ip)
			s.active = false
		}
	}
	w.flood.prune(now)
}
