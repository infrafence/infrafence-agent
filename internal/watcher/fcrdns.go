package watcher

import (
	"context"
	"errors"
	"log"
	"maps"
	"net"
	"strings"
	"sync"
	"time"
)

// fcrdnsResult caches the result of a Forward-Confirmed rDNS check.
type fcrdnsResult struct {
	verified  bool
	hostname  string
	checkedAt time.Time
	undecided bool // DNS failed: kept fcrdnsUndecidedTTL only
}

// fcrdnsCache stores FCrDNS verification results per IP.
type fcrdnsCache struct {
	mu      sync.RWMutex
	entries map[string]fcrdnsResult
	ttl     time.Duration
	// pending: addresses being verified now (one lookup at a time each).
	pending map[string]bool
}

// maxPendingFcrdns bounds the verifications running at once.
const maxPendingFcrdns = 32

// begin claims the verification of ip: false when it is already running,
// or too many are.
func (c *fcrdnsCache) begin(ip string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending == nil {
		c.pending = map[string]bool{}
	}
	if c.pending[ip] || len(c.pending) >= maxPendingFcrdns {
		return false
	}
	c.pending[ip] = true
	return true
}

func (c *fcrdnsCache) end(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.pending, ip)
}

// newFcrdnsCache creates a new FCrDNS cache with the given TTL.
func newFcrdnsCache(ttl time.Duration) *fcrdnsCache {
	return &fcrdnsCache{
		entries: make(map[string]fcrdnsResult),
		ttl:     ttl,
	}
}

// lookup checks if a cached result exists and is still valid.
func (c *fcrdnsCache) lookup(ip string) (fcrdnsResult, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	r, ok := c.entries[ip]
	if !ok {
		return r, false
	}
	ttl := c.ttl
	if r.undecided {
		ttl = fcrdnsUndecidedTTL
	}
	if time.Since(r.checkedAt) > ttl {
		return r, false
	}
	return r, true
}

// storeResult saves a result to the cache.
func (c *fcrdnsCache) storeResult(ip string, verified bool, hostname string, undecided bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[ip] = fcrdnsResult{
		verified:  verified,
		hostname:  hostname,
		checkedAt: time.Now(),
		undecided: undecided,
	}

	// Prune expired entries if cache is large; still too large (many
	// addresses at once): drop entries until under the cap.
	if len(c.entries) > 5000 {
		now := time.Now()
		for k, v := range c.entries {
			if now.Sub(v.checkedAt) > c.ttl {
				delete(c.entries, k)
			}
		}
		for k := range c.entries {
			if len(c.entries) <= 4000 {
				break
			}
			delete(c.entries, k)
		}
	}
}

// knownBotDomains maps bot categories to their legitimate rDNS domain suffixes.
// Only bots in this list are FCrDNS-verified — all others skip verification.
var knownBotDomains = map[string][]string{
	// Google
	"googlebot":        {".googlebot.com", ".google.com"},
	"google-adsbot":    {".googlebot.com", ".google.com"},
	"google-mediabot":  {".googlebot.com", ".google.com"},
	"google-feedfetch": {".google.com"},
	// Bing
	"bingbot":         {".search.msn.com"},
	"msnbot":          {".search.msn.com"},
	"bingpreview":     {".search.msn.com"},
	// Yahoo / Oath
	"yahoo-slurp":     {".crawl.yahoo.net"},
	// Yandex
	"yandexbot":       {".yandex.ru", ".yandex.net", ".yandex.com"},
	// Baidu
	"baiduspider":     {".baidu.com", ".baidu.jp"},
	// Apple
	"applebot":        {".applebot.apple.com"},
	// DuckDuckGo
	"duckduckbot":     {".duckduckgo.com"},
	// Facebook
	"facebookbot":     {".facebook.com", ".fbsv.net"},
	// LinkedIn
	"linkedinbot":     {".linkedin.com"},
	// Twitter
	"twitterbot":      {".twttr.com"},
	// Pinterest
	"pinterestbot":    {".pinterest.com"},
	// Ahrefs
	"ahrefsbot":       {".ahrefs.com"},
	// SEMrush
	"semrushbot":      {".semrush.com"},
}

// searchEngineSlugs are the search engine crawlers a "block" bot rule never
// bans once FCrDNS confirms them: banning the real Googlebot or Bingbot
// takes a site out of search results. An impostor is banned as usual.
var searchEngineSlugs = map[string]bool{
	"googlebot": true, "google-adsbot": true, "google-mediabot": true, "google-feedfetch": true,
	"bingbot": true, "msnbot": true, "bingpreview": true,
	"yahoo-slurp": true, "duckduckbot": true, "applebot": true,
}

// fcrdnsTimeout bounds each DNS lookup of a verification.
const fcrdnsTimeout = 5 * time.Second

// Replaced in tests.
var (
	lookupAddr = func(ctx context.Context, ip string) ([]string, error) { return net.DefaultResolver.LookupAddr(ctx, ip) }
	lookupHost = func(ctx context.Context, host string) ([]string, error) { return net.DefaultResolver.LookupHost(ctx, host) }
)

// verifyFcrdns performs Forward-Confirmed reverse DNS verification.
//
// Steps:
//  1. PTR lookup: IP → hostname (e.g., "crawl-66-249-66-1.googlebot.com")
//  2. Check if hostname ends with an expected domain suffix
//  3. Forward lookup: hostname → IPs
//  4. Verify the original IP is in the forward results
//
// Returns (verified, hostname, decided). verified=true means the bot is
// legitimate; decided=false means the resolver failed (timeout, temporary
// failure): neither verified nor an impostor. Any answer of the address'
// DNS (no name, a refusal, malformed records) decides.
func verifyFcrdns(ip string, expectedSuffixes []string) (bool, string, bool) {
	// Strip IPv4-mapped IPv6 prefix (::ffff:1.2.3.4 → 1.2.3.4)
	// PTR lookups fail on mapped addresses but work on the plain IPv4.
	ip = strings.TrimPrefix(ip, "::ffff:")

	// Step 1: PTR lookup
	ctx, cancel := context.WithTimeout(context.Background(), fcrdnsTimeout)
	names, err := lookupAddr(ctx, ip)
	cancel()
	if err != nil && len(names) == 0 {
		// Only the resolver failing leaves it undecided; any other answer
		// (no name, a refusal, malformed records) is not the crawler.
		return false, "", !dnsTemporary(err)
	}

	// Step 2: a name under an expected domain suffix
	hostname := ""
	for _, n := range names {
		h := strings.TrimSuffix(n, ".")
		for _, suffix := range expectedSuffixes {
			if strings.HasSuffix(strings.ToLower(h), suffix) {
				hostname = h
				break
			}
		}
		if hostname != "" {
			break
		}
	}
	if hostname == "" {
		if len(names) > 0 {
			return false, strings.TrimSuffix(names[0], "."), true
		}
		return false, "", true
	}

	// Step 3: Forward lookup (fully qualified: no search domains)
	ctx, cancel = context.WithTimeout(context.Background(), fcrdnsTimeout)
	addrs, err := lookupHost(ctx, hostname+".")
	cancel()
	if err != nil && len(addrs) == 0 {
		return false, hostname, !dnsTemporary(err)
	}

	// Step 4: Verify original IP is in forward results
	want := net.ParseIP(ip)
	for _, addr := range addrs {
		if a := net.ParseIP(addr); a != nil && a.Equal(want) {
			return true, hostname, true
		}
	}

	return false, hostname, true
}

// dnsTemporary: the lookup failed for a reason of the resolver (timeout,
// temporary failure), not because of what the address' DNS answered.
func dnsTemporary(err error) bool {
	var de *net.DNSError
	return errors.As(err, &de) && (de.IsTimeout || de.IsTemporary)
}

// dnsNotFound: the name does not exist (a definite answer).
func dnsNotFound(err error) bool {
	var de *net.DNSError
	return errors.As(err, &de) && de.IsNotFound
}

// fcrdnsUndecidedTTL: how long a verification that could not be decided is
// kept before trying again.
const fcrdnsUndecidedTTL = 5 * time.Minute

// fcrdnsVerdict is the result of a bot's verification.
type fcrdnsVerdict int

const (
	fcrdnsNotVerifiable fcrdnsVerdict = iota // no rDNS domains known for the bot
	fcrdnsVerified                           // the real crawler
	fcrdnsImpostor                           // claims the bot, rDNS says otherwise
	fcrdnsUndecided                          // DNS failed: neither
)

// botVerdict verifies a bot IP with FCrDNS (cached). slug is the bot
// fingerprint slug (e.g., "googlebot", "bingbot"). Bots without known
// domain suffixes are not verifiable. Runs the lookups: call it from a
// goroutine, never with w.mu held.
func (w *WebWatcher) botVerdict(ip, slug string) (fcrdnsVerdict, string) {
	suffixes, known := knownBotDomains[slug]
	if !known {
		return fcrdnsNotVerifiable, ""
	}
	if v, h, ok := w.cachedBotVerdict(ip, slug); ok {
		return v, h
	}

	verified, hostname, decided := verifyFcrdns(ip, suffixes)
	w.fcrdns.storeResult(fcrdnsKey(ip, slug), verified, hostname, !decided)

	switch {
	case !decided:
		log.Printf("[fcrdns] %s claims %s: DNS lookup failed, not verified either way", ip, slug)
		return fcrdnsUndecided, hostname
	case verified:
		log.Printf("[fcrdns] %s verified as %s (%s)", ip, hostname, slug)
		return fcrdnsVerified, hostname
	case hostname != "":
		log.Printf("[fcrdns] %s SPOOFED: claims %s but rDNS=%s", ip, slug, hostname)
	default:
		log.Printf("[fcrdns] %s SPOOFED: claims %s but no valid rDNS", ip, slug)
	}
	return fcrdnsImpostor, hostname
}

// fcrdnsKey: an address is verified for the bot it claims (the domains
// differ per bot).
func fcrdnsKey(ip, slug string) string { return ip + " " + slug }

// cachedBotVerdict is botVerdict from the cache only (no lookup; safe with
// w.mu held). ok=false when the bot is verifiable and nothing is cached.
func (w *WebWatcher) cachedBotVerdict(ip, slug string) (fcrdnsVerdict, string, bool) {
	if _, known := knownBotDomains[slug]; !known {
		return fcrdnsNotVerifiable, "", true
	}
	r, ok := w.fcrdns.lookup(fcrdnsKey(ip, slug))
	if !ok {
		return 0, "", false
	}
	switch {
	case r.undecided:
		return fcrdnsUndecided, r.hostname, true
	case r.verified:
		return fcrdnsVerified, r.hostname, true
	}
	return fcrdnsImpostor, r.hostname, true
}

// withBotVerdict calls fn with the bot's verdict, w.mu held: right away
// when it is cached, otherwise once a lookup in a goroutine has it. A
// request that comes while the address is being verified (or while too
// many are) is not handled again. Must be called with w.mu held.
func (w *WebWatcher) withBotVerdict(ip, slug string, fn func(fcrdnsVerdict, string)) {
	if v, h, ok := w.cachedBotVerdict(ip, slug); ok {
		fn(v, h)
		return
	}
	key := fcrdnsKey(ip, slug)
	if !w.fcrdns.begin(key) {
		return
	}
	go func() {
		defer w.fcrdns.end(key)
		v, h := w.botVerdict(ip, slug)
		w.mu.Lock()
		defer w.mu.Unlock()
		fn(v, h)
	}()
}

// blockSearchEngineBot applies a "block" rule to a search engine crawler:
// an impostor is banned, the real crawler (and one DNS could not decide)
// is not. Must be called with w.mu held.
func (w *WebWatcher) blockSearchEngineBot(ip, slug string, v fcrdnsVerdict, hostname string, details map[string]string) {
	d := maps.Clone(details)
	if hostname != "" {
		d["fcrdns_hostname"] = hostname
	}
	switch v {
	case fcrdnsImpostor:
		if w.banned[ip] {
			return
		}
		d["fcrdns_verified"] = "false"
		w.banned[ip] = true
		go w.onBan(ip, "bot_blocked", 1)
		go w.onEvent(ip, "bot_detected", "warning", d)
	case fcrdnsVerified:
		if w.botEventDue(ip, slug) {
			d["fcrdns_verified"] = "true"
			d["not_banned"] = "verified_crawler"
			go w.onEvent(ip, "bot_detected", "info", d)
		}
	default:
		if w.botEventDue(ip, slug) {
			d["fcrdns_verified"] = "unknown"
			d["not_banned"] = "dns_unavailable"
			go w.onEvent(ip, "bot_detected", "info", d)
		}
	}
}

// allowVerifiableBot handles an allowed crawler that FCrDNS can verify:
// the real one is reported as a crawl, an impostor goes through the normal
// scoring (bot_spoofed points, ban at the block threshold like any bad
// request). Must be called with w.mu held.
func (w *WebWatcher) allowVerifiableBot(ip, slug string, v fcrdnsVerdict, hostname, logPath, line string, details map[string]string) {
	d := maps.Clone(details)
	if hostname != "" {
		d["fcrdns_hostname"] = hostname
	}
	switch v {
	case fcrdnsImpostor:
		d["fcrdns_verified"] = "false"
		if w.banned[ip] {
			return
		}
		if w.addScore(ip, "bot_spoofed", logPath, line, maps.Clone(d)) {
			return
		}
		// Not reported by the scoring (below the observe level, points set
		// to 0, ModSecurity already reported it): reported once an hour.
		if w.botEventDue(ip, slug) {
			d["bot_action"] = "spoofed"
			go w.onEvent(ip, "bot_spoofed", "warning", d)
		}
	case fcrdnsVerified:
		if w.botEventDue(ip, slug) {
			d["fcrdns_verified"] = "true"
			go w.onEvent(ip, "bot_crawl", "info", d)
		}
	default:
		if w.botEventDue(ip, slug) {
			d["fcrdns_verified"] = "unknown"
			go w.onEvent(ip, "bot_crawl", "info", d)
		}
	}
}
