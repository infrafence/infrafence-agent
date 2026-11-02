package watcher

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeDNS answers the PTR and forward lookups: 66.249.66.1 is the real
// Googlebot, 203.0.113.50 has no PTR record, 203.0.113.60 times out.
func fakeDNS(t *testing.T) {
	oldAddr, oldHost := lookupAddr, lookupHost
	lookupAddr = func(_ context.Context, ip string) ([]string, error) {
		switch ip {
		case "66.249.66.1":
			return []string{"crawl-66-249-66-1.googlebot.com."}, nil
		case "203.0.113.60":
			return nil, &net.DNSError{Err: "i/o timeout", IsTimeout: true}
		}
		return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
	}
	lookupHost = func(_ context.Context, host string) ([]string, error) {
		if host == "crawl-66-249-66-1.googlebot.com" {
			return []string{"66.249.66.1"}, nil
		}
		return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
	}
	t.Cleanup(func() { lookupAddr, lookupHost = oldAddr, oldHost })
}

type botRecorder struct {
	mu     sync.Mutex
	events []string
	bans   []string
}

func (r *botRecorder) event(ip, typ string, d map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ip+" "+typ+" verified="+d["fcrdns_verified"]+" not_banned="+d["not_banned"])
}

func (r *botRecorder) ban(ip, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bans = append(r.bans, ip+" "+reason)
}

func (r *botRecorder) snapshot() ([]string, []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.events...), append([]string(nil), r.bans...)
}

func newBotWatcher(t *testing.T, action string) (*WebWatcher, *botRecorder) {
	fakeDNS(t)
	rec := &botRecorder{}
	w := NewWebWatcher(nil, nil,
		func(ip, reason string, _ int) { rec.ban(ip, reason) },
		func(ip, typ, _ string, d map[string]string) { rec.event(ip, typ, d) })
	w.SetOnScoredBan(func(ip, reason string, _ int, _ time.Duration) { rec.ban(ip, reason) })
	w.UpdateBotFingerprints([]BotFingerprintInput{{Slug: "googlebot", Name: "Googlebot", Pattern: `Googlebot\/`, IsRegex: true, Action: action}})
	return w, rec
}

func googlebotLine(ip string) string {
	return ip + ` - - [02/Nov/2026:10:00:00 +0000] "GET /page HTTP/1.1" 200 512 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"`
}

// waitFor polls until cond holds (the lookups run in goroutines).
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for range 200 {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out")
}

func TestImpostorGooglebotIsScored(t *testing.T) {
	w, rec := newBotWatcher(t, "allow")
	w.processLine("/var/log/nginx/access.log", googlebotLine("203.0.113.50"))
	waitFor(t, func() bool { e, _ := rec.snapshot(); return len(e) == 1 })
	if e, b := rec.snapshot(); e[0] != "203.0.113.50 bot_spoofed verified=false not_banned=" || len(b) != 0 {
		t.Fatalf("first request: events %v bans %v", e, b)
	}
	// A second request past the 2 s dedup: 80 points, banned like any bad request.
	w.mu.Lock()
	w.recentScores = map[string]time.Time{}
	w.mu.Unlock()
	w.processLine("/var/log/nginx/access.log", googlebotLine("203.0.113.50"))
	waitFor(t, func() bool { _, b := rec.snapshot(); return len(b) == 1 })
	if _, b := rec.snapshot(); b[0] != "203.0.113.50 bot_spoofed" {
		t.Fatalf("bans %v", b)
	}
}

func TestRealGooglebotAllowed(t *testing.T) {
	w, rec := newBotWatcher(t, "allow")
	w.processLine("/var/log/nginx/access.log", googlebotLine("66.249.66.1"))
	waitFor(t, func() bool { e, _ := rec.snapshot(); return len(e) == 1 })
	if e, b := rec.snapshot(); e[0] != "66.249.66.1 bot_crawl verified=true not_banned=" || len(b) != 0 {
		t.Fatalf("events %v bans %v", e, b)
	}
}

func TestBlockedGooglebotOnlyImpostorBanned(t *testing.T) {
	w, rec := newBotWatcher(t, "block")
	w.processLine("/var/log/nginx/access.log", googlebotLine("66.249.66.1"))
	w.processLine("/var/log/nginx/access.log", googlebotLine("203.0.113.50"))
	w.processLine("/var/log/nginx/access.log", googlebotLine("203.0.113.60"))
	waitFor(t, func() bool { e, _ := rec.snapshot(); return len(e) == 3 })
	time.Sleep(50 * time.Millisecond)
	e, b := rec.snapshot()
	if len(b) != 1 || b[0] != "203.0.113.50 bot_blocked" {
		t.Fatalf("bans %v (events %v)", b, e)
	}
	want := map[string]bool{
		"66.249.66.1 bot_detected verified=true not_banned=verified_crawler":    true,
		"203.0.113.50 bot_detected verified=false not_banned=":                  true,
		"203.0.113.60 bot_detected verified=unknown not_banned=dns_unavailable": true,
	}
	for _, x := range e {
		if !want[x] {
			t.Errorf("unexpected event %q", x)
		}
	}
}

func TestFcrdnsUndecidedNotCachedLong(t *testing.T) {
	c := newFcrdnsCache(24 * time.Hour)
	c.storeResult("k", false, "", true)
	c.entries["k"] = fcrdnsResult{undecided: true, checkedAt: time.Now().Add(-6 * time.Minute)}
	if _, ok := c.lookup("k"); ok {
		t.Error("an undecided result older than 5 minutes is still cached")
	}
	if !c.begin("a") || c.begin("a") {
		t.Error("one verification per address at a time")
	}
	c.end("a")
	if !c.begin("a") {
		t.Error("begin after end")
	}
}
