package watcher

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type floodRecorder struct {
	mu     sync.Mutex
	events []floodEvent
	bans   []string
}

type floodEvent struct {
	ip, severity string
	d            map[string]string
}

func (r *floodRecorder) snapshot() ([]floodEvent, []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]floodEvent(nil), r.events...), append([]string(nil), r.bans...)
}

// fakeFloodClock makes floodNow return *now.
func fakeFloodClock(t *testing.T) *time.Time {
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	old := floodNow
	floodNow = func() time.Time { return now }
	t.Cleanup(func() { floodNow = old })
	return &now
}

const floodLog = "/usr/local/apache/domlogs/example.com"

func newFloodWatcher(t *testing.T) (*WebWatcher, *floodRecorder, *time.Time) {
	t.Helper()
	now := fakeFloodClock(t)
	rec := &floodRecorder{}
	w := NewWebWatcher(nil, map[string][]string{floodLog: {"example.com"}},
		func(ip, reason string, _ int) {
			rec.mu.Lock()
			defer rec.mu.Unlock()
			rec.bans = append(rec.bans, ip+" "+reason+" untimed")
		},
		func(ip, typ, severity string, d map[string]string) {
			if typ != httpFloodType {
				return // bot_unknown and the like
			}
			rec.mu.Lock()
			defer rec.mu.Unlock()
			rec.events = append(rec.events, floodEvent{ip, severity, d})
		})
	w.SetOnTimedBan(func(ip, reason string, d time.Duration) {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		rec.bans = append(rec.bans, ip+" "+reason+" "+d.String())
	})
	return w, rec, now
}

func floodLine(ip, uri, ua string, status int) string {
	return fmt.Sprintf(`%s - - [20/Nov/2026:10:00:00 +0000] "GET %s HTTP/1.1" %d 512 "-" "%s"`, ip, uri, status, ua)
}

// send logs n requests of ip in logPath.
func send(w *WebWatcher, logPath, ip string, n int) {
	for i := range n {
		w.processLine(logPath, floodLine(ip, fmt.Sprintf("/page?id=%d", i), "Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0", 200))
	}
}

// settle waits for the event goroutines.
func settle() { time.Sleep(30 * time.Millisecond) }

func TestHTTPFloodBansAtThreshold(t *testing.T) {
	w, rec, _ := newFloodWatcher(t)
	send(w, floodLog, "203.0.113.10", httpFloodDefault-1)
	settle()
	if e, b := rec.snapshot(); len(e) != 0 || len(b) != 0 {
		t.Fatalf("below the threshold: events %v bans %v", e, b)
	}
	send(w, floodLog, "203.0.113.10", 1)
	waitFor(t, func() bool { e, b := rec.snapshot(); return len(e) == 1 && len(b) == 1 })
	// Banned: the rest of the flood is not counted, nor reported again.
	send(w, floodLog, "203.0.113.10", 2000)
	settle()
	e, b := rec.snapshot()
	if len(e) != 1 || len(b) != 1 || b[0] != "203.0.113.10 http_flood 30m0s" {
		t.Fatalf("events %d bans %v", len(e), b)
	}
	d := e[0].d
	want := map[string]string{
		"requests": "600", "window_seconds": "60", "threshold": "600", "action": "banned",
		"ban_level": "1", "ban_seconds": "1800", "top_hosts": "example.com (451)", "top_paths": "/page (451)",
		"status_mix": "2xx=451", "sampled_requests": "451", "user_agent": "Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0",
		"domain": "example.com", "log_file": "example.com", "method": "GET",
	}
	for k, v := range want {
		if d[k] != v {
			t.Errorf("details[%s] = %q, want %q", k, d[k], v)
		}
	}
	if e[0].severity != "critical" || d["ban_until"] != "2026-11-20T10:30:00Z" || d["raw_line"] == "" {
		t.Errorf("severity %s, ban_until %s, raw_line %q", e[0].severity, d["ban_until"], d["raw_line"])
	}
	if w.flood.samples != 0 || w.flood.ips["203.0.113.10"] != nil {
		t.Errorf("counter kept after the ban: %d samples", w.flood.samples)
	}
}

func TestHTTPFloodWindowSlides(t *testing.T) {
	w, rec, now := newFloodWatcher(t)
	// 500 now, 500 more 61 s later: never 600 within a minute.
	send(w, floodLog, "203.0.113.11", 500)
	*now = now.Add(61 * time.Second)
	send(w, floodLog, "203.0.113.11", 500)
	settle()
	if e, b := rec.snapshot(); len(e) != 0 || len(b) != 0 {
		t.Fatalf("spread over two minutes: events %v bans %v", e, b)
	}
	// 300 + 300 thirty seconds apart: one window.
	send(w, floodLog, "203.0.113.12", 300)
	*now = now.Add(30 * time.Second)
	send(w, floodLog, "203.0.113.12", 300)
	waitFor(t, func() bool { _, b := rec.snapshot(); return len(b) == 1 })
}

func TestHTTPFloodAcrossVhostsAndServers(t *testing.T) {
	w, rec, _ := newFloodWatcher(t)
	shop := "/usr/local/apache/domlogs/shop.example.com-ssl_log"
	nginx := "/var/log/nginx/access.log"
	w.domainMap[shop] = []string{"shop.example.com"}
	w.SetSources([]LogPathInfo{{Path: floodLog, Server: "apache"}, {Path: shop, Server: "apache"}, {Path: nginx, Server: "nginx"}})

	// The same 400 requests logged by nginx in front and Apache behind: 400,
	// not 800.
	send(w, nginx, "203.0.113.13", 400)
	send(w, floodLog, "203.0.113.13", 400)
	settle()
	if e, b := rec.snapshot(); len(e) != 0 || len(b) != 0 {
		t.Fatalf("one request counted twice: events %v bans %v", e, b)
	}
	// Two vhosts of the same Apache add up.
	send(w, floodLog, "203.0.113.14", 350)
	send(w, shop, "203.0.113.14", 250)
	waitFor(t, func() bool { e, _ := rec.snapshot(); return len(e) == 1 })
	e, _ := rec.snapshot()
	// Sampled from 150 requests on: 200 of example.com, then 250 of shop.
	if got := e[0].d["top_hosts"]; got != "shop.example.com (250), example.com (201)" || e[0].d["sampled_requests"] != "451" {
		t.Fatalf("top_hosts %q", got)
	}
}

func TestHTTPFloodSkipsStaticFiles(t *testing.T) {
	w, rec, _ := newFloodWatcher(t)
	for range 1000 {
		w.processLine(floodLog, floodLine("203.0.113.15", "/wp-content/uploads/a.jpg", "Mozilla/5.0", 200))
	}
	settle()
	if e, b := rec.snapshot(); len(e) != 0 || len(b) != 0 {
		t.Fatalf("static files counted: events %v bans %v", e, b)
	}
}

func TestHTTPFloodExemptions(t *testing.T) {
	w, rec, _ := newFloodWatcher(t)
	w.UpdateWhitelist([]string{"203.0.113.20"}, []string{"198.51.100.0/24"})
	w.SetNeverBan(func(ip string) bool { return ip == "192.0.2.30" })
	for _, ip := range []string{"203.0.113.20", "198.51.100.7", "127.0.0.1", "10.1.2.3", "100.64.1.2", "fd00::1", "192.0.2.30"} {
		send(w, floodLog, ip, 2*httpFloodDefault)
	}
	settle()
	if e, b := rec.snapshot(); len(e) != 0 || len(b) != 0 {
		t.Fatalf("exempt addresses: events %v bans %v", e, b)
	}
	// Each logged once.
	if len(w.flood.notes) != 7 {
		t.Fatalf("notes %v", w.flood.notes)
	}
}

func TestHTTPFloodCDNEdge(t *testing.T) {
	w, rec, _ := newFloodWatcher(t)
	send(w, floodLog, "104.16.1.1", 2*httpFloodDefault)  // Cloudflare
	send(w, floodLog, "151.101.1.1", 2*httpFloodDefault) // Fastly, same log
	settle()
	e, b := rec.snapshot()
	if len(b) != 0 || len(e) != 1 {
		t.Fatalf("CDN edges: events %v bans %v", e, b)
	}
	d := e[0].d
	if e[0].severity != "warning" || d["not_banned"] != "cdn_edge" || d["cdn"] != "cloudflare" || d["action"] != "reported" ||
		!strings.Contains(d["hint"], "mod_remoteip") {
		t.Fatalf("CDN event %+v", e[0])
	}
	for ip, want := range map[string]string{
		"162.158.1.1": "cloudflare", "2606:4700::1": "cloudflare", "151.101.1.1": "fastly", "192.88.134.5": "sucuri",
		"23.40.1.1": "akamai", "130.176.1.1": "cloudfront", "45.60.1.1": "imperva", "35.191.1.1": "google_cloud_lb",
		"45.32.67.144": "quic.cloud", "203.0.113.1": "", "8.8.8.8": "",
	} {
		if got := cdnProvider(ip); got != want {
			t.Errorf("cdnProvider(%s) = %q, want %q", ip, got, want)
		}
	}
}

func TestHTTPFloodCrawlers(t *testing.T) {
	fakeDNS(t)
	w, rec, _ := newFloodWatcher(t)
	googlebot := "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	burst := func(ip string) {
		for i := range httpFloodDefault {
			w.processLine(floodLog, floodLine(ip, fmt.Sprintf("/p%d", i), googlebot, 200))
		}
	}
	burst("66.249.66.1")  // the real Googlebot: never banned
	burst("203.0.113.50") // an impostor: banned
	burst("203.0.113.60") // DNS times out: reported, not banned
	waitFor(t, func() bool { e, _ := rec.snapshot(); return len(e) == 2 })
	settle()
	e, b := rec.snapshot()
	if len(b) != 1 || b[0] != "203.0.113.50 http_flood 30m0s" {
		t.Fatalf("bans %v", b)
	}
	byIP := map[string]map[string]string{}
	for _, ev := range e {
		byIP[ev.ip] = ev.d
	}
	if d := byIP["203.0.113.50"]; d["action"] != "banned" || d["fcrdns_verified"] != "false" {
		t.Errorf("impostor %v", d)
	}
	if d := byIP["203.0.113.60"]; d["not_banned"] != "dns_unavailable" || d["fcrdns_verified"] != "unknown" {
		t.Errorf("undecided %v", d)
	}
	if !w.flood.notes["verified_crawler 66.249.66.1"] {
		t.Errorf("real crawler not logged: %v", w.flood.notes)
	}
}

func TestHTTPFloodEscalation(t *testing.T) {
	w, rec, now := newFloodWatcher(t)
	ip := "203.0.113.40"
	ban := func() string {
		t.Helper()
		_, before := rec.snapshot()
		send(w, floodLog, ip, httpFloodDefault)
		waitFor(t, func() bool { _, b := rec.snapshot(); return len(b) == len(before)+1 })
		_, b := rec.snapshot()
		return strings.TrimPrefix(b[len(b)-1], ip+" http_flood ")
	}
	// expire moves past the ban and lets the watcher count the address again.
	expire := func(d time.Duration) {
		*now = now.Add(d + time.Minute)
		w.pruneFlood()
	}
	for i, want := range []string{"30m0s", "6h0m0s", "24h0m0s", "24h0m0s"} {
		if got := ban(); got != want {
			t.Fatalf("ban %d: %s, want %s", i+1, got, want)
		}
		expire(map[string]time.Duration{"30m0s": 30 * time.Minute, "6h0m0s": 6 * time.Hour, "24h0m0s": 24 * time.Hour}[want])
	}
	// More than 24 h after the last ban: back to the first step.
	*now = now.Add(24 * time.Hour)
	w.pruneFlood()
	if got := ban(); got != "30m0s" {
		t.Fatalf("after a quiet day: %s", got)
	}
	waitFor(t, func() bool { e, _ := rec.snapshot(); return len(e) == 5 })
	e, _ := rec.snapshot()
	if len(e) != 5 || e[2].d["ban_level"] != "3" || e[3].d["ban_seconds"] != "86400" {
		t.Fatalf("events %d, %v", len(e), e[2].d)
	}
}

func TestHTTPFloodReportOnly(t *testing.T) {
	for _, mode := range []string{"detect_only", "learning"} {
		t.Run(mode, func(t *testing.T) {
			w, rec, now := newFloodWatcher(t)
			if mode == "learning" {
				w.SetMonitorMode(true)
			} else {
				w.UpdateWAFConfig(&WAFConfig{DetectOnlyTypes: []string{httpFloodType}})
			}
			send(w, floodLog, "203.0.113.70", httpFloodDefault)
			waitFor(t, func() bool { e, _ := rec.snapshot(); return len(e) == 1 })
			// Still flooding a few minutes later: no second event within the hour.
			*now = now.Add(5 * time.Minute)
			send(w, floodLog, "203.0.113.70", httpFloodDefault)
			settle()
			e, b := rec.snapshot()
			if len(b) != 0 || len(e) != 1 || e[0].severity != "warning" || e[0].d["not_banned"] != mode || e[0].d["action"] != "reported" {
				t.Fatalf("events %+v bans %v", e, b)
			}
			*now = now.Add(time.Hour)
			send(w, floodLog, "203.0.113.70", httpFloodDefault)
			waitFor(t, func() bool { e, _ := rec.snapshot(); return len(e) == 2 })
		})
	}
}

func TestHTTPFloodConfig(t *testing.T) {
	w, rec, _ := newFloodWatcher(t)
	// Off: not even counted.
	w.UpdateWAFConfig(&WAFConfig{EnabledTypes: []string{"sql_injection"}})
	send(w, floodLog, "203.0.113.80", 2*httpFloodDefault)
	if len(w.flood.ips) != 0 {
		t.Fatalf("counted while off")
	}
	// On with its own threshold.
	w.UpdateWAFConfig(&WAFConfig{EnabledTypes: []string{httpFloodType}, Thresholds: map[string]int{httpFloodType: 200}})
	send(w, floodLog, "203.0.113.81", 200)
	waitFor(t, func() bool { e, _ := rec.snapshot(); return len(e) == 1 && e[0].d["threshold"] == "200" })
	// A threshold below the floor is raised to it.
	w.UpdateWAFConfig(&WAFConfig{Thresholds: map[string]int{httpFloodType: 5}})
	send(w, floodLog, "203.0.113.82", httpFloodMin-1)
	settle()
	if _, b := rec.snapshot(); len(b) != 1 {
		t.Fatalf("banned below the floor: %v", b)
	}
	send(w, floodLog, "203.0.113.82", 1)
	waitFor(t, func() bool { _, b := rec.snapshot(); return len(b) == 2 })
}

func TestHTTPFloodMemoryCap(t *testing.T) {
	w, _, now := newFloodWatcher(t)
	e := accessLogEntry{method: "GET", uri: "/", status: 200, userAgent: "x"}
	w.mu.Lock()
	for i := range floodMaxIPs + 100 {
		w.countFlood(fmt.Sprintf("2001:db8::%x", i), floodLog, "", "apache", &e)
	}
	n := len(w.flood.ips)
	w.mu.Unlock()
	if n != floodMaxIPs {
		t.Fatalf("%d addresses tracked, cap %d", n, floodMaxIPs)
	}
	// Once they are idle for a window, new addresses are counted again.
	*now = now.Add(2 * time.Minute)
	w.mu.Lock()
	w.countFlood("203.0.113.90", floodLog, "", "apache", &e)
	n, tracked := len(w.flood.ips), w.flood.ips["203.0.113.90"] != nil
	w.mu.Unlock()
	if n != 1 || !tracked {
		t.Fatalf("after pruning: %d tracked, new one %v", n, tracked)
	}
}

func TestFloodSampleIsBounded(t *testing.T) {
	var s floodSample
	for i := range 1000 {
		e := accessLogEntry{uri: fmt.Sprintf("/p%d?x=1", i%40), userAgent: "ua", status: 200 + (i%4)*100}
		s.record(fmt.Sprintf("h%d.example.com", i%30), &e)
	}
	if s.hosts.names[floodTopSlots-1] == "" || len(strings.Split(s.paths.top(3), ", ")) != 3 {
		t.Fatalf("top: %q", s.paths.top(3))
	}
	if got := s.statusMix(); got != "2xx=250, 3xx=250, 4xx=250, 5xx=250" {
		t.Fatalf("status mix %q", got)
	}
	long := strings.Repeat("é", 400) + "\x1b[31m"
	if c := floodClean(long); len(c) > floodMaxField || strings.ContainsRune(c, 0x1b) {
		t.Fatalf("clean: %d bytes", len(c))
	}
	if c := floodClean("a\x00b\nc"); c != "a?b?c" {
		t.Fatalf("control characters: %q", c)
	}
}

func TestFloodCounterBuckets(t *testing.T) {
	var c floodCounter
	for i := range 12 {
		c.add(uint32(100+i), 3)
	}
	if n := c.add(111, 3); n != 13 {
		t.Fatalf("window count %d", n)
	}
	// One bucket later the first one leaves the window.
	if n := c.add(112, 3); n != 13 {
		t.Fatalf("after sliding %d", n)
	}
	// A clock that goes back counts in the newest bucket.
	if n := c.add(50, 3); n != 14 {
		t.Fatalf("clock back %d", n)
	}
	// A long pause empties it.
	if n := c.add(1000, 3); n != 1 {
		t.Fatalf("after a pause %d", n)
	}
}

func TestCpanelDomlogs(t *testing.T) {
	dir := t.TempDir()
	write := func(name string) {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range []string{"example.com", "example.com-ssl_log", "example.com-bytes_log", "ftpxferlog",
		"example.com-ftp_log", "old.example.com.gz", ".hidden.com", "user1/shop.example.com-ssl_log"} {
		write(n)
	}
	// The same log twice (a symlink): read once.
	if err := os.Symlink(filepath.Join(dir, "example.com"), filepath.Join(dir, "user1", "example.com")); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, info := range cpanelDomlogsIn(dir) {
		rel, _ := filepath.Rel(dir, info.Path)
		got[rel] = strings.Join(info.Domains, ",")
	}
	want := map[string]string{"example.com": "example.com", "example.com-ssl_log": "example.com", "user1/shop.example.com-ssl_log": "shop.example.com"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("domlogs %v, want %v", got, want)
	}
}

// LiteSpeed (cPanel's lsphp setups) writes the domlogs in Apache's format,
// with HTTP/2 and HTTP/3 requests.
func TestHTTPFloodLiteSpeedLines(t *testing.T) {
	w, rec, _ := newFloodWatcher(t)
	w.SetSources([]LogPathInfo{{Path: floodLog, Server: "litespeed"}})
	for i := range httpFloodDefault {
		proto := []string{"HTTP/1.1", "HTTP/2", "HTTP/3"}[i%3]
		w.processLine(floodLog, fmt.Sprintf(`203.0.113.95 - - [20/Nov/2026:10:00:00 +0100] "GET /?p=%d %s" 200 3000 "https://example.com/" "Mozilla/5.0"`, i, proto))
	}
	waitFor(t, func() bool { _, b := rec.snapshot(); return len(b) == 1 })
}

// The cost of a request in processLine with and without http_flood (a
// browser UA, a dynamic page, 1000 addresses), and of the counter alone.
func BenchmarkProcessLineHTTPFlood(b *testing.B) {
	lines := make([]string, 1000)
	for i := range lines {
		lines[i] = floodLine(fmt.Sprintf("198.51.%d.%d", i/250, i%250+1), "/index.php?p=1", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0", 200)
	}
	others := []string{"bot_unknown"}
	for k := range defaultScorePoints {
		others = append(others, k)
	}
	for _, on := range []bool{true, false} {
		b.Run(map[bool]string{true: "on", false: "off"}[on], func(b *testing.B) {
			w := NewWebWatcher(nil, map[string][]string{floodLog: {"example.com"}}, func(string, string, int) {}, func(string, string, string, map[string]string) {})
			types := others
			if on {
				types = append([]string{httpFloodType}, others...)
			}
			w.UpdateWAFConfig(&WAFConfig{EnabledTypes: types, Thresholds: map[string]int{httpFloodType: 1 << 30}})
			b.ReportAllocs()
			b.ResetTimer()
			for i := range b.N {
				w.processLine(floodLog, lines[i%len(lines)])
			}
		})
	}
}

func BenchmarkCountFlood(b *testing.B) {
	w := NewWebWatcher(nil, nil, func(string, string, int) {}, func(string, string, string, map[string]string) {})
	w.UpdateWAFConfig(&WAFConfig{Thresholds: map[string]int{httpFloodType: 1 << 30}})
	ips := make([]string, 10000)
	for i := range ips {
		ips[i] = fmt.Sprintf("2001:db8::%x", i)
	}
	e := accessLogEntry{method: "GET", uri: "/index.php", status: 200, userAgent: "Mozilla/5.0"}
	w.mu.Lock()
	defer w.mu.Unlock()
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		w.countFlood(ips[i%len(ips)], floodLog, "", "apache", &e)
	}
}
