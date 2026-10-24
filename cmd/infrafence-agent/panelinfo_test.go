package main

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/panel"
)

func testMap(hours int, attacks int64) *api.AttackMap {
	m := &api.AttackMap{Hours: hours, GeneratedAt: "2026-10-16T11:58:00Z",
		Countries:  []api.MapCountry{{Code: "CN", Attacks: attacks}},
		Categories: []api.MapCategory{{Cat: "ssh", Attacks: attacks}}}
	m.Total.Attacks = attacks
	return m
}

func TestPanelMapCacheAndRateLimit(t *testing.T) {
	f := withFakePanel(t)
	panelLastHeartbeat.Store(f.now.Add(-time.Minute).Unix())
	var calls atomic.Int32
	var fail atomic.Bool
	panelFetchMap = func(_ context.Context, hours int) (*api.AttackMap, error) {
		calls.Add(1)
		if fail.Load() {
			return nil, errors.New("dial tcp: connection refused")
		}
		return testMap(hours, int64(calls.Load())), nil
	}
	attacks := func(r panel.Response) any { return r["total"].(map[string]any)["attacks"] }

	// Nothing yet and the dashboard down: not_connected, and no second
	// request within 5 minutes.
	fail.Store(true)
	for i := 0; i < 3; i++ {
		if r := handlePanel(panel.Request{Command: "map", Hours: 24}); r["error"] != panel.ErrNotConnected {
			t.Fatalf("nothing cached: %v", r)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("%d requests in a minute, want 1", calls.Load())
	}

	// After 5 minutes it asks again; the answer is cached.
	fail.Store(false)
	f.now = f.now.Add(5 * time.Minute)
	panelLastHeartbeat.Store(f.now.Add(-time.Minute).Unix())
	r := handlePanel(panel.Request{Command: "map", Hours: 24})
	if !r.Succeeded() || r["stale"] != false || r["connected"] != true || r["hours"] != float64(24) || attacks(r) != float64(2) {
		t.Fatalf("fresh: %v", r)
	}
	f.now = f.now.Add(4 * time.Minute)
	if r := handlePanel(panel.Request{Command: "map", Hours: 24}); attacks(r) != float64(2) || r["stale"] != false || calls.Load() != 2 {
		t.Fatalf("cached: %v, %d requests", r, calls.Load())
	}

	// The other range is its own entry.
	if r := handlePanel(panel.Request{Command: "map", Hours: 168}); r["hours"] != float64(168) || calls.Load() != 3 {
		t.Fatalf("7 days: %v", r)
	}

	// Dashboard down after 5 minutes: the last answer, stale; still one
	// request per 5 minutes.
	fail.Store(true)
	f.now = f.now.Add(time.Minute)
	for i := 0; i < 3; i++ {
		r := handlePanel(panel.Request{Command: "map", Hours: 24})
		if !r.Succeeded() || r["stale"] != true || attacks(r) != float64(2) {
			t.Fatalf("stale: %v", r)
		}
	}
	if calls.Load() != 4 {
		t.Fatalf("%d requests, want 4", calls.Load())
	}
	// Back: fresh again at the next interval.
	fail.Store(false)
	f.now = f.now.Add(5 * time.Minute)
	if r := handlePanel(panel.Request{Command: "map", Hours: 24}); r["stale"] != false || attacks(r) != float64(5) {
		t.Fatalf("back: %v", r)
	}

	// A clock set back does not stop the requests.
	f.now = f.now.Add(-time.Hour)
	handlePanel(panel.Request{Command: "map", Hours: 24})
	if calls.Load() != 6 {
		t.Fatalf("clock set back: %d requests", calls.Load())
	}

	// No heartbeat for a while: connected false, the map still answers.
	panelLastHeartbeat.Store(f.now.Add(-10 * time.Minute).Unix())
	if r := handlePanel(panel.Request{Command: "map", Hours: 24}); r["connected"] != false || !r.Succeeded() {
		t.Fatalf("not connected: %v", r)
	}
}

// Requests arriving together send one request; they wait for it.
func TestPanelMapOneRequestInFlight(t *testing.T) {
	withFakePanel(t)
	var calls atomic.Int32
	release := make(chan struct{})
	panelFetchMap = func(_ context.Context, hours int) (*api.AttackMap, error) {
		calls.Add(1)
		<-release
		return testMap(hours, 7), nil
	}
	var wg sync.WaitGroup
	results := make([]panel.Response, 4)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = panelMap(24)
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("%d requests, want 1", calls.Load())
	}
	for _, r := range results {
		if !r.Succeeded() || r["stale"] != false {
			t.Errorf("waiting request: %v", r)
		}
	}
}

// A request that hangs is cut at panelInfoTimeout; a panic is a failure.
func TestPanelMapBounded(t *testing.T) {
	withFakePanel(t)
	saved := panelInfoTimeout
	panelInfoTimeout = 50 * time.Millisecond
	t.Cleanup(func() { panelInfoTimeout = saved })
	panelFetchMap = func(ctx context.Context, _ int) (*api.AttackMap, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	start := time.Now()
	if r := panelMap(24); r["error"] != panel.ErrNotConnected || time.Since(start) > 2*time.Second {
		t.Fatalf("hung request: %v after %s", r, time.Since(start))
	}
	panelFetchMap = func(context.Context, int) (*api.AttackMap, error) { panic("boom") }
	if r := panelMap(168); r["error"] != panel.ErrNotConnected {
		t.Fatalf("panic: %v", r)
	}
	panelInfoCache.Lock()
	busy := panelInfoCache.entries["map:168"].busy
	panelInfoCache.Unlock()
	if busy != nil {
		t.Fatal("entry left busy after a panic")
	}
}

func TestPanelScoreCachedFifteenMinutes(t *testing.T) {
	f := withFakePanel(t)
	var calls atomic.Int32
	var fail atomic.Bool
	panelFetchScore = func(context.Context) (*api.SecurityScore, error) {
		calls.Add(1)
		if fail.Load() {
			return nil, errors.New("503")
		}
		return &api.SecurityScore{GeneratedAt: "2026-10-16T11:58:00Z", Score: 72, Grade: "C",
			Items: []api.ScoreItem{{Key: "hardening", Points: 12, Detail: map[string]any{"failed": 22.0, "total": 43.0}}},
			Trend: []api.ScorePoint{}}, nil
	}
	r := handlePanel(panel.Request{Command: "score"})
	if !r.Succeeded() || r["score"] != float64(72) || r["grade"] != "C" || r["stale"] != false {
		t.Fatalf("score: %v", r)
	}
	f.now = f.now.Add(14 * time.Minute)
	fail.Store(true)
	if handlePanel(panel.Request{Command: "score"})["stale"] != false || calls.Load() != 1 {
		t.Fatalf("asked again within 15 minutes: %d", calls.Load())
	}
	f.now = f.now.Add(time.Minute)
	if r := handlePanel(panel.Request{Command: "score"}); r["stale"] != true || r["score"] != float64(72) || calls.Load() != 2 {
		t.Fatalf("stale: %v, %d", r, calls.Load())
	}
}

// An answer computed more than an hour ago is stale even when it was just
// received.
func TestPanelInfoOldAnswerIsStale(t *testing.T) {
	f := withFakePanel(t)
	panelFetchMap = func(_ context.Context, hours int) (*api.AttackMap, error) {
		m := testMap(hours, 1)
		m.GeneratedAt = f.now.Add(-61 * time.Minute).Format(time.RFC3339)
		return m, nil
	}
	if r := panelMap(24); !r.Succeeded() || r["stale"] != true {
		t.Fatalf("old answer: %v", r)
	}
	panelFetchMap = func(_ context.Context, hours int) (*api.AttackMap, error) {
		m := testMap(hours, 1)
		m.GeneratedAt = f.now.Add(-59 * time.Minute).Format(time.RFC3339)
		return m, nil
	}
	if r := panelMap(168); r["stale"] != false {
		t.Fatalf("recent answer: %v", r)
	}
	// A fresh map that ages in the cache while the dashboard is down.
	f.now = f.now.Add(2 * time.Minute)
	panelFetchMap = func(context.Context, int) (*api.AttackMap, error) { return nil, errors.New("down") }
	if r := panelMap(168); r["stale"] != true {
		t.Fatalf("aged answer: %v", r)
	}
}
