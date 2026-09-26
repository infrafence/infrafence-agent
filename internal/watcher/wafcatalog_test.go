package watcher

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestWAFCatalogIntegrity(t *testing.T) {
	c := BuiltinWAFCatalog("test")
	seen := map[string]bool{}
	for _, p := range c.Patterns {
		if seen[p.ID] {
			t.Errorf("duplicate pattern ID %q", p.ID)
		}
		seen[p.ID] = true
		if c.ScorePoints[p.EventType] == 0 {
			t.Errorf("%s: event type %q has no score points, so it could never fire", p.ID, p.EventType)
		}
	}
	for _, th := range c.Thresholds {
		if th.ConfigKey == "" || th.DefaultThreshold <= 0 || th.WindowSeconds <= 0 {
			t.Errorf("incomplete threshold rule %+v", th)
		}
	}
	if len(c.Patterns) < 100 || len(c.Thresholds) != 7 {
		t.Errorf("unexpected catalog size: %d patterns, %d thresholds", len(c.Patterns), len(c.Thresholds))
	}
}

// Sends one SQL injection request (score 40 ≥ observe 30) and reports whether
// an event came out.
func detectsSQLi(t *testing.T, disabled []string) bool {
	t.Helper()
	var mu sync.Mutex
	got := 0
	w := NewWebWatcher(nil, nil, func(string, string, int) {}, func(ip, eventType, severity string, d map[string]string) {
		mu.Lock()
		defer mu.Unlock()
		if eventType == "sql_injection" {
			got++
		}
	})
	w.UpdateWAFConfig(&WAFConfig{DisabledPatterns: disabled})
	line := fmt.Sprintf(`203.0.113.9 - - [%s] "GET /item?id=1+union+select+1 HTTP/1.1" 200 512 "-" "Mozilla/5.0"`,
		time.Now().Format("02/Jan/2006:15:04:05 -0700"))
	w.processLine("/var/log/nginx/access.log", line)
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	return got > 0
}

func TestDisabledBuiltinPattern(t *testing.T) {
	if !detectsSQLi(t, nil) {
		t.Fatal("baseline: union+select should be detected")
	}
	if detectsSQLi(t, []string{"sql_injection:union+select"}) {
		t.Error("disabled pattern still detected")
	}
	if !detectsSQLi(t, []string{"sql_injection:sleep("}) {
		t.Error("disabling a different pattern must not affect this one")
	}
}
