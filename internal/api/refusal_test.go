package api

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/infrafence/infrafence-agent/internal/backoff"
)

// A dashboard that refuses the agent is asked again only after the backoff:
// the requests in between fail at once without reaching it, the first
// success lets everything through again.
func TestRefusalHoldsRequests(t *testing.T) {
	var hits atomic.Int32
	var mu sync.Mutex
	status, body := http.StatusForbidden, `{"error":"suspended"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		mu.Lock()
		st, b := status, body
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(st)
		_, _ = io.WriteString(w, b)
	}))
	defer srv.Close()

	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	var nmu sync.Mutex
	clock := func() time.Time { nmu.Lock(); defer nmu.Unlock(); return now }
	advance := func(d time.Duration) { nmu.Lock(); now = now.Add(d); nmu.Unlock() }
	c := New(srv.URL, "tok")
	c.gate = backoff.NewWith(clock, func() float64 { return 0 }, t.Logf)

	_, err := c.Heartbeat(HeartbeatRequest{})
	var se *statusError
	if !errors.As(err, &se) || se.code != 403 || se.held {
		t.Fatalf("first heartbeat: %v, want the 403", err)
	}
	if se.retryAfter != backoff.Suspended {
		t.Fatalf("403 suspended: retry after %s, want %s", se.retryAfter, backoff.Suspended)
	}
	// Heartbeat, sync and events are all held now.
	if _, err := c.Sync(); !IsHeld(err) {
		t.Fatalf("sync during the backoff: %v, want held", err)
	}
	if err := c.DeliverEvents([]EventRequest{{Type: "x"}}); !IsHeld(err) {
		t.Fatalf("events during the backoff: %v, want held", err)
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("dashboard asked %d times during the backoff, want 1", n)
	}

	advance(backoff.Suspended)
	mu.Lock()
	status, body = http.StatusOK, `{}`
	mu.Unlock()
	if _, err := c.Heartbeat(HeartbeatRequest{}); err != nil {
		t.Fatalf("heartbeat after the backoff: %v", err)
	}
	if c.gate.Wait() != 0 {
		t.Fatal("success did not reset the backoff")
	}
	if _, err := c.Sync(); err != nil {
		t.Fatalf("sync after recovery: %v", err)
	}
	if n := hits.Load(); n != 3 {
		t.Fatalf("hits = %d, want 3", n)
	}
}

// A 401 starts at a minute and doubles; a 503 (dashboard down) is not a
// refusal and holds nothing.
func TestRefusal401BacksOffAnd503DoesNot(t *testing.T) {
	var code atomic.Int32
	code.Store(http.StatusServiceUnavailable)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(int(code.Load()))
	}))
	defer srv.Close()
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	c := New(srv.URL, "tok")
	c.gate = backoff.NewWith(func() time.Time { return now }, func() float64 { return 0 }, t.Logf)

	if _, err := c.Sync(); err == nil || IsHeld(err) {
		t.Fatalf("503: %v", err)
	}
	if c.gate.Wait() != 0 {
		t.Fatal("a 503 started the refusal backoff")
	}
	code.Store(http.StatusUnauthorized)
	_, _ = c.Sync()
	if w := c.gate.Wait(); w != backoff.Min {
		t.Fatalf("after a 401: wait %s, want %s", w, backoff.Min)
	}
	now = now.Add(backoff.Min)
	_, _ = c.Sync()
	if w := c.gate.Wait(); w != 2*backoff.Min {
		t.Fatalf("after a second 401: wait %s, want %s", w, 2*backoff.Min)
	}
}
