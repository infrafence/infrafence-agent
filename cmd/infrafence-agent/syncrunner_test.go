package main

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
)

type countingSync struct {
	calls   atomic.Int32
	running atomic.Int32
	overlap atomic.Bool
	fail    atomic.Bool
	delay   time.Duration
}

func (c *countingSync) run() error {
	if c.running.Add(1) > 1 {
		c.overlap.Store(true)
	}
	defer c.running.Add(-1)
	c.calls.Add(1)
	time.Sleep(c.delay)
	if c.fail.Load() {
		return errors.New("sync failed")
	}
	return nil
}

func fastRunner(c *countingSync) (*syncRunner, context.CancelFunc) {
	r := newSyncRunner(c.run)
	r.debounce = 20 * time.Millisecond
	r.minGap = 100 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	go r.Loop(ctx)
	return r, cancel
}

func eventually(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestBurstOfRequestsIsOneSync(t *testing.T) {
	c := &countingSync{}
	r, cancel := fastRunner(c)
	defer cancel()
	for i := 0; i < 50; i++ {
		r.Request("push")
	}
	eventually(t, func() bool { return c.calls.Load() >= 1 })
	time.Sleep(250 * time.Millisecond)
	if n := c.calls.Load(); n > 2 {
		t.Errorf("50 requests caused %d syncs", n)
	}
}

func TestSyncsNeverOverlap(t *testing.T) {
	c := &countingSync{delay: 30 * time.Millisecond}
	r, cancel := fastRunner(c)
	defer cancel()
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = r.Now("periodic") }()
		r.Request("push")
	}
	wg.Wait()
	time.Sleep(200 * time.Millisecond)
	if c.overlap.Load() {
		t.Error("two syncs ran at the same time")
	}
}

func TestRateLimitsForgedPushFlood(t *testing.T) {
	c := &countingSync{}
	r, cancel := fastRunner(c)
	defer cancel()
	stop := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(stop) {
		r.Request("push:sync")
		time.Sleep(time.Millisecond)
	}
	// minGap 100ms over 500ms: about 5 syncs, never one per message.
	if n := c.calls.Load(); n > 7 {
		t.Errorf("flood caused %d syncs", n)
	}
}

func TestConfigVersion(t *testing.T) {
	c := &countingSync{}
	r, cancel := fastRunner(c)
	defer cancel()

	r.ObserveVersion("") // older dashboard: nothing
	time.Sleep(150 * time.Millisecond)
	if c.calls.Load() != 0 {
		t.Fatal("empty version must not sync")
	}

	r.ObserveVersion("v1")
	eventually(t, func() bool { return c.calls.Load() == 1 })

	r.ObserveVersion("v1") // unchanged: nothing
	time.Sleep(200 * time.Millisecond)
	if n := c.calls.Load(); n != 1 {
		t.Fatalf("unchanged version synced again (%d)", n)
	}

	r.ObserveVersion("v2")
	eventually(t, func() bool { return c.calls.Load() == 2 })
}

func TestFailedSyncIsRetriedOnNextHeartbeat(t *testing.T) {
	c := &countingSync{}
	c.fail.Store(true)
	r, cancel := fastRunner(c)
	defer cancel()

	r.ObserveVersion("v1")
	eventually(t, func() bool { return c.calls.Load() == 1 })
	time.Sleep(150 * time.Millisecond)

	c.fail.Store(false)
	r.ObserveVersion("v1") // same version, but never applied
	eventually(t, func() bool { return c.calls.Load() == 2 })

	r.ObserveVersion("v1")
	time.Sleep(200 * time.Millisecond)
	if n := c.calls.Load(); n != 2 {
		t.Errorf("applied version synced again (%d)", n)
	}
}

func TestNextBanExpiry(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	str := func(s string) *string { return &s }
	bans := []api.Ban{
		{IPAddress: "1.1.1.1"}, // permanent
		{IPAddress: "2.2.2.2", ExpiresAt: str("2026-09-26T11:00:00Z")},        // already expired
		{IPAddress: "3.3.3.3", ExpiresAt: str("2026-09-27T12:00:00+00:00")},   // tomorrow
		{IPAddress: "4.4.4.4", ExpiresAt: str("2026-09-26T13:00:00.5+00:00")}, // in 1h
		{IPAddress: "5.5.5.5", ExpiresAt: str("garbage")},
	}
	next, ok := nextBanExpiry(bans, now)
	want := time.Date(2026, 9, 26, 13, 0, 1, 500_000_000, time.UTC)
	if !ok || !next.Equal(want) {
		t.Errorf("next = %v %v, want %v", next, ok, want)
	}
	if _, ok := nextBanExpiry(bans[:2], now); ok {
		t.Error("permanent and expired bans have no next expiry")
	}
}

func TestScheduledSyncFiresAtExpiry(t *testing.T) {
	c := &countingSync{}
	r, cancel := fastRunner(c)
	defer cancel()

	r.ScheduleAt(time.Now().Add(150*time.Millisecond), "ban expiry")
	time.Sleep(100 * time.Millisecond)
	if c.calls.Load() != 0 {
		t.Fatal("synced before the expiry")
	}
	eventually(t, func() bool { return c.calls.Load() == 1 })

	// A later time doesn't replace an earlier pending one; zero cancels.
	r.ScheduleAt(time.Now().Add(100*time.Millisecond), "ban expiry")
	r.ScheduleAt(time.Now().Add(time.Hour), "ban expiry")
	eventually(t, func() bool { return c.calls.Load() == 2 })
	r.ScheduleAt(time.Now().Add(100*time.Millisecond), "ban expiry")
	r.ScheduleAt(time.Time{}, "")
	time.Sleep(300 * time.Millisecond)
	if n := c.calls.Load(); n != 2 {
		t.Errorf("cancelled schedule still synced (%d)", n)
	}
}
