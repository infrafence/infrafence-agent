package main

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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
