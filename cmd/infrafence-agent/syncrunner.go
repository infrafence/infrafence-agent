package main

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/realtime"
)

// syncRunner is the only path to syncAndApply: syncs never overlap, and
// bursts of requests (a push per changed row, a flapping connection, a
// forged push message) collapse into one sync at most every minGap.
//
// Requests come from startup, the periodic fallback, the heartbeat's config
// version and realtime pushes.
type syncRunner struct {
	run func() error

	debounce time.Duration // wait for a burst of changes to finish
	minGap   time.Duration // never sync more often than this

	mu       sync.Mutex // held for the whole sync
	requests chan string

	vmu      sync.Mutex
	seen     string // latest config version reported by the dashboard
	applied  string // config version of the last successful sync
	lastSync time.Time

	tmu   sync.Mutex
	timer *time.Timer // next scheduled sync (ban expiry)
	at    time.Time
}

func newSyncRunner(run func() error) *syncRunner {
	return &syncRunner{
		run:      run,
		debounce: 500 * time.Millisecond,
		minGap:   3 * time.Second,
		requests: make(chan string, 1),
	}
}

// Now syncs immediately (waiting for a running sync to finish).
func (s *syncRunner) Now(reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vmu.Lock()
	version := s.seen
	s.vmu.Unlock()

	err := s.run()

	s.vmu.Lock()
	s.lastSync = time.Now()
	if err == nil {
		s.applied = version
	}
	s.vmu.Unlock()
	if err != nil {
		log.Printf("[sync] %s sync failed: %v", reason, err)
	}
	return err
}

// Request asks for a sync soon; never blocks. Requests made while one is
// pending are merged into it.
func (s *syncRunner) Request(reason string) {
	select {
	case s.requests <- reason:
	default:
	}
}

// Loop serves Request calls; run it in its own goroutine.
func (s *syncRunner) Loop(ctx context.Context) {
	for {
		var reason string
		select {
		case <-ctx.Done():
			return
		case reason = <-s.requests:
		}
		time.Sleep(s.debounce)
		s.vmu.Lock()
		wait := s.minGap - time.Since(s.lastSync)
		s.vmu.Unlock()
		if wait > 0 {
			time.Sleep(wait)
		}
		// Anything requested meanwhile is covered by this sync.
		select {
		case <-s.requests:
		default:
		}
		log.Printf("[sync] syncing now (%s)", reason)
		_ = s.Now(reason)
	}
}

// ScheduleAt requests a sync at t (e.g. when the next ban expires), so an
// expired ban is lifted on time instead of at the next periodic sync. Only
// the earliest pending time is kept; a zero t cancels it.
func (s *syncRunner) ScheduleAt(t time.Time, reason string) {
	s.tmu.Lock()
	defer s.tmu.Unlock()
	if s.timer != nil && !t.IsZero() && !s.at.IsZero() && s.at.Before(t) && time.Until(s.at) > 0 {
		return // an earlier sync is already scheduled
	}
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	s.at = t
	if t.IsZero() {
		return
	}
	s.timer = time.AfterFunc(time.Until(t), func() { s.Request(reason) })
}

// nextBanExpiry returns when the earliest of bans expires after now (plus a
// second, so the server already considers it expired), or false if none does.
func nextBanExpiry(bans []api.Ban, now time.Time) (time.Time, bool) {
	var next time.Time
	for _, b := range bans {
		if b.ExpiresAt == nil {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, *b.ExpiresAt)
		if err != nil || !t.After(now) {
			continue
		}
		if next.IsZero() || t.Before(next) {
			next = t
		}
	}
	if next.IsZero() {
		return next, false
	}
	return next.Add(time.Second), true
}

// ObserveVersion records the config version from a heartbeat and requests a
// sync when it differs from the last one applied. An empty version (older
// dashboard) is ignored.
func (s *syncRunner) ObserveVersion(v string) {
	if v == "" {
		return
	}
	s.vmu.Lock()
	s.seen = v
	changed := v != s.applied
	s.vmu.Unlock()
	if changed {
		s.Request("config changed")
	}
}

// pushListener keeps one realtime subscription matching the dashboard's
// latest heartbeat reply, restarting it when the channel changes.
type pushListener struct {
	runner *syncRunner
	cur    realtime.Config
	cancel context.CancelFunc
}

func (p *pushListener) Apply(rc *api.RealtimeConfig) {
	var cfg realtime.Config
	if rc != nil {
		cfg = realtime.Config{URL: rc.URL, Key: rc.Key, Topic: rc.Topic}
	}
	if cfg == p.cur {
		return
	}
	if p.cancel != nil {
		p.cancel()
		p.cancel = nil
	}
	p.cur = cfg
	if cfg.URL == "" || cfg.Key == "" || cfg.Topic == "" {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	go realtime.New(cfg, func(event string) {
		p.runner.Request("push:" + event)
	}).Run(ctx)
}
