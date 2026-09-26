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
		_ = s.Now(reason)
	}
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
