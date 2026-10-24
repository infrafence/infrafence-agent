package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/panel"
)

// "panel map" and "panel score": what the dashboard computes for this
// server (where its attacks came from, its security score), fetched by the
// running agent for the plugins. The plugins may ask on every page view;
// the dashboard is asked at most once per panelMapEvery for each map range
// and once per panelScoreEvery for the score, whether it answered or not.
// The request runs in the socket handler, never in a protection loop, and
// is bounded by panelInfoTimeout and the client's size limit. When the
// dashboard does not answer, the last answer is given again with "stale":
// true (also when the answer was computed more than an hour ago); with
// nothing to give, the error is not_connected.

var (
	panelMapEvery    = 5 * time.Minute
	panelScoreEvery  = 15 * time.Minute
	panelInfoTimeout = 10 * time.Second
)

// Set by startPanelSocket; replaced in tests.
var (
	panelFetchMap   func(ctx context.Context, hours int) (*api.AttackMap, error)
	panelFetchScore func(ctx context.Context) (*api.SecurityScore, error)
)

// infoEntry is the last answer for one key ("map:24", "map:168", "score").
type infoEntry struct {
	fields map[string]any // the dashboard's answer as reply fields
	failed bool           // the latest request got no valid answer
	tried  time.Time      // latest request, answered or not
	busy   chan struct{}  // closed when the request in flight ends
}

var panelInfoCache struct {
	sync.Mutex
	entries map[string]*infoEntry
}

func resetPanelInfoCache() {
	panelInfoCache.Lock()
	panelInfoCache.entries = nil
	panelInfoCache.Unlock()
}

func panelMap(hours int) panel.Response {
	return panelCachedInfo("map:"+strconv.Itoa(hours), panelMapEvery, "attack map", func(ctx context.Context) (any, error) {
		if panelFetchMap == nil {
			return nil, errNoDashboard
		}
		return panelFetchMap(ctx, hours)
	})
}

func panelScore() panel.Response {
	return panelCachedInfo("score", panelScoreEvery, "security score", func(ctx context.Context) (any, error) {
		if panelFetchScore == nil {
			return nil, errNoDashboard
		}
		return panelFetchScore(ctx)
	})
}

var errNoDashboard = errors.New("no dashboard client")

// panelCachedInfo answers from the cache, asking the dashboard first when the
// last request for key is at least every old. Concurrent requests for the
// same key wait for the one in flight instead of sending their own.
func panelCachedInfo(key string, every time.Duration, what string, fetch func(context.Context) (any, error)) panel.Response {
	panelInfoCache.Lock()
	if panelInfoCache.entries == nil {
		panelInfoCache.entries = map[string]*infoEntry{}
	}
	e := panelInfoCache.entries[key]
	if e == nil {
		e = &infoEntry{}
		panelInfoCache.entries[key] = e
	}
	if ch := e.busy; ch != nil {
		panelInfoCache.Unlock()
		select {
		case <-ch:
		case <-time.After(panelInfoTimeout):
		}
		panelInfoCache.Lock()
	}
	// A clock set back never stops the requests for long.
	if since := panelNow().Sub(e.tried); e.busy != nil || since >= 0 && since < every {
		r := infoAnswerLocked(e, what)
		panelInfoCache.Unlock()
		return r
	}
	ch := make(chan struct{})
	e.busy, e.tried = ch, panelNow()
	panelInfoCache.Unlock()

	fields, err := fetchInfo(fetch)

	panelInfoCache.Lock()
	defer panelInfoCache.Unlock()
	e.busy = nil
	close(ch)
	if err != nil {
		// At most one line per key and interval: requests are that rare.
		log.Printf("[panel] %s (%s): %v", what, key, err)
		e.failed = true
	} else {
		e.fields, e.failed = fields, false
	}
	return infoAnswerLocked(e, what)
}

// fetchInfo runs fetch with the timeout and turns its answer into reply
// fields. A panic is an error like any other (the entry must not stay busy).
func fetchInfo(fetch func(context.Context) (any, error)) (fields map[string]any, err error) {
	defer func() {
		if r := recover(); r != nil {
			fields, err = nil, fmt.Errorf("panic: %v", r)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), panelInfoTimeout)
	defer cancel()
	v, err := fetch(ctx)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	if fields == nil {
		return nil, errors.New("empty answer")
	}
	return fields, nil
}

func infoAnswerLocked(e *infoEntry, what string) panel.Response {
	if e.fields == nil {
		return panel.Fail(panel.ErrNotConnected, "the InfraFence dashboard has not sent this server's %s (not reachable, or it does not offer it yet)", what)
	}
	r := panel.OK(e.fields)
	r["stale"] = e.failed || infoTooOld(e.fields)
	r["connected"] = panelConnected()
	return r
}

// panelInfoMaxAge: an answer the dashboard computed longer ago than this is
// stale even when it was just received (a dashboard serving old data).
const panelInfoMaxAge = time.Hour

func infoTooOld(fields map[string]any) bool {
	s, _ := fields["generated_at"].(string)
	t, err := time.Parse(time.RFC3339, s)
	return err != nil || panelNow().Sub(t) > panelInfoMaxAge
}

// panelConnected: the last heartbeat the dashboard accepted is less than 3
// minutes old (as in "status").
func panelConnected() bool {
	ts := panelLastHeartbeat.Load()
	return ts > 0 && panelNow().Sub(time.Unix(ts, 0)) < 3*time.Minute
}
