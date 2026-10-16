package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Event delivery. Events are queued and sent in batches, one request per
// batch, so a busy host does not make one request per event:
//
//   - urgent events (see urgentEvent) are sent at once, together with every
//     event queued before them (order is kept); after an urgent send the
//     next one waits eventUrgentGap, so a burst shares one request;
//   - the others wait at most eventFlushEvery, or until eventBatchMax are
//     queued;
//   - events are never merged: each one keeps its own type, details and time
//     (the dashboard counts them);
//   - a failed send is retried with backoff, the batch first; a batch the
//     server refuses is split in halves until the refused event is found;
//   - at most eventQueueMax events and eventQueueBytes wait: past that the
//     oldest non-urgent ones are dropped and one warning event reports how
//     many;
//   - on shutdown, the urgent events not delivered are kept in a file and
//     sent at the next start.
//
// Detection and blocking never wait for delivery: they happen before the
// event is queued.
const (
	eventFlushEvery = 5 * time.Second
	eventUrgentGap  = time.Second
	eventBatchMax   = 100
	eventQueueMax   = 5000
	eventQueueBytes = 16 << 20
	// eventDropChunk events (and a tenth of eventQueueBytes) are dropped at
	// once when the queue is full, so a flood against a dashboard that is
	// down does not compact the queue for every new event.
	eventDropChunk = eventQueueMax / 10

	eventRetryMin = time.Second
	eventRetryMax = 30 * time.Second
	// eventRetryAfterMax bounds the wait a 429 reply asks for.
	eventRetryAfterMax = 5 * time.Minute
	// eventFlushRetry is the delay between tries while a shutdown or update
	// flush waits.
	eventFlushRetry = 500 * time.Millisecond
	// After eventPoisonTries server errors in a row the batch is split, in
	// case one event makes the server fail.
	eventPoisonTries = 10
	// eventSplitGap separates the requests that follow a refusal, so a
	// server that refuses everything is not flooded.
	eventSplitGap = 200 * time.Millisecond
	// eventDropLogEvery limits the "queue full" log line.
	eventDropLogEvery = 30 * time.Second

	// Size limits of an event's details.
	eventDetailMax      = 2048
	eventDetailShortMax = 512 // uri, user_agent
	eventDetailKeys     = 64
	eventDetailKeyMax   = 128
	eventSpoolMaxBytes  = 32 << 20
)

var errEventsStopped = errors.New("event delivery stopped")

// eventClock is replaced in tests.
type eventClock interface {
	Now() time.Time
	// At fires at t (at once if t has passed).
	At(t time.Time) <-chan time.Time
}

type realClock struct{}

func (realClock) Now() time.Time                  { return time.Now() }
func (realClock) At(t time.Time) <-chan time.Time { return time.After(time.Until(t)) }

type queuedEvent struct {
	ev     EventRequest
	urgent bool
	size   int
	at     time.Time
}

type flushWaiter struct {
	ctx context.Context
	ch  chan error
}

type eventSender struct {
	send  func(context.Context, []EventRequest) error
	clock eventClock
	mu    sync.Mutex
	// spoolPath, if set, keeps the urgent events not delivered at shutdown.
	spoolPath string
	queue     []queuedEvent
	urgent    int // urgent events in queue
	bytes     int // estimated size of queue
	sending   int // events taken from queue and not delivered yet
	stopped   bool
	// lastUrgent is when the last batch with an urgent event was taken.
	lastUrgent time.Time
	// dropped counts the events dropped (refused: of them, refused by the
	// server) since the last warning event, droppedTotal since the start.
	dropped      int
	refused      int
	firstDrop    time.Time
	droppedTotal uint64
	dropLogAt    time.Time
	dropLogN     int

	// ctx ends when the sender stops: a send in progress is abandoned.
	ctx    context.Context
	cancel context.CancelFunc
	wake   chan struct{}
	flush  chan flushWaiter
	stop   chan struct{}
	done   chan struct{}
}

func newEventSender(send func(context.Context, []EventRequest) error, clock eventClock) *eventSender {
	ctx, cancel := context.WithCancel(context.Background())
	return &eventSender{
		send:   send,
		clock:  clock,
		ctx:    ctx,
		cancel: cancel,
		wake:   make(chan struct{}, 1),
		flush:  make(chan flushWaiter),
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}
}

// add queues events; urgent ones wake the sender.
func (s *eventSender) add(events []EventRequest) error {
	now := s.clock.Now()
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return errEventsStopped
	}
	wake := false
	for _, e := range events {
		size := eventSize(e)
		s.makeRoom(now, size)
		u := urgentEvent(e)
		if u {
			s.urgent++
		}
		s.queue = append(s.queue, queuedEvent{ev: e, urgent: u, size: size, at: now})
		s.bytes += size
		wake = wake || u || len(s.queue) == 1 || len(s.queue) >= eventBatchMax
	}
	s.mu.Unlock()
	if wake {
		s.poke()
	}
	return nil
}

func (s *eventSender) poke() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// makeRoom drops the oldest events when one of size more would not fit:
// non-urgent ones first, until eventDropChunk events and a tenth of the byte
// budget are free. Called with mu held.
func (s *eventSender) makeRoom(now time.Time, size int) {
	if len(s.queue) < eventQueueMax && s.bytes+size <= eventQueueBytes {
		return
	}
	n, b := len(s.queue), s.bytes
	full := func() bool {
		return n > eventQueueMax-eventDropChunk || b+size > eventQueueBytes-eventQueueBytes/10
	}
	drop := make([]bool, len(s.queue))
	for pass := 0; pass < 2 && full(); pass++ {
		for i, q := range s.queue {
			if !full() {
				break
			}
			if drop[i] || pass == 0 && q.urgent {
				continue
			}
			drop[i] = true
			n--
			b -= q.size
		}
	}
	kept := s.queue[:0]
	for i, q := range s.queue {
		if !drop[i] {
			kept = append(kept, q)
		} else if q.urgent {
			s.urgent--
		}
	}
	clear(s.queue[len(kept):])
	dropped := len(s.queue) - len(kept)
	s.queue, s.bytes = kept, b
	s.noteDropped(now, dropped, 0)
}

// noteDropped counts events lost, refused of them by the server. Called with
// mu held.
func (s *eventSender) noteDropped(now time.Time, n, refused int) {
	if n == 0 {
		return
	}
	if s.dropped == 0 {
		s.firstDrop = now
	}
	s.dropped += n
	s.refused += refused
	s.droppedTotal += uint64(n)
	s.dropLogN += n
	if refused == 0 && now.Sub(s.dropLogAt) >= eventDropLogEvery {
		log.Printf("[api] event queue full (%d events, %d MB): dropped the %d oldest events", eventQueueMax, eventQueueBytes>>20, s.dropLogN)
		s.dropLogAt, s.dropLogN = now, 0
	}
}

func (s *eventSender) refusedOne(now time.Time) {
	s.mu.Lock()
	s.noteDropped(now, 1, 1)
	s.mu.Unlock()
}

// take returns the next batch when one is due (or force is set), otherwise
// nil and when the next one is due (zero: queue empty).
func (s *eventSender) take(now time.Time, force bool) ([]EventRequest, time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dropped > 0 {
		details := map[string]string{
			"dropped":     strconv.Itoa(s.dropped),
			"since":       s.firstDrop.UTC().Format(time.RFC3339),
			"queue_limit": strconv.Itoa(eventQueueMax),
		}
		if s.refused > 0 {
			details["refused"] = strconv.Itoa(s.refused)
		}
		warn := EventRequest{
			Type:       "event_queue_overflow",
			Severity:   "warning",
			Details:    details,
			OccurredAt: s.firstDrop.UTC().Format(time.RFC3339),
		}
		size := eventSize(warn)
		s.queue = append(s.queue, queuedEvent{ev: warn, size: size, at: s.firstDrop})
		s.bytes += size
		s.dropped, s.refused = 0, 0
	}
	if len(s.queue) == 0 {
		s.queue = nil
		return nil, time.Time{}
	}
	due := s.queue[0].at.Add(eventFlushEvery)
	if gap := s.lastUrgent.Add(eventUrgentGap); s.urgent > 0 && gap.Before(due) {
		due = gap
	}
	if !force && len(s.queue) < eventBatchMax && now.Before(due) {
		return nil, due
	}
	n := min(len(s.queue), eventBatchMax)
	batch := make([]EventRequest, n)
	for i, q := range s.queue[:n] {
		batch[i] = q.ev
		s.bytes -= q.size
		if q.urgent {
			s.urgent--
			s.lastUrgent = now
		}
	}
	m := copy(s.queue, s.queue[n:])
	clear(s.queue[m:])
	s.queue = s.queue[:m]
	s.sending = n
	return batch, time.Time{}
}

func (s *eventSender) sent(n int) {
	s.mu.Lock()
	s.sending -= n
	s.mu.Unlock()
}

func (s *eventSender) depth() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.queue) + s.sending
}

// run delivers the queue until stop is closed.
func (s *eventSender) run() {
	defer close(s.done)
	var (
		pending []EventRequest // taken from the queue, not delivered yet
		// parts are the sizes of the parts of pending still to send: one
		// normally, halves after a refusal.
		parts []int
		fails int // failures of the current part in a row
		// someDelivered: a part of pending was delivered.
		someDelivered bool
		backoff       time.Duration
		retry         <-chan time.Time
		waiters       []flushWaiter // Flush callers
	)
	release := func(err error) {
		for _, w := range waiters {
			w.ch <- err
		}
		waiters = nil
	}
	for {
		// Flush callers that gave up stop the fast shutdown retries.
		live := waiters[:0]
		for _, w := range waiters {
			if err := w.ctx.Err(); err != nil {
				w.ch <- err
				continue
			}
			live = append(live, w)
		}
		waiters = live

		var due <-chan time.Time
		if retry == nil {
			if pending == nil {
				var at time.Time
				pending, at = s.take(s.clock.Now(), len(waiters) > 0)
				if pending != nil {
					parts, fails, someDelivered = []int{len(pending)}, 0, false
				} else if !at.IsZero() {
					due = s.clock.At(at)
				}
			}
			if pending != nil {
				n := parts[0]
				err := s.send(s.ctx, pending[:n])
				if err != nil && s.ctx.Err() != nil {
					// Stopping: what was not delivered is kept in the spool.
					s.spool(pending)
					release(errEventsStopped)
					return
				}
				var se *statusError
				isStatus := errors.As(err, &se)
				delivered := err == nil
				refused := isStatus && se.permanent()
				// A server error is blamed on an event only when it persists
				// and another part of the batch was delivered meanwhile.
				poisoned := isStatus && se.serverFault() && fails+1 >= eventPoisonTries
				switch {
				case delivered:
					backoff = 0
					someDelivered = true
				case (refused || poisoned) && n > 1:
					log.Printf("[api] %d events not accepted (%v): sending them in halves", n, err)
					parts = append([]int{n / 2, n - n/2}, parts[1:]...)
					fails = 0
					retry = s.clock.At(s.clock.Now().Add(eventSplitGap))
				case refused || poisoned && someDelivered:
					if pending[0].Type == "event_queue_overflow" {
						// Not counted: that would queue a new warning.
						log.Printf("[api] overflow warning not accepted, dropped: %v", err)
					} else {
						log.Printf("[api] event %s not accepted, dropped: %v", pending[0].Type, err)
						s.refusedOne(s.clock.Now())
					}
					s.sent(n)
					pending, parts, fails = pending[n:], parts[1:], 0
					if len(parts) == 0 {
						pending = nil
					}
					retry = s.clock.At(s.clock.Now().Add(eventSplitGap))
				default:
					fails++
					backoff = min(max(2*backoff, eventRetryMin), eventRetryMax)
					wait := backoff
					if isStatus && se.retryAfter > wait {
						wait = min(se.retryAfter, eventRetryAfterMax)
					}
					if len(waiters) > 0 {
						wait = eventFlushRetry
					}
					log.Printf("[api] event delivery failed (%d events), retrying in %s: %v", n, wait, err)
					retry = s.clock.At(s.clock.Now().Add(wait))
				}
				if delivered {
					s.sent(n)
					pending, parts, fails = pending[n:], parts[1:], 0
					if len(parts) == 0 {
						pending = nil
					}
					continue
				}
			} else if len(waiters) > 0 {
				release(nil)
				continue
			}
		}
		select {
		case <-s.wake:
		case <-due:
		case <-retry:
			retry = nil
		case w := <-s.flush:
			waiters = append(waiters, w)
			retry = nil
		case <-s.stop:
			s.spool(pending)
			release(errEventsStopped)
			return
		}
	}
}

// Flush sends every queued event now and waits until they are delivered or
// ctx ends; failed sends are retried every eventFlushRetry meanwhile.
func (s *eventSender) Flush(ctx context.Context) error {
	w := flushWaiter{ctx: ctx, ch: make(chan error, 1)}
	select {
	case s.flush <- w:
	case <-s.done:
		return errEventsStopped
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-w.ch:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close flushes the queue (within ctx), then stops the sender: the urgent
// events still not delivered are written to the spool. Events reported
// afterwards are refused.
func (s *eventSender) Close(ctx context.Context) error {
	err := s.Flush(ctx)
	s.mu.Lock()
	already := s.stopped
	s.stopped = true
	s.mu.Unlock()
	if !already {
		close(s.stop)
		s.cancel()
	}
	<-s.done
	return err
}

// spool writes the urgent events of pending and of the queue to spoolPath
// (0600, replaced atomically), for replay at the next start. Called by run
// as it stops.
func (s *eventSender) spool(pending []EventRequest) {
	var keep []EventRequest
	for _, e := range pending {
		if urgentEvent(e) {
			keep = append(keep, e)
		}
	}
	s.mu.Lock()
	for _, q := range s.queue {
		if q.urgent {
			keep = append(keep, q.ev)
		}
	}
	path := s.spoolPath
	s.mu.Unlock()
	if len(keep) == 0 || path == "" {
		return
	}
	if len(keep) > eventQueueMax {
		keep = keep[len(keep)-eventQueueMax:]
	}
	if err := writeSpool(path, keep); err != nil {
		log.Printf("[api] %d urgent events not delivered and not saved: %v", len(keep), err)
		return
	}
	log.Printf("[api] %d urgent events not delivered: saved to %s, sent at the next start", len(keep), path)
}

func writeSpool(path string, events []EventRequest) error {
	data, err := json.Marshal(events)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Chmod(0o600)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}

// readSpool returns the events saved at the last shutdown and removes the
// file, so they are queued once.
func readSpool(path string) ([]EventRequest, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer os.Remove(path)
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, eventSpoolMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > eventSpoolMaxBytes {
		return nil, fmt.Errorf("%s is larger than %d MB", path, eventSpoolMaxBytes>>20)
	}
	var events []EventRequest
	if err := json.Unmarshal(data, &events); err != nil {
		return nil, err
	}
	if len(events) > eventQueueMax {
		events = events[len(events)-eventQueueMax:]
	}
	for i := range events {
		limitEvent(&events[i])
	}
	return events, nil
}

// limitEvent bounds the size of an event's details: values are cut to
// eventDetailMax bytes (uri and user_agent to eventDetailShortMax), keys to
// eventDetailKeyMax (as the other fields), and at most eventDetailKeys keys are kept (the first in
// sort order). The details map must belong to the event (copied).
func limitEvent(e *EventRequest) {
	e.Type = truncateUTF8(e.Type, eventDetailKeyMax)
	e.Severity = truncateUTF8(e.Severity, eventDetailKeyMax)
	e.SourceIP = truncateUTF8(e.SourceIP, eventDetailKeyMax)
	e.Protocol = truncateUTF8(e.Protocol, eventDetailKeyMax)
	e.OccurredAt = truncateUTF8(e.OccurredAt, eventDetailKeyMax)
	if len(e.Details) == 0 {
		return
	}
	keys := make([]string, 0, len(e.Details))
	for k := range e.Details {
		keys = append(keys, k)
	}
	if len(keys) > eventDetailKeys {
		sort.Strings(keys)
		for _, k := range keys[eventDetailKeys:] {
			delete(e.Details, k)
		}
		keys = keys[:eventDetailKeys]
	}
	for _, k := range keys {
		v := e.Details[k]
		limit := eventDetailMax
		if k == "uri" || k == "user_agent" {
			limit = eventDetailShortMax
		}
		short := truncateUTF8(k, eventDetailKeyMax)
		if short != k {
			delete(e.Details, k)
		}
		e.Details[short] = truncateUTF8(v, limit)
	}
}

// truncateUTF8 cuts s to at most n bytes, not inside a UTF-8 sequence.
func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// eventSize estimates the memory an event holds.
func eventSize(e EventRequest) int {
	n := 128 + len(e.Type) + len(e.Severity) + len(e.SourceIP) + len(e.Protocol) + len(e.OccurredAt)
	for k, v := range e.Details {
		n += 32 + len(k) + len(v)
	}
	return n
}

// urgentEvent reports the events sent without waiting for the next batch:
// critical ones, and whatever their severity, brute force and ban
// detections, malware detections and quarantine results, web attacks of
// high severity, the results of firewall changes, virtual patches and
// restores, everything that failed or was rolled back, and agent updates.
func urgentEvent(e EventRequest) bool {
	t := e.Type
	switch {
	case e.Severity == "critical",
		strings.Contains(t, "brute"),
		strings.Contains(t, "ban"),
		strings.HasSuffix(t, "_failed"),
		strings.HasSuffix(t, "_rolled_back"),
		strings.HasPrefix(t, "quarantine_"),
		strings.HasPrefix(t, "firewall_"),
		strings.HasPrefix(t, "virtual_patch_"),
		strings.HasPrefix(t, "update_"),
		strings.HasSuffix(t, "_after_update"):
		return true
	case strings.HasPrefix(t, "malware_"):
		return t != "malware_scan_started" && t != "malware_scan_progress"
	case e.Severity == "high" && e.SourceIP != "":
		// Web attacks: reported by ModSecurity or the access log watcher.
		return e.Details["source"] == "modsecurity" || e.Details["domain"] != "" || e.Details["uri"] != ""
	}
	return false
}

// statusError is an HTTP error reply.
type statusError struct {
	code int
	body string
	// retryAfter is the wait a 429 or 503 reply asked for (zero: none).
	retryAfter time.Duration
}

func newStatusError(resp *http.Response) *statusError {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	e := &statusError{code: resp.StatusCode, body: string(b)}
	if v := strings.TrimSpace(resp.Header.Get("Retry-After")); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
			e.retryAfter = time.Duration(secs) * time.Second
		} else if t, err := http.ParseTime(v); err == nil {
			e.retryAfter = max(time.Until(t), 0)
		}
	}
	return e
}

func (e *statusError) Error() string {
	return "server returned " + strconv.Itoa(e.code) + ": " + e.body
}

// permanent reports a refusal of the events themselves, which sending them
// again would not change. Other errors (401 after a token change, 403 from a
// proxy, 404 during a deploy...) are retried.
func (e *statusError) permanent() bool {
	switch e.code {
	case http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity:
		return true
	}
	return false
}

// serverFault reports an error of the server itself, which one event may
// cause; not a proxy that cannot reach it (502, 503, 504: a dashboard that
// is down or moving).
func (e *statusError) serverFault() bool {
	switch e.code {
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return false
	}
	return e.code >= 500
}
