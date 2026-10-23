package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

// fakeClock moves only when the test advances it.
type fakeClock struct {
	mu      sync.Mutex
	now     time.Time
	waiters []fakeTimer
}

type fakeTimer struct {
	at time.Time
	ch chan time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) At(t time.Time) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := make(chan time.Time, 1)
	if !t.After(c.now) {
		ch <- c.now
		return ch
	}
	c.waiters = append(c.waiters, fakeTimer{at: t, ch: ch})
	return ch
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	kept := c.waiters[:0]
	for _, w := range c.waiters {
		if !w.at.After(c.now) {
			w.ch <- c.now
			continue
		}
		kept = append(kept, w)
	}
	c.waiters = kept
}

// armed waits until the sender set a timer, so advancing the clock
// reaches it.
func (c *fakeClock) armed(t *testing.T) {
	t.Helper()
	eventually(t, "a timer", func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return len(c.waiters) > 0
	})
}

// recorder is the send function of the tests: it records every batch and
// fails while fail returns an error.
type recorder struct {
	mu      sync.Mutex
	batches [][]EventRequest
	tries   int
	fail    func(batch []EventRequest) error
	// block makes a send wait until it is abandoned.
	block bool
}

func (r *recorder) send(ctx context.Context, batch []EventRequest) error {
	r.mu.Lock()
	block := r.block
	r.mu.Unlock()
	if block {
		<-ctx.Done()
		return ctx.Err()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tries++
	if r.fail != nil {
		if err := r.fail(batch); err != nil {
			return err
		}
	}
	r.batches = append(r.batches, append([]EventRequest(nil), batch...))
	return nil
}

func (r *recorder) setFail(f func([]EventRequest) error) {
	r.mu.Lock()
	r.fail = f
	r.mu.Unlock()
}

func (r *recorder) got() [][]EventRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]EventRequest(nil), r.batches...)
}

func (r *recorder) attempts() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.tries
}

func (r *recorder) types() []string {
	var out []string
	for _, b := range r.got() {
		for _, e := range b {
			out = append(out, e.Type)
		}
	}
	return out
}

func startSender(t *testing.T) (*eventSender, *recorder, *fakeClock) {
	t.Helper()
	rec := &recorder{}
	clock := newFakeClock()
	s := newEventSender(rec.send, clock)
	go s.run()
	t.Cleanup(func() {
		s.mu.Lock()
		s.stopped = true
		s.mu.Unlock()
		select {
		case <-s.stop:
		default:
			close(s.stop)
		}
		s.cancel()
		<-s.done
	})
	return s, rec, clock
}

// eventually waits for cond, the sender runs in its own goroutine.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// quiet checks that nothing is sent for a while.
func quiet(t *testing.T, rec *recorder, want int) {
	t.Helper()
	time.Sleep(30 * time.Millisecond)
	if n := len(rec.got()); n != want {
		t.Fatalf("%d batches sent, want %d", n, want)
	}
}

func info(typ string) EventRequest {
	return EventRequest{Type: typ, Severity: "info", OccurredAt: "2026-10-15T12:00:00Z"}
}

func TestEventsWaitForTheFlushInterval(t *testing.T) {
	s, rec, clock := startSender(t)
	for i := 0; i < 3; i++ {
		if err := s.add([]EventRequest{info("port_scan")}); err != nil {
			t.Fatal(err)
		}
	}
	clock.armed(t)
	clock.Advance(eventFlushEvery - time.Millisecond)
	quiet(t, rec, 0)
	clock.Advance(time.Millisecond)
	eventually(t, "the flush", func() bool { return len(rec.got()) == 1 })
	if b := rec.got()[0]; len(b) != 3 {
		t.Fatalf("batch of %d events, want 3 (one request)", len(b))
	}
	quiet(t, rec, 1)
}

func TestFlushIntervalCountsFromTheOldestEvent(t *testing.T) {
	s, rec, clock := startSender(t)
	_ = s.add([]EventRequest{info("a")})
	clock.armed(t)
	clock.Advance(3 * time.Second)
	_ = s.add([]EventRequest{info("b")})
	clock.Advance(2 * time.Second)
	eventually(t, "the flush", func() bool { return len(rec.got()) == 1 })
	if got := rec.types(); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("sent %v, want [a b]", got)
	}
}

func TestFullBatchIsSentWithoutWaiting(t *testing.T) {
	s, rec, _ := startSender(t)
	for i := 0; i < eventBatchMax; i++ {
		_ = s.add([]EventRequest{info("e" + strconv.Itoa(i))})
	}
	eventually(t, "the full batch", func() bool { return len(rec.got()) == 1 })
	if b := rec.got()[0]; len(b) != eventBatchMax {
		t.Fatalf("batch of %d events, want %d", len(b), eventBatchMax)
	}
}

func TestUrgentEventIsSentAtOnceWithTheQueueBeforeIt(t *testing.T) {
	s, rec, _ := startSender(t)
	_ = s.add([]EventRequest{info("port_scan"), info("bot_detected")})
	quiet(t, rec, 0)
	_ = s.add([]EventRequest{{Type: "brute_force", Severity: "critical", SourceIP: "203.0.113.2"}})
	eventually(t, "the urgent send", func() bool { return len(rec.got()) == 1 })
	if got := rec.types(); len(got) != 3 || got[2] != "brute_force" {
		t.Fatalf("sent %v, want the queued events then brute_force", got)
	}
}

func TestEventsAreNeverMerged(t *testing.T) {
	s, rec, _ := startSender(t)
	var burst []EventRequest
	for i := 0; i < 7; i++ {
		burst = append(burst, EventRequest{Type: "brute_force", Severity: "critical", SourceIP: "203.0.113.2",
			Details: map[string]string{"n": strconv.Itoa(i)}, OccurredAt: "2026-10-15T12:00:0" + strconv.Itoa(i) + "Z"})
	}
	_ = s.add(burst)
	eventually(t, "the burst", func() bool { return len(rec.types()) == 7 })
	if n := len(rec.got()); n != 1 {
		t.Fatalf("%d requests for events reported together, want 1", n)
	}
	for i, e := range rec.got()[0] {
		if e.Details["n"] != strconv.Itoa(i) || e.OccurredAt != burst[i].OccurredAt {
			t.Fatalf("event %d changed: %+v", i, e)
		}
	}
}

func TestUrgentEvents(t *testing.T) {
	for _, tc := range []struct {
		e    EventRequest
		want bool
	}{
		{EventRequest{Type: "db_exposed", Severity: "critical"}, true},
		{EventRequest{Type: "brute_force_ssh", Severity: "warning"}, true},
		{EventRequest{Type: "wp_bruteforce", Severity: "info"}, true},
		{EventRequest{Type: "port_scan_ban", Severity: "info"}, true},
		{EventRequest{Type: "malware_realtime", Severity: "warning"}, true},
		{EventRequest{Type: "malware_scan_progress", Severity: "info"}, false},
		{EventRequest{Type: "quarantine_completed", Severity: "info"}, true},
		{EventRequest{Type: "quarantine_restored", Severity: "info"}, true},
		{EventRequest{Type: "firewall_action_done", Severity: "info"}, true},
		{EventRequest{Type: "virtual_patch_done", Severity: "info"}, true},
		{EventRequest{Type: "trust_token_placed", Severity: "info"}, true},
		{EventRequest{Type: "hardening_fix_rolled_back", Severity: "warning"}, true},
		{EventRequest{Type: "yara_install_failed", Severity: "warning"}, true},
		{EventRequest{Type: "update_completed", Severity: "info"}, true},
		{EventRequest{Type: "update_available", Severity: "info"}, true},
		{EventRequest{Type: "sql_injection", Severity: "high", SourceIP: "203.0.113.2", Details: map[string]string{"source": "modsecurity"}}, true},
		{EventRequest{Type: "xss_attempt", Severity: "high", SourceIP: "203.0.113.2", Details: map[string]string{"domain": "example.com"}}, true},
		{EventRequest{Type: "xss_attempt", Severity: "warning", SourceIP: "203.0.113.2", Details: map[string]string{"domain": "example.com"}}, false},
		{EventRequest{Type: "port_scan", Severity: "high", SourceIP: "203.0.113.2"}, false},
		{EventRequest{Type: "bot_detected", Severity: "info"}, false},
		{EventRequest{Type: "host_preflight", Severity: "info"}, false},
		{EventRequest{Type: "yara_rules_updated", Severity: "info"}, false},
	} {
		if got := urgentEvent(tc.e); got != tc.want {
			t.Errorf("urgentEvent(%s/%s) = %v, want %v", tc.e.Type, tc.e.Severity, got, tc.want)
		}
	}
}

func TestQueueCapDropsOldestNonUrgentAndWarns(t *testing.T) {
	s, rec, _ := startSender(t)
	rec.setFail(func([]EventRequest) error { return errors.New("dashboard down") })
	_ = s.add([]EventRequest{{Type: "firewall_action_done", Severity: "info"}})
	eventually(t, "the first try", func() bool { return rec.attempts() == 1 })
	// The batch being sent holds the urgent event; fill the queue past the cap.
	_ = s.add([]EventRequest{{Type: "brute_force", Severity: "critical"}})
	for i := 0; i < eventQueueMax; i++ {
		_ = s.add([]EventRequest{info("n" + strconv.Itoa(i))})
	}
	s.mu.Lock()
	queued, dropped, total := len(s.queue), s.dropped, s.droppedTotal
	first := s.queue[0].ev.Type
	s.mu.Unlock()
	if queued > eventQueueMax {
		t.Fatalf("%d events queued, cap is %d", queued, eventQueueMax)
	}
	if dropped != eventDropChunk || total != uint64(eventDropChunk) {
		t.Fatalf("dropped %d (total %d), want %d", dropped, total, eventDropChunk)
	}
	if first != "brute_force" {
		t.Fatalf("queue starts with %s: the urgent event must not be dropped", first)
	}

	rec.setFail(nil)
	if err := s.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	types := rec.types()
	if types[0] != "firewall_action_done" || types[1] != "brute_force" || types[2] != "n"+strconv.Itoa(eventDropChunk) {
		t.Fatalf("sent %v..., want the batch, the urgent event, then the oldest event kept", types[:3])
	}
	last := rec.got()[len(rec.got())-1]
	warn := last[len(last)-1]
	if warn.Type != "event_queue_overflow" || warn.Severity != "warning" || warn.Details["dropped"] != strconv.Itoa(eventDropChunk) {
		t.Fatalf("last event %+v, want one overflow warning with the dropped count", warn)
	}
	if n := len(types); n != 1+1+eventQueueMax-eventDropChunk+1 {
		t.Fatalf("%d events sent", n)
	}
}

func TestFailedSendIsRetriedWithBackoffInOrder(t *testing.T) {
	s, rec, clock := startSender(t)
	failing := true
	rec.setFail(func([]EventRequest) error {
		if failing {
			return &statusError{code: http.StatusServiceUnavailable, body: "down"}
		}
		return nil
	})
	_ = s.add([]EventRequest{info("a"), {Type: "update_started", Severity: "info"}})
	eventually(t, "the first try", func() bool { return rec.attempts() == 1 })
	_ = s.add([]EventRequest{info("b")})

	clock.armed(t)
	clock.Advance(eventRetryMin - time.Millisecond)
	quiet(t, rec, 0)
	if n := rec.attempts(); n != 1 {
		t.Fatalf("%d tries before the backoff ended", n)
	}
	clock.Advance(time.Millisecond)
	eventually(t, "the second try", func() bool { return rec.attempts() == 2 })
	// The backoff doubles.
	clock.armed(t)
	clock.Advance(2*eventRetryMin - time.Millisecond)
	quiet(t, rec, 0)
	if n := rec.attempts(); n != 2 {
		t.Fatalf("%d tries, the backoff did not double", n)
	}

	rec.mu.Lock()
	failing = false
	rec.mu.Unlock()
	clock.Advance(time.Millisecond)
	eventually(t, "delivery", func() bool { return len(rec.got()) == 1 })
	clock.armed(t)
	clock.Advance(eventFlushEvery)
	eventually(t, "the event queued later", func() bool { return len(rec.got()) == 2 })
	if got := rec.types(); len(got) != 3 || got[0] != "a" || got[1] != "update_started" || got[2] != "b" {
		t.Fatalf("sent %v, want [a update_started b]", got)
	}
}

func TestRefusedBatchIsSplitUntilTheRefusedEvent(t *testing.T) {
	s, rec, clock := startSender(t)
	rec.setFail(func(b []EventRequest) error {
		for _, e := range b {
			if e.Type == "bad" {
				return &statusError{code: http.StatusUnprocessableEntity, body: "invalid"}
			}
		}
		return nil
	})
	_ = s.add([]EventRequest{info("a"), info("bad"), info("c")})
	drive(t, clock, eventSplitGap, "the events", func() bool { return len(rec.types()) == 3 })
	got := rec.types()
	if len(got) != 3 || got[0] != "a" || got[1] != "c" || got[2] != "event_queue_overflow" {
		t.Fatalf("sent %v, want [a c event_queue_overflow]: only the refused event is lost", got)
	}
	warn := rec.got()[len(rec.got())-1][0]
	if warn.Details["dropped"] != "1" || warn.Details["refused"] != "1" {
		t.Fatalf("overflow details %v, want the refused event counted", warn.Details)
	}
	// [a bad c], [a], [bad c], [bad], [c], the warning.
	if n := rec.attempts(); n != 6 {
		t.Fatalf("%d requests, want 6", n)
	}
}

func TestUnauthorizedIsRetriedNotDropped(t *testing.T) {
	s, rec, _ := startSender(t)
	rec.setFail(func([]EventRequest) error { return &statusError{code: http.StatusUnauthorized, body: "token"} })
	_ = s.add([]EventRequest{info("a"), info("b")})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := s.Flush(ctx); err == nil {
		t.Fatal("flush succeeded while the server refused the token")
	}
	if n := rec.attempts(); n != 1 {
		t.Fatalf("%d requests, want 1 then a pause (no event-by-event sending)", n)
	}
	if d := s.depth(); d != 2 {
		t.Fatalf("%d events kept, want 2", d)
	}
}

func TestCloseFlushesAndRefusesLaterEvents(t *testing.T) {
	s, rec, _ := startSender(t)
	_ = s.add([]EventRequest{info("a"), info("b")})
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := rec.types(); len(got) != 2 {
		t.Fatalf("sent %v at shutdown, want [a b]", got)
	}
	if err := s.add([]EventRequest{info("late")}); !errors.Is(err, errEventsStopped) {
		t.Fatalf("event after close: %v, want refused", err)
	}
}

// drive advances the clock past every timer the sender sets, by step, until
// cond holds.
func drive(t *testing.T, clock *fakeClock, step time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		clock.mu.Lock()
		armed := len(clock.waiters) > 0
		clock.mu.Unlock()
		if armed {
			clock.Advance(step)
		} else {
			time.Sleep(time.Millisecond)
		}
	}
}

func TestShutdownFlushKeepsRetrying(t *testing.T) {
	s, rec, clock := startSender(t)
	rec.setFail(func([]EventRequest) error {
		if rec.tries <= 3 {
			return errors.New("connection refused")
		}
		return nil
	})
	_ = s.add([]EventRequest{info("a")})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Flush(ctx) }()
	drive(t, clock, eventFlushRetry, "the flush", func() bool { return len(done) == 1 })
	if err := <-done; err != nil {
		t.Fatalf("flush: %v", err)
	}
	if n := rec.attempts(); n != 4 {
		t.Fatalf("%d tries, want 4", n)
	}
	// The retries did not wait for the backoff (1 s, 2 s, 4 s).
	if d := clock.Now().Sub(newFakeClock().Now()); d >= 7*eventRetryMin {
		t.Fatalf("delivered after %s: the flush waited for the backoff", d)
	}
}

func TestCloseSpoolsUrgentEventsForTheNextStart(t *testing.T) {
	s, rec, _ := startSender(t)
	path := filepath.Join(t.TempDir(), "state", "unsent-events.json")
	s.spoolPath = path
	rec.setFail(func([]EventRequest) error { return errors.New("connection refused") })
	_ = s.add([]EventRequest{info("a"), {Type: "brute_force", Severity: "critical", SourceIP: "203.0.113.2", OccurredAt: "2026-10-15T12:00:00Z"}})
	_ = s.add([]EventRequest{{Type: "firewall_action_done", Severity: "info"}, info("b")})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := s.Close(ctx); err == nil {
		t.Fatal("close reported success while nothing was delivered")
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("spool mode %v, want 0600", fi.Mode().Perm())
	}
	events, err := readSpool(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].Type != "brute_force" || events[0].OccurredAt != "2026-10-15T12:00:00Z" || events[1].Type != "firewall_action_done" {
		t.Fatalf("spooled %+v, want the two urgent events, unchanged", events)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("spool still there after it was read: its events would be sent twice")
	}
}

func TestSendInProgressAtShutdownIsAbandonedAndSpooled(t *testing.T) {
	s, rec, _ := startSender(t)
	path := filepath.Join(t.TempDir(), "unsent-events.json")
	s.spoolPath = path
	rec.mu.Lock()
	rec.block = true
	rec.mu.Unlock()
	_ = s.add([]EventRequest{{Type: "quarantine_completed", Severity: "info"}})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_ = s.Close(ctx)
	events, err := readSpool(path)
	if err != nil || len(events) != 1 || events[0].Type != "quarantine_completed" {
		t.Fatalf("spooled %v (%v), want the event being sent", events, err)
	}
}

func TestSpoolIsReplayedAtStart(t *testing.T) {
	var mu sync.Mutex
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Events []EventRequest `json:"events"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		for _, e := range body.Events {
			got = append(got, e.Type+"@"+e.OccurredAt)
		}
		mu.Unlock()
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "unsent-events.json")
	if err := writeSpool(path, []EventRequest{{Type: "update_completed", Severity: "info", OccurredAt: "2026-10-15T11:59:00Z"}}); err != nil {
		t.Fatal(err)
	}
	c := New(srv.URL, "tok")
	c.SetEventSpool(path)
	if err := c.CloseEvents(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0] != "update_completed@2026-10-15T11:59:00Z" {
		t.Fatalf("sent %v, want the spooled event with its own time", got)
	}
}

func TestSpoolThatIsNotARegularFileIsIgnored(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere.json")
	if err := os.WriteFile(target, []byte(`[{"type":"x","severity":"info","occurred_at":""}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "unsent-events.json")
	if err := os.Symlink(target, path); err != nil {
		t.Skip(err)
	}
	if events, err := readSpool(path); err == nil || len(events) != 0 {
		t.Fatalf("read %v through a link, want it refused", events)
	}
}

func TestUrgentSendsAreAtLeastAGapApart(t *testing.T) {
	s, rec, clock := startSender(t)
	urgent := func(n string) EventRequest {
		return EventRequest{Type: "brute_force", Severity: "critical", Details: map[string]string{"n": n}}
	}
	_ = s.add([]EventRequest{urgent("1")})
	eventually(t, "the first urgent send", func() bool { return len(rec.got()) == 1 })
	for i := 2; i <= 5; i++ {
		_ = s.add([]EventRequest{urgent(strconv.Itoa(i))})
	}
	clock.armed(t)
	clock.Advance(eventUrgentGap - time.Millisecond)
	quiet(t, rec, 1)
	clock.Advance(time.Millisecond)
	eventually(t, "the next urgent send", func() bool { return len(rec.got()) == 2 })
	if b := rec.got()[1]; len(b) != 4 || b[0].Details["n"] != "2" || b[3].Details["n"] != "5" {
		t.Fatalf("second request %v, want the 4 urgent events in order", b)
	}
	// After a quiet period the next urgent event goes at once.
	clock.Advance(10 * time.Second)
	_ = s.add([]EventRequest{urgent("6")})
	eventually(t, "the urgent send after a pause", func() bool { return len(rec.got()) == 3 })
}

func TestRetryAfterIsHonored(t *testing.T) {
	s, rec, clock := startSender(t)
	rec.setFail(func([]EventRequest) error {
		if rec.tries == 1 {
			return &statusError{code: http.StatusTooManyRequests, body: "slow down", retryAfter: 10 * time.Second}
		}
		return nil
	})
	_ = s.add([]EventRequest{{Type: "update_completed", Severity: "info"}})
	eventually(t, "the first try", func() bool { return rec.attempts() == 1 })
	clock.armed(t)
	clock.Advance(10*time.Second - time.Millisecond)
	quiet(t, rec, 0)
	if n := rec.attempts(); n != 1 {
		t.Fatalf("%d tries before Retry-After ended", n)
	}
	clock.Advance(time.Millisecond)
	eventually(t, "delivery", func() bool { return len(rec.got()) == 1 })
}

func TestRetryAfterHeader(t *testing.T) {
	for _, tc := range []struct {
		header string
		want   time.Duration
	}{
		{"7", 7 * time.Second},
		{"", 0},
		{"soon", 0},
		{time.Now().Add(-time.Minute).UTC().Format(http.TimeFormat), 0},
	} {
		resp := &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("x"))}
		if tc.header != "" {
			resp.Header.Set("Retry-After", tc.header)
		}
		if got := newStatusError(resp).retryAfter; got != tc.want {
			t.Errorf("Retry-After %q: %s, want %s", tc.header, got, tc.want)
		}
	}
}

func TestRepeatedServerErrorsIsolateAPoisonEvent(t *testing.T) {
	s, rec, clock := startSender(t)
	rec.setFail(func(b []EventRequest) error {
		for _, e := range b {
			if e.Type == "poison" {
				return &statusError{code: http.StatusInternalServerError, body: "boom"}
			}
		}
		return nil
	})
	_ = s.add([]EventRequest{info("a"), info("poison"), info("c")})
	drive(t, clock, eventRetryMax, "the events after the poison one", func() bool { return len(rec.types()) == 3 })
	got := rec.types()
	if got[0] != "a" || got[1] != "c" || got[2] != "event_queue_overflow" {
		t.Fatalf("sent %v, want [a c event_queue_overflow]", got)
	}
	// [a poison c] x10, [a], [poison c] x10, [poison] x10, [c], the warning.
	if n := rec.attempts(); n != 3*eventPoisonTries+3 {
		t.Fatalf("%d requests, want %d", n, 3*eventPoisonTries+3)
	}
}

func TestRefusedOverflowWarningIsNotWarnedAgain(t *testing.T) {
	s, rec, clock := startSender(t)
	rec.setFail(func(b []EventRequest) error {
		for _, e := range b {
			if e.Type == "bad" || e.Type == "event_queue_overflow" {
				return &statusError{code: http.StatusUnprocessableEntity, body: "invalid"}
			}
		}
		return nil
	})
	_ = s.add([]EventRequest{{Type: "bad", Severity: "critical"}})
	drive(t, clock, eventSplitGap, "the warning attempt", func() bool { return rec.attempts() == 2 })
	clock.Advance(time.Minute)
	quiet(t, rec, 0)
	if n := rec.attempts(); n != 2 {
		t.Fatalf("%d requests: a refused warning must not produce another one", n)
	}
}

func TestServerErrorsWithoutAnyDeliveryDropNothing(t *testing.T) {
	s, rec, clock := startSender(t)
	rec.setFail(func([]EventRequest) error { return &statusError{code: http.StatusInternalServerError, body: "boom"} })
	_ = s.add([]EventRequest{{Type: "brute_force", Severity: "critical"}, info("b")})
	drive(t, clock, eventRetryMax, "many tries", func() bool { return rec.attempts() >= 4*eventPoisonTries })
	if d := s.depth(); d != 2 {
		t.Fatalf("%d events kept, want 2: an outage is not a poison event", d)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.droppedTotal != 0 {
		t.Fatalf("%d events dropped", s.droppedTotal)
	}
}

func TestDashboardDownIsNeverSplit(t *testing.T) {
	s, rec, clock := startSender(t)
	rec.setFail(func([]EventRequest) error { return &statusError{code: http.StatusBadGateway, body: "down"} })
	_ = s.add([]EventRequest{{Type: "update_completed", Severity: "info"}, info("b")})
	drive(t, clock, eventRetryMax, "many tries", func() bool { return rec.attempts() >= 3*eventPoisonTries })
	if d := s.depth(); d != 2 {
		t.Fatalf("%d events kept, want 2: a dashboard that is down loses nothing", d)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.droppedTotal != 0 {
		t.Fatalf("%d events dropped", s.droppedTotal)
	}
}

// A sender that does not run: add and take only.
func idleSender() (*eventSender, *fakeClock) {
	clock := newFakeClock()
	return newEventSender(func(context.Context, []EventRequest) error { return nil }, clock), clock
}

func TestFullChunkDroppedWhenFewNonUrgentRemain(t *testing.T) {
	s, clock := idleSender()
	for i := 0; i < 10; i++ {
		_ = s.add([]EventRequest{info("n")})
	}
	for i := 0; i < eventQueueMax-10; i++ {
		_ = s.add([]EventRequest{{Type: "brute_force", Severity: "critical", Details: map[string]string{"n": strconv.Itoa(i)}}})
	}
	_ = s.add([]EventRequest{info("last")})
	s.mu.Lock()
	if n := len(s.queue); n != eventQueueMax-eventDropChunk+1 {
		t.Fatalf("%d queued, want %d", n, eventQueueMax-eventDropChunk+1)
	}
	if s.urgent != eventQueueMax-eventDropChunk {
		t.Fatalf("urgent count %d, want %d", s.urgent, eventQueueMax-eventDropChunk)
	}
	if first := s.queue[0].ev.Details["n"]; first != strconv.Itoa(eventDropChunk-10) {
		t.Fatalf("queue starts with urgent event %s, want the oldest ones dropped", first)
	}
	// The vacated slots hold nothing.
	for _, q := range s.queue[len(s.queue):cap(s.queue)] {
		if q.ev.Details != nil || q.ev.Type != "" {
			t.Fatal("dropped event still referenced by the queue")
		}
	}
	if s.dropLogN != 0 {
		t.Fatalf("first drop not logged at once (%d pending)", s.dropLogN)
	}
	firstDrop := s.firstDrop
	s.mu.Unlock()

	// A second overflow within eventDropLogEvery is not logged again.
	for i := 0; i < eventDropChunk; i++ {
		_ = s.add([]EventRequest{info("more")})
	}
	s.mu.Lock()
	if s.dropLogN != eventDropChunk {
		t.Fatalf("%d drops waiting to be logged, want %d", s.dropLogN, eventDropChunk)
	}
	s.mu.Unlock()

	clock.Advance(time.Minute)
	_, _ = s.take(clock.Now(), true)
	s.mu.Lock()
	defer s.mu.Unlock()
	warn := s.queue[len(s.queue)-1].ev
	if warn.Type != "event_queue_overflow" || warn.OccurredAt != firstDrop.UTC().Format(time.RFC3339) {
		t.Fatalf("overflow event %+v, want occurred_at = first drop", warn)
	}
	if warn.Details["dropped"] != strconv.Itoa(2*eventDropChunk) {
		t.Fatalf("overflow reports %s dropped, want %d", warn.Details["dropped"], 2*eventDropChunk)
	}
}

func TestQueueByteBudget(t *testing.T) {
	s, _ := idleSender()
	big := func() EventRequest {
		d := map[string]string{}
		for i := 0; i < eventDetailKeys; i++ {
			d["k"+strconv.Itoa(i)] = strings.Repeat("x", eventDetailMax)
		}
		return EventRequest{Type: "port_scan", Severity: "info", Details: d}
	}
	for i := 0; i < 300; i++ {
		_ = s.add([]EventRequest{big()})
		s.mu.Lock()
		over := s.bytes > eventQueueBytes
		s.mu.Unlock()
		if over {
			t.Fatalf("queue holds %d bytes after %d events, budget %d", s.bytes, i+1, eventQueueBytes)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.droppedTotal == 0 || len(s.queue) >= 300 {
		t.Fatalf("%d queued, %d dropped: the byte budget did not apply", len(s.queue), s.droppedTotal)
	}
	sum := 0
	for _, q := range s.queue {
		sum += q.size
	}
	if sum != s.bytes {
		t.Fatalf("byte count %d, events hold %d", s.bytes, sum)
	}
}

func TestLimitEvent(t *testing.T) {
	d := map[string]string{
		"message":    strings.Repeat("m", 5000),
		"uri":        strings.Repeat("u", 1000),
		"user_agent": strings.Repeat("a", 1000),
		"utf8":       strings.Repeat("é", 2000),
		"short":      "kept",
	}
	for i := 0; i < 100; i++ {
		d["z"+strconv.Itoa(1000+i)] = "v"
	}
	e := EventRequest{Type: "x", Severity: "info", Details: d}
	limitEvent(&e)
	if n := len(e.Details); n != eventDetailKeys {
		t.Fatalf("%d keys, want %d", n, eventDetailKeys)
	}
	if e.Details["short"] != "kept" || len(e.Details["message"]) != eventDetailMax {
		t.Fatalf("message %d bytes, want %d", len(e.Details["message"]), eventDetailMax)
	}
	if len(e.Details["uri"]) != eventDetailShortMax || len(e.Details["user_agent"]) != eventDetailShortMax {
		t.Fatalf("uri %d, user_agent %d bytes, want %d", len(e.Details["uri"]), len(e.Details["user_agent"]), eventDetailShortMax)
	}
	if v := e.Details["utf8"]; len(v) > eventDetailMax || !utf8.ValidString(v) {
		t.Fatalf("utf8 value cut inside a character (%d bytes)", len(v))
	}
}

func TestFlushWithEmptyQueue(t *testing.T) {
	s, rec, _ := startSender(t)
	if err := s.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	quiet(t, rec, 0)
}

// The client sends the queued events in one request, as a list.
func TestReportEventsBatchesRequests(t *testing.T) {
	var mu sync.Mutex
	var requests []int
	var values []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Events []EventRequest `json:"events"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		requests = append(requests, len(body.Events))
		for _, e := range body.Events {
			values = append(values, e.Details["k"])
		}
		mu.Unlock()
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := New(srv.URL, "tok")
	details := map[string]string{"k": "v"}
	for i := 0; i < 10; i++ {
		if err := c.ReportEvents([]EventRequest{{Type: "port_scan", Severity: "info", Details: details}}); err != nil {
			t.Fatal(err)
		}
	}
	details["k"] = "changed after reporting"
	if err := c.CloseEvents(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 1 || requests[0] != 10 {
		t.Fatalf("requests carried %v events, want one request with 10", requests)
	}
	for _, v := range values {
		if v != "v" {
			t.Fatalf("details sent as %q: the event must be copied when reported", v)
		}
	}
}

// While the dashboard refuses the agent, events wait for the refusal
// backoff (up to 30 minutes), not the 5-minute cap of a 429.
func TestRefusalBackoffIsHonored(t *testing.T) {
	s, rec, clock := startSender(t)
	rec.setFail(func([]EventRequest) error {
		if rec.tries == 1 {
			return &statusError{code: http.StatusForbidden, body: `{"error":"suspended"}`, retryAfter: 30 * time.Minute}
		}
		return nil
	})
	_ = s.add([]EventRequest{{Type: "update_completed", Severity: "info"}})
	eventually(t, "the first try", func() bool { return rec.attempts() == 1 })
	clock.armed(t)
	clock.Advance(30*time.Minute - time.Millisecond)
	quiet(t, rec, 0)
	if n := rec.attempts(); n != 1 {
		t.Fatalf("%d tries during the refusal backoff", n)
	}
	clock.Advance(time.Millisecond)
	eventually(t, "delivery", func() bool { return len(rec.got()) == 1 })
}

// A flush while requests are held gives up at once instead of retrying
// until its deadline; the events are kept.
func TestFlushGivesUpWhileHeld(t *testing.T) {
	s, rec, _ := startSender(t)
	rec.setFail(func([]EventRequest) error {
		return &statusError{code: http.StatusForbidden, held: true, retryAfter: 20 * time.Minute}
	})
	_ = s.add([]EventRequest{info("a")})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	if err := s.Flush(ctx); !IsHeld(err) {
		t.Fatalf("flush: %v, want the held error", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("flush took %s", d)
	}
	if s.depth() != 1 {
		t.Fatalf("depth %d, want the event kept", s.depth())
	}
}
