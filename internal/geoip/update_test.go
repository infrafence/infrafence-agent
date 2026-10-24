package geoip

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/infrafence/infrafence-agent/internal/geoip/mmdbtest"
)

// fakeDashboard answers like GET /api/v1/agent/geoip.
type fakeDashboard struct {
	mu         sync.Mutex
	db         []byte // nil: the dashboard has no database
	calls      int
	etags      []string
	err        error
	retryAfter time.Duration
	block      chan struct{} // when set, a fetch waits on it
}

func (f *fakeDashboard) fetch(ctx context.Context, etag string, w io.Writer, maxBytes int64) (bool, time.Duration, error) {
	f.mu.Lock()
	f.calls++
	f.etags = append(f.etags, etag)
	db, err, ra, block := f.db, f.err, f.retryAfter, f.block
	f.mu.Unlock()
	if block != nil {
		<-block
	}
	if err != nil {
		return false, ra, err
	}
	if db == nil {
		return false, 0, errors.New("server returned 503")
	}
	sum := sha256.Sum256(db)
	if etag == `"`+hex.EncodeToString(sum[:])+`"` {
		return true, 0, nil
	}
	_, err = w.Write(db)
	return false, 0, err
}

func (f *fakeDashboard) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func dbWith(t *testing.T, cc string) []byte {
	t.Helper()
	data, err := mmdbtest.Build("DBIP-Country-Lite", append([]mmdbtest.Network{{CIDR: "198.51.100.0/24", Country: cc}}, mmdbtest.Anchors...), time.Unix(1760000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newTestUpdater(t *testing.T, f *fakeDashboard) (*Updater, *Lookup, string, *int, *clock) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "geoip-country.mmdb")
	l := New(path) // nothing there yet
	swaps := new(int)
	u := NewUpdater(l, path, f.fetch, func() { *swaps++ })
	c := &clock{t: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)}
	u.now = c.now
	return u, l, path, swaps, c
}

func TestUpdaterDownloadsVerifiesAndSwaps(t *testing.T) {
	f := &fakeDashboard{db: dbWith(t, "XX")}
	u, l, path, swaps, _ := newTestUpdater(t, f)
	u.Want(true)
	if !u.due() {
		t.Fatal("no database yet: a download is due")
	}
	u.Check(context.Background())
	if *swaps != 1 || l.Path() != path || l.Country("198.51.100.7") != "XX" {
		t.Fatalf("swaps %d, path %q, country %q", *swaps, l.Path(), l.Country("198.51.100.7"))
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o644 {
		t.Fatalf("file: %v %v", st, err)
	}
	if f.etags[0] != "" {
		t.Errorf("first request sent a tag: %q", f.etags[0])
	}
	assertOnlyFile(t, path)

	// A new edition replaces it.
	f.db = dbWith(t, "YY")
	u.Check(context.Background())
	if *swaps != 2 || l.Country("198.51.100.7") != "YY" {
		t.Fatalf("second edition: swaps %d, country %q", *swaps, l.Country("198.51.100.7"))
	}
	// And a restart loads it from the file.
	if l2 := New(path); l2.Country("198.51.100.7") != "YY" {
		t.Fatal("the saved database does not load")
	}
}

func TestUpdaterKeepsTheOldDatabaseOnABadFile(t *testing.T) {
	f := &fakeDashboard{db: dbWith(t, "XX")}
	u, l, path, swaps, c := newTestUpdater(t, f)
	u.Want(true)
	u.Check(context.Background())
	before, _ := os.ReadFile(path)

	for name, bad := range map[string][]byte{
		"junk":      []byte("<html>proxy error</html>"),
		"truncated": dbWith(t, "YY")[:500],
		"no anchors": func() []byte {
			d, _ := mmdbtest.Build("DBIP-Country-Lite", []mmdbtest.Network{{CIDR: "198.51.100.0/24", Country: "YY"}}, time.Now())
			return d
		}(),
	} {
		f.db = bad
		u.nextTry = time.Time{}
		u.Check(context.Background())
		after, _ := os.ReadFile(path)
		if !bytes.Equal(before, after) || l.Country("198.51.100.7") != "XX" || *swaps != 1 {
			t.Fatalf("%s: the database in use changed", name)
		}
		assertOnlyFile(t, path)
		if !u.nextTry.After(c.t) {
			t.Fatalf("%s: no wait before the next try", name)
		}
	}
}

func TestUpdaterNotModified(t *testing.T) {
	db := dbWith(t, "XX")
	f := &fakeDashboard{db: db}
	u, _, path, swaps, c := newTestUpdater(t, f)
	u.Want(true)
	u.Check(context.Background())

	c.t = c.t.Add(25 * time.Hour)
	if !u.due() {
		t.Fatal("a day later a check is due")
	}
	u.Check(context.Background())
	sum := sha256.Sum256(db)
	if want := `"` + hex.EncodeToString(sum[:]) + `"`; f.etags[1] != want {
		t.Fatalf("tag %q, want %q", f.etags[1], want)
	}
	if *swaps != 1 {
		t.Fatal("304 swapped the database")
	}
	if st, _ := os.Stat(path); !st.ModTime().Equal(c.t) {
		t.Fatalf("304 did not mark the file checked: %v", st.ModTime())
	}
	if u.due() {
		t.Fatal("checked just now: not due")
	}
	// After a restart the file's time counts as the last check.
	u2 := NewUpdater(New(path), path, f.fetch, nil)
	u2.now = c.now
	u2.Want(true)
	if u2.due() {
		t.Fatal("restart right after a check: not due")
	}
}

func TestUpdaterNeverDownloadsWithoutBlockedCountries(t *testing.T) {
	f := &fakeDashboard{db: dbWith(t, "XX")}
	u, _, _, _, _ := newTestUpdater(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { u.Run(ctx); close(done) }()
	for range 100 {
		u.Want(false) // every sync without a blocked country
	}
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done
	if n := f.count(); n != 0 {
		t.Fatalf("%d downloads without a blocked country", n)
	}
}

func TestUpdaterRequestRate(t *testing.T) {
	f := &fakeDashboard{db: dbWith(t, "XX")}
	u, _, _, _, c := newTestUpdater(t, f)
	runCtx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { u.Run(runCtx); close(done) }()
	start := c.t
	checkedAt := func(t time.Time) bool {
		u.mu.Lock()
		defer u.mu.Unlock()
		return u.lastCheck.Equal(t)
	}

	// Syncs every 5 minutes for just under a day (the last at 23:55): one
	// download.
	u.Want(true)
	waitFor(t, func() bool { return checkedAt(start) })
	for i := 1; i < 288; i++ {
		u.mu.Lock()
		c.t = start.Add(time.Duration(i) * 5 * time.Minute)
		u.mu.Unlock()
		u.Want(true)
	}
	time.Sleep(20 * time.Millisecond)
	if n := f.count(); n != 1 {
		t.Fatalf("%d requests in under a day, want 1", n)
	}

	// 24 hours after the last check (not before) the next one is due.
	u.mu.Lock()
	c.t = start.Add(refreshEvery - time.Nanosecond)
	u.mu.Unlock()
	if u.due() {
		t.Fatal("due before 24 hours")
	}
	u.mu.Lock()
	c.t = start.Add(refreshEvery)
	u.mu.Unlock()
	u.Want(true)
	waitFor(t, func() bool { return checkedAt(start.Add(refreshEvery)) })
	if n := f.count(); n != 2 {
		t.Fatalf("%d requests a day after the first, want 2", n)
	}
	stop()
	<-done // no check of Run's in flight below
	ctx := context.Background()

	// Failures back off: 1 h, 2 h, 4 h... never more than a day; a
	// Retry-After longer than that is honoured.
	f.mu.Lock()
	f.err = errors.New("server returned 503")
	f.mu.Unlock()
	u.mu.Lock()
	u.lastCheck = time.Time{}
	u.mu.Unlock()
	for _, want := range []time.Duration{time.Hour, 2 * time.Hour, 4 * time.Hour} {
		u.Check(ctx)
		u.mu.Lock()
		got := u.nextTry.Sub(c.t)
		u.mu.Unlock()
		if got != want {
			t.Fatalf("backoff %s, want %s", got, want)
		}
	}
	for range 10 {
		u.Check(ctx)
	}
	if got := u.nextTry.Sub(c.t); got != refreshEvery {
		t.Fatalf("backoff %s, want at most a day", got)
	}
	f.mu.Lock()
	f.retryAfter = 30 * time.Hour
	f.mu.Unlock()
	u.Check(ctx)
	if got := u.nextTry.Sub(c.t); got != 30*time.Hour {
		t.Fatalf("Retry-After: wait %s", got)
	}
	if u.due() {
		t.Fatal("due while waiting after a failure")
	}
}

// A sync never waits for a download.
func TestWantNeverBlocks(t *testing.T) {
	f := &fakeDashboard{db: dbWith(t, "XX"), block: make(chan struct{})}
	u, _, _, _, _ := newTestUpdater(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go u.Run(ctx)
	u.Want(true)
	waitFor(t, func() bool { return f.count() == 1 }) // the download hangs
	done := make(chan struct{})
	go func() {
		for range 50 {
			u.Want(true)
			u.Want(false)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Want blocked behind a download")
	}
	close(f.block)
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("timed out")
}

// assertOnlyFile: no temporary file is left next to the database.
func assertOnlyFile(t *testing.T, path string) {
	t.Helper()
	entries, _ := os.ReadDir(filepath.Dir(path))
	for _, e := range entries {
		if e.Name() != filepath.Base(path) {
			t.Fatalf("leftover file %s", e.Name())
		}
	}
}
