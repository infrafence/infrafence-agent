package geoip

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Fetcher downloads the country database into w, at most maxBytes, unless
// etag (the SHA-256 of the agent's copy, see api.ETagOf) is current:
// notModified, nothing written. retryAfter is a wait the server asked for.
type Fetcher func(ctx context.Context, etag string, w io.Writer, maxBytes int64) (notModified bool, retryAfter time.Duration, err error)

// tmpPattern names the temporary file of a download, next to the database.
const tmpPattern = ".geoip-country-*.tmp"

// The updater checks at most once per refreshEvery; after a failure it
// waits retryMin, doubling up to refreshEvery. A download may take up to
// downloadTimeout.
var (
	refreshEvery    = 24 * time.Hour
	retryMin        = time.Hour
	downloadTimeout = 5 * time.Minute
)

// Updater keeps the country database at Path current from the dashboard,
// only while a country is blocked (Want). Downloads run on their own
// goroutine (Run): a sync only signals it.
type Updater struct {
	lookup *Lookup
	path   string
	fetch  Fetcher
	// onSwap runs after a new database is in use (the country sets are
	// loaded again from it).
	onSwap func()
	now    func() time.Time

	wake chan struct{}

	mu        sync.Mutex
	want      bool
	lastCheck time.Time // the last answer from the dashboard (database or 304)
	nextTry   time.Time // after a failure, no attempt before
	failures  int
	state     string // logged on change only
}

// NewUpdater returns an updater for the database at path, loaded into
// lookup. A copy already at path counts as checked when it was written
// (or confirmed current) last.
func NewUpdater(lookup *Lookup, path string, fetch Fetcher, onSwap func()) *Updater {
	u := &Updater{lookup: lookup, path: path, fetch: fetch, onSwap: onSwap, now: time.Now, wake: make(chan struct{}, 1)}
	// Temporary files of a download the agent did not finish (killed).
	if old, err := filepath.Glob(filepath.Join(filepath.Dir(path), tmpPattern)); err == nil {
		for _, f := range old {
			_ = os.Remove(f)
		}
	}
	if st, err := os.Stat(path); err == nil && lookup.Path() == path {
		u.lastCheck = st.ModTime()
	}
	return u
}

// Want tells the updater whether a country is blocked (each sync calls it).
// Without one nothing is downloaded. It never blocks.
func (u *Updater) Want(on bool) {
	u.mu.Lock()
	u.want = on
	u.mu.Unlock()
	if on {
		select {
		case u.wake <- struct{}{}:
		default:
		}
	}
}

// Run checks for a new database whenever Want asks for one and an hour
// after each look, until ctx ends.
func (u *Updater) Run(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-u.wake:
		case <-t.C:
		}
		if u.due() {
			u.Check(ctx)
		}
	}
}

// due: a country is blocked, and the last check is a day old (or there is
// no database from the dashboard), and no failure asks to wait.
func (u *Updater) due() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	now := u.now()
	if !u.want || now.Before(u.nextTry) {
		return false
	}
	return u.lookup.Path() != u.path || u.lastCheck.IsZero() || now.Sub(u.lastCheck) >= refreshEvery
}

// Check asks the dashboard for the database once: a new one is verified,
// written to the path atomically and loaded; on any failure the database
// in use stays.
func (u *Updater) Check(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()
	swapped, retryAfter, err := u.check(ctx)
	u.mu.Lock()
	now := u.now()
	if err != nil {
		u.failures++
		wait := retryMin << min(u.failures-1, 5)
		wait = min(wait, refreshEvery)
		u.nextTry = now.Add(max(wait, retryAfter))
		u.mu.Unlock()
		u.setState("country database not updated: " + err.Error() + " (the database in use, if any, stays)")
		return
	}
	u.failures = 0
	u.nextTry = time.Time{}
	u.lastCheck = now
	u.mu.Unlock()
	if swapped {
		u.setState("country database updated")
		if u.onSwap != nil {
			u.onSwap()
		}
		return
	}
	u.setState("country database is current")
}

func (u *Updater) setState(s string) {
	u.mu.Lock()
	changed := s != u.state
	u.state = s
	u.mu.Unlock()
	if changed {
		log.Printf("[geoip] %s", s)
	}
}

func (u *Updater) check(ctx context.Context) (swapped bool, retryAfter time.Duration, err error) {
	// The tag of the copy in use; a file there that could not be loaded
	// is downloaded again.
	etag := ""
	if u.lookup.Path() == u.path {
		if sum, err := fileSHA256(u.path); err == nil {
			etag = `"` + sum + `"`
		}
	}

	dir := filepath.Dir(u.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, 0, err
	}
	tmp, err := os.CreateTemp(dir, tmpPattern)
	if err != nil {
		return false, 0, err
	}
	defer os.Remove(tmp.Name()) // a no-op after the rename
	defer tmp.Close()

	notModified, retryAfter, err := u.fetch(ctx, etag, tmp, MaxSize)
	if err != nil {
		return false, retryAfter, err
	}
	if notModified {
		if etag == "" {
			return false, 0, fmt.Errorf("the dashboard answered 304 to a request without a tag")
		}
		now := u.now()
		_ = os.Chtimes(u.path, now, now) // the next check is a day after this one
		return false, 0, nil
	}
	if err := tmp.Sync(); err != nil {
		return false, 0, err
	}
	// Read back through the open file, not by name.
	size, err := tmp.Seek(0, io.SeekEnd)
	if err != nil {
		return false, 0, err
	}
	if size > MaxSize {
		return false, 0, fmt.Errorf("downloaded file larger than %d MB", MaxSize>>20)
	}
	data := make([]byte, size)
	if _, err := tmp.ReadAt(data, 0); err != nil {
		return false, 0, err
	}
	if err := tmp.Close(); err != nil {
		return false, 0, err
	}
	r, err := Check(data)
	if err != nil {
		return false, 0, fmt.Errorf("downloaded file refused: %w", err)
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return false, 0, err
	}
	if err := os.Rename(tmp.Name(), u.path); err != nil {
		return false, 0, err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	u.lookup.Replace(r, u.path)
	return true, 0, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, MaxSize+1)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
