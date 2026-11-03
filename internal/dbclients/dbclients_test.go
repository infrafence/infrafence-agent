package dbclients

import (
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"
)

type clock struct{ t time.Time }

var base = time.Now().UTC().Truncate(24*time.Hour).Add(-5*24*time.Hour + 10*time.Hour)

func (c *clock) now() time.Time { return c.t }

func newTestLog(t *testing.T, path string) (*Log, *clock) {
	t.Helper()
	// Days in the past: New loads with the real clock.
	c := &clock{t: base}
	l := New(path)
	l.Now = c.now
	return l, c
}

func TestRegularNeedsThreeDays(t *testing.T) {
	l, c := newTestLog(t, "")
	// A backup job: one connection a night on three nights; a scanner once.
	for d := 0; d < 3; d++ {
		l.Observe(map[int][]string{3306: {"203.0.113.7"}})
		l.Observe(map[int][]string{3306: {"203.0.113.7"}})
		if d == 0 {
			l.Observe(map[int][]string{3306: {"198.51.100.66"}})
		}
		if d < 2 {
			if got := l.Regular(3306); len(got) != 0 {
				t.Fatalf("day %d: regular too early: %v", d, got)
			}
		}
		c.t = c.t.Add(24 * time.Hour)
	}
	c.t = c.t.Add(-24 * time.Hour)
	got := l.Regular(3306)
	if len(got) != 1 || got[0].IP != "203.0.113.7" || got[0].Days != 3 {
		t.Fatalf("got %+v", got)
	}
	if !got[0].First.Equal(base) || !got[0].Last.Equal(base.Add(48*time.Hour)) {
		t.Fatalf("first/last: %v %v", got[0].First, got[0].Last)
	}
	if len(l.Regular(5432)) != 0 {
		t.Fatal("other port")
	}
	// A week later the oldest days are out of the window.
	c.t = c.t.Add(5 * 24 * time.Hour)
	if got := l.Regular(3306); len(got) != 0 {
		t.Fatalf("out of the window: %+v", got)
	}
}

func TestObserveSkipsPrivateAndBounds(t *testing.T) {
	l, _ := newTestLog(t, "")
	l.Observe(map[int][]string{3306: {"10.0.0.5", "127.0.0.1", "100.64.1.1", "fe80::1", "not-an-ip", "::ffff:203.0.113.9"}})
	p := l.Pending(10)
	if len(p) != 1 || p[0].IP != "203.0.113.9" {
		t.Fatalf("got %+v", p)
	}
	var many []string
	for i := 0; i < maxPerPortDay+50; i++ {
		many = append(many, "198.51."+strconv.Itoa(i/250)+"."+strconv.Itoa(i%250+1))
	}
	l.Observe(map[int][]string{6379: many})
	if n := l.countDayLocked(6379, l.day(l.Now())); n != maxPerPortDay {
		t.Fatalf("kept %d addresses, want %d", n, maxPerPortDay)
	}
}

func TestPendingAndMarkSent(t *testing.T) {
	l, c := newTestLog(t, "")
	l.Observe(map[int][]string{5432: {"203.0.113.7"}, 3306: {"203.0.113.8"}})
	p := l.Pending(10)
	if len(p) != 2 || p[0].Port != 3306 || p[0].Day != base.Format("2006-01-02") || p[0].Samples != 1 || p[0].FirstSeen != base.Format(time.RFC3339) {
		t.Fatalf("got %+v", p)
	}
	l.MarkSent(p)
	if p := l.Pending(10); len(p) != 0 {
		t.Fatalf("sent again: %+v", p)
	}
	c.t = c.t.Add(time.Minute)
	l.Observe(map[int][]string{5432: {"203.0.113.7"}})
	p = l.Pending(1)
	if len(p) != 1 || p[0].Port != 5432 || p[0].Samples != 2 || p[0].LastSeen != base.Add(time.Minute).Format(time.RFC3339) {
		t.Fatalf("got %+v", p)
	}
}

func TestSaveAndLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db-clients.json")
	l, c := newTestLog(t, path)
	for d := 0; d < 3; d++ {
		l.Observe(map[int][]string{27017: {"203.0.113.7"}})
		c.t = c.t.Add(24 * time.Hour)
	}
	l.Save()
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("file: %v %v", fi, err)
	}
	l2 := New(path)
	l2.Now = func() time.Time { return c.t.Add(-time.Hour) }
	if got := l2.Regular(27017); len(got) != 1 || got[0].Days != 3 {
		t.Fatalf("after load: %+v", got)
	}
	// Loaded entries are sent once more (the dashboard upserts them).
	if p := l2.Pending(10); len(p) != 3 {
		t.Fatalf("pending after load: %+v", p)
	}
	// A corrupt file is ignored.
	_ = os.WriteFile(path, []byte("{not json"), 0o600)
	if got := New(path).Regular(27017); len(got) != 0 {
		t.Fatalf("corrupt: %+v", got)
	}
}

func TestShortDayForTests(t *testing.T) {
	l, c := newTestLog(t, "")
	l.DayLength = 30 * time.Second
	for i := 0; i < 3; i++ {
		l.Observe(map[int][]string{6379: {"192.0.2.2"}})
		c.t = c.t.Add(30 * time.Second)
	}
	c.t = c.t.Add(-time.Second)
	if got := l.Regular(6379); !reflect.DeepEqual(len(got), 1) {
		t.Fatalf("got %+v", got)
	}
}
