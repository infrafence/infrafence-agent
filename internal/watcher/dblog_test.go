package watcher

import (
	"fmt"
	"testing"
	"time"
)

type dbBan struct{ ip, reason string }

type dbEvent struct {
	ip, typ, severity string
	d                 map[string]string
}

// newTestDBWatcher returns a watcher with the default threshold (5 in
// 5 minutes) and channels that collect its bans and events.
func newTestDBWatcher() (*DBWatcher, chan dbBan, chan dbEvent) {
	bans := make(chan dbBan, 64)
	evs := make(chan dbEvent, 64)
	w := &DBWatcher{
		threshold: 5,
		window:    5 * time.Minute,
		onBan:     func(ip, reason string, count int) { bans <- dbBan{ip, reason} },
		attempts:  make(map[string][]time.Time),
		banned:    make(map[string]bool),
		whitelist: make(map[string]bool),
	}
	w.SetOnEvent(func(ip, typ, severity string, d map[string]string) { evs <- dbEvent{ip, typ, severity, d} })
	return w, bans, evs
}

// collectDB gathers what the watcher's goroutines sent within a short wait.
func collectDB(bans chan dbBan, evs chan dbEvent) ([]dbBan, []dbEvent) {
	var b []dbBan
	var e []dbEvent
	deadline := time.After(300 * time.Millisecond)
	for {
		select {
		case x := <-bans:
			b = append(b, x)
		case x := <-evs:
			e = append(e, x)
		case <-deadline:
			return b, e
		}
	}
}

func accessDenied(ip string) string {
	return fmt.Sprintf("2026-11-07T10:00:00.123456Z 42 [Warning] Access denied for user 'app'@'%s' (using password: YES)", ip)
}

const (
	abortedLine = "2026-11-07T10:00:00.123456Z 43 [Warning] Aborted connection 43 to db: 'shop' user: 'app' host: '%s' (Got an error reading communication packets)"
	pgDropLine  = `2026-11-07 10:00:00 UTC [812] app@shop LOG:  could not receive data from client: Connection reset by peer connection host=%s`
)

// Dropped connections (MySQL "Aborted connection", PostgreSQL "could not
// receive data") never lead to a ban and are reported once a window per
// address, with the lines since the last report.
func TestDBSuspiciousNeverBans(t *testing.T) {
	w, bans, evs := newTestDBWatcher()
	for i := 0; i < 20; i++ {
		w.processLine(fmt.Sprintf(abortedLine, "203.0.113.20"))
		w.processLine(fmt.Sprintf(pgDropLine, "203.0.113.21"))
	}
	b, e := collectDB(bans, evs)
	if len(b) != 0 {
		t.Fatalf("banned: %v", b)
	}
	if len(e) != 2 {
		t.Fatalf("events: %+v", e)
	}
	for _, x := range e {
		if x.typ != "db_suspicious" || x.severity != "warning" || x.d["lines"] != "1" {
			t.Fatalf("event: %+v", x)
		}
	}
	if len(w.attempts) != 0 {
		t.Errorf("counted: %v", w.attempts)
	}

	// The next window's event carries the 19 lines not reported, plus its own.
	w.mu.Lock()
	w.dropped["203.0.113.20"].since = time.Now().Add(-w.window - time.Second)
	w.mu.Unlock()
	w.processLine(fmt.Sprintf(abortedLine, "203.0.113.20"))
	if _, e := collectDB(bans, evs); len(e) != 1 || e[0].d["lines"] != "20" {
		t.Errorf("next window: %+v", e)
	}

	// Counts are forgotten two windows later, and the map is bounded.
	w.cleanup(time.Now().Add(2*w.window + time.Second))
	if len(w.dropped) != 0 {
		t.Errorf("kept: %v", w.dropped)
	}
	w.mu.Lock()
	w.dropped = make(map[string]*dbDropped)
	for i := 0; i <= dbMaxEntries; i++ {
		w.dropped[fmt.Sprint(i)] = &dbDropped{since: time.Now()}
	}
	w.mu.Unlock()
	w.cleanup(time.Now())
	if len(w.dropped) != 0 {
		t.Errorf("bound: %d", len(w.dropped))
	}
}

// Failed logins of an unknown address are banned at the threshold; those
// of a regular or declared client are reported as not banned.
func TestDBKnownClientNotBanned(t *testing.T) {
	w, bans, evs := newTestDBWatcher()
	var asked []string
	w.SetKnownClient(func(ip string) string {
		asked = append(asked, ip)
		if ip == "203.0.113.7" {
			return "regular_client"
		}
		return ""
	})
	for i := 0; i < 5; i++ {
		w.processLine(accessDenied("203.0.113.7"))
		w.processLine(accessDenied("203.0.113.8"))
	}
	b, e := collectDB(bans, evs)
	if len(b) != 1 || b[0] != (dbBan{"203.0.113.8", "db_brute_force"}) {
		t.Fatalf("bans: %v", b)
	}
	var guarded []dbEvent
	for _, x := range e {
		if x.d["action"] == "not_banned" {
			guarded = append(guarded, x)
		}
	}
	if len(guarded) != 1 {
		t.Fatalf("not_banned events: %+v", e)
	}
	g := guarded[0]
	if g.ip != "203.0.113.7" || g.typ != "db_brute_force" || g.severity != "critical" ||
		g.d["not_banned"] != "regular_client" || g.d["attempts"] != "5" || g.d["reason"] != "db_brute_force" {
		t.Errorf("not_banned event: %+v", g)
	}
	// Asked only at the threshold, once per address.
	if len(asked) != 2 {
		t.Errorf("guard asked for %v", asked)
	}
	// The rest of the window is quiet for the known client.
	w.processLine(accessDenied("203.0.113.7"))
	if b, e := collectDB(bans, evs); len(b) != 0 || len(e) != 0 {
		t.Errorf("after the threshold: %v %+v", b, e)
	}
}

// A known client is not banned for its country either; an unknown address
// is, as before, also on a dropped connection.
func TestDBKnownClientNotGeoblocked(t *testing.T) {
	w, bans, evs := newTestDBWatcher()
	w.SetCheckIP(func(ip string) string { return "geoblock_xx" })
	w.SetKnownClient(func(ip string) string {
		if ip == "198.51.100.4" {
			return "declared_mysql_host"
		}
		return ""
	})
	w.processLine(accessDenied("198.51.100.4"))
	w.processLine(fmt.Sprintf(abortedLine, "203.0.113.30"))
	b, e := collectDB(bans, evs)
	if len(b) != 1 || b[0] != (dbBan{"203.0.113.30", "geoblock_xx"}) {
		t.Fatalf("bans: %v", b)
	}
	// The failed login, and once the country ban it was spared.
	geo := 0
	for _, x := range e {
		if x.ip != "198.51.100.4" || x.typ != "db_brute_force" {
			t.Fatalf("event: %+v", x)
		}
		if x.d["reason"] == "geoblock_xx" && x.d["not_banned"] == "declared_mysql_host" {
			geo++
		}
	}
	if len(e) != 2 || geo != 1 {
		t.Fatalf("events: %+v", e)
	}
	for i := 0; i < 4; i++ {
		w.processLine(accessDenied("198.51.100.4"))
	}
	w.processLine(fmt.Sprintf(abortedLine, "198.51.100.4"))
	b, e = collectDB(bans, evs)
	if len(b) != 0 {
		t.Fatalf("known client banned: %v", b)
	}
	guarded := 0
	for _, x := range e {
		if x.d["reason"] == "geoblock_xx" {
			t.Errorf("country exemption reported again: %+v", x)
		}
		if x.d["attempts"] == "5" && x.d["not_banned"] == "declared_mysql_host" {
			guarded++
		}
	}
	// 4 failed logins and the threshold's not_banned; the banned state then
	// skips the dropped connection.
	if len(e) != 5 || guarded != 1 {
		t.Errorf("events: %+v", e)
	}
}

// The guard is asked once a window per address, also for a known client
// that its country would ban on every line.
func TestDBKnownClientCached(t *testing.T) {
	w, bans, evs := newTestDBWatcher()
	w.SetCheckIP(func(ip string) string { return "geoblock_xx" })
	asked := 0
	w.SetKnownClient(func(ip string) string {
		asked++
		return "regular_client"
	})
	for i := 0; i < 30; i++ {
		w.processLine(fmt.Sprintf(abortedLine, "203.0.113.70"))
	}
	b, e := collectDB(bans, evs)
	if asked != 1 || len(b) != 0 {
		t.Fatalf("asked %d times, bans %v", asked, b)
	}
	// The country exemption and one dropped-connection event.
	if len(e) != 2 {
		t.Errorf("events: %+v", e)
	}
	// A window later it is asked again.
	w.mu.Lock()
	w.knownSeen["203.0.113.70"].since = time.Now().Add(-w.window - time.Second)
	w.mu.Unlock()
	w.processLine(fmt.Sprintf(abortedLine, "203.0.113.70"))
	collectDB(bans, evs)
	if asked != 2 {
		t.Errorf("asked %d times", asked)
	}
}

// Once the window has passed, the ban state and the guard's answer are
// forgotten: a client no longer known is banned at the next threshold.
func TestDBBanStateExpiry(t *testing.T) {
	w, bans, evs := newTestDBWatcher()
	known := "regular_client"
	asked := 0
	w.SetKnownClient(func(ip string) string {
		asked++
		return known
	})
	for i := 0; i < 6; i++ {
		w.processLine(accessDenied("203.0.113.80"))
	}
	if b, _ := collectDB(bans, evs); len(b) != 0 || asked != 1 {
		t.Fatalf("bans %v, asked %d", b, asked)
	}
	w.cleanup(time.Now().Add(w.window + time.Second))
	if w.banned["203.0.113.80"] || w.knownSeen["203.0.113.80"] != nil || w.attempts["203.0.113.80"] != nil {
		t.Fatal("state kept past the window")
	}
	known = ""
	for i := 0; i < 5; i++ {
		w.processLine(accessDenied("203.0.113.80"))
	}
	if b, _ := collectDB(bans, evs); len(b) != 1 || asked != 2 {
		t.Errorf("bans %v, asked %d", b, asked)
	}
}

// Monitor mode bans nothing and does not ask the guard.
func TestDBKnownClientMonitorMode(t *testing.T) {
	w, bans, evs := newTestDBWatcher()
	w.SetMonitorMode(true)
	w.SetKnownClient(func(ip string) string {
		t.Errorf("guard asked for %s", ip)
		return ""
	})
	for i := 0; i < 5; i++ {
		w.processLine(accessDenied("203.0.113.8"))
	}
	b, e := collectDB(bans, evs)
	if len(b) != 0 || len(e) != 5 {
		t.Errorf("bans %v, events %d", b, len(e))
	}
}

// PostgreSQL failed logins of a regular client are not banned either; an
// unknown address is.
func TestDBKnownClientPostgreSQL(t *testing.T) {
	w, bans, evs := newTestDBWatcher()
	w.SetKnownClient(func(ip string) string {
		if ip == "203.0.113.50" {
			return "regular_client"
		}
		return ""
	})
	for i := 0; i < 5; i++ {
		for _, ip := range []string{"203.0.113.50", "203.0.113.60"} {
			w.processLine(fmt.Sprintf(`2026-11-07 10:00:00 UTC [900] app@shop FATAL:  password authentication failed for user "app" connection authorized: host=%s`, ip))
		}
	}
	b, e := collectDB(bans, evs)
	if len(b) != 1 || b[0] != (dbBan{"203.0.113.60", "db_brute_force"}) {
		t.Fatalf("bans: %v", b)
	}
	guarded := 0
	for _, x := range e {
		if x.ip == "203.0.113.50" && x.d["not_banned"] == "regular_client" {
			guarded++
		}
	}
	if guarded != 1 {
		t.Errorf("events: %+v", e)
	}
}
