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

// Dropped connections (MySQL "Aborted connection", PostgreSQL "could not
// receive data") are reported but never lead to a ban.
func TestDBSuspiciousNeverBans(t *testing.T) {
	w, bans, evs := newTestDBWatcher()
	for i := 0; i < 20; i++ {
		w.processLine("2026-11-07T10:00:00.123456Z 43 [Warning] Aborted connection 43 to db: 'shop' user: 'app' host: '203.0.113.20' (Got an error reading communication packets)")
		w.processLine(`2026-11-07 10:00:00 UTC [812] app@shop LOG:  could not receive data from client: Connection reset by peer connection host=203.0.113.21`)
	}
	b, e := collectDB(bans, evs)
	if len(b) != 0 {
		t.Fatalf("banned: %v", b)
	}
	if len(e) != 40 {
		t.Fatalf("events: %d", len(e))
	}
	for _, x := range e {
		if x.typ != "db_suspicious" || x.severity != "warning" {
			t.Fatalf("event: %+v", x)
		}
	}
	if len(w.attempts) != 0 {
		t.Errorf("counted: %v", w.attempts)
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
	w.processLine("2026-11-07T10:00:00.123456Z 43 [Warning] Aborted connection 43 to db: 'shop' user: 'app' host: '203.0.113.30' (Got an error reading communication packets)")
	b, e := collectDB(bans, evs)
	if len(b) != 1 || b[0] != (dbBan{"203.0.113.30", "geoblock_xx"}) {
		t.Fatalf("bans: %v", b)
	}
	if len(e) != 1 || e[0].ip != "198.51.100.4" || e[0].typ != "db_brute_force" {
		t.Fatalf("events: %+v", e)
	}
	for i := 0; i < 4; i++ {
		w.processLine(accessDenied("198.51.100.4"))
	}
	b, e = collectDB(bans, evs)
	if len(b) != 0 {
		t.Fatalf("known client banned: %v", b)
	}
	guarded := 0
	for _, x := range e {
		if x.d["action"] == "not_banned" && x.d["not_banned"] == "declared_mysql_host" {
			guarded++
		}
	}
	if len(e) != 5 || guarded != 1 {
		t.Errorf("events: %+v", e)
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
