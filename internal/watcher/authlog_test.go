package watcher

import (
	"testing"
	"time"
)

func runBruteForce(t *testing.T, monitor bool) (bans, events []string, details map[string]string) {
	t.Helper()
	banCh := make(chan string, 4)
	evCh := make(chan map[string]string, 4)
	w := New(func(ip, reason string, count int) { banCh <- ip })
	w.SetOnEvent(func(ip, eventType, severity string, d map[string]string) {
		if eventType == "brute_force" {
			evCh <- d
		}
	})
	if monitor {
		w.SetMonitorMode(true)
	}
	for i := 0; i < 5; i++ {
		w.recordAttempt("203.0.113.7", "invalid_user")
	}

	deadline := time.After(time.Second)
	for {
		select {
		case ip := <-banCh:
			bans = append(bans, ip)
		case d := <-evCh:
			events = append(events, "brute_force")
			details = d
		case <-deadline:
			return
		}
	}
}

func TestBruteForceBanAlsoEmitsEvent(t *testing.T) {
	bans, events, d := runBruteForce(t, false)
	if len(bans) != 1 || len(events) != 1 {
		t.Fatalf("enforcement mode: got %d bans, %d events; want 1 and 1", len(bans), len(events))
	}
	if d["action"] != "banned" || d["attempts"] != "5" || d["reason"] != "invalid_user" {
		t.Errorf("event details: %#v", d)
	}
}

func TestBruteForceMonitorModeEventOnly(t *testing.T) {
	bans, events, _ := runBruteForce(t, true)
	if len(bans) != 0 || len(events) != 1 {
		t.Fatalf("monitor mode: got %d bans, %d events; want 0 and 1", len(bans), len(events))
	}
}
