package session

import (
	"fmt"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

// TestSessionTracker_ConcurrentAccess exercises the real production race
// pattern: the tail goroutine calls processLine() while every other detector
// in the agent (integrity, malware, port scan, egress, DNS, WAF...) can call
// NotifySigmaEvent() concurrently via the API client's event observer, and a
// panel sync can call UpdateConfig() at the same time. Run with -race.
func TestSessionTracker_ConcurrentAccess(t *testing.T) {
	tracker := New(func(eventType, severity string, details map[string]string) {})
	tracker.UpdateConfig(Config{Enabled: true, SigmaEnabled: true, SigmaMinLevel: "info"})

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Simulates the tail goroutine processing auth.log lines: opens and
	// closes sessions under a distinct PID each time.
	wg.Add(1)
	go func() {
		defer wg.Done()
		pid := 0
		for {
			select {
			case <-stop:
				return
			default:
			}
			pid++
			p := fmt.Sprintf("%d", pid)
			tracker.processLine(fmt.Sprintf("Aug 18 12:00:00 server sshd[%s]: Accepted password for u from 1.2.3.4 port 1111 ssh2", p))
			tracker.processLine(fmt.Sprintf("Aug 18 12:00:00 server sshd[%s]: pam_unix(sshd:session): session closed for user u", p))
		}
	}()

	// Simulates several independent detectors reporting events concurrently
	// via the observer path (NotifySigmaEvent) while sessions open and close.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				tracker.NotifySigmaEvent("integrity_change", "critical")
			}
		}()
	}

	// Simulates the panel sync updating config concurrently (real pattern:
	// syncAndApply calls UpdateConfig on every sync cycle).
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			tracker.UpdateConfig(Config{Enabled: true, SigmaEnabled: true, SigmaMinLevel: "warning"})
		}
	}()

	time.Sleep(150 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// TestSessionTracker_StopReleasesGoroutinesPromptly verifies that Stop()
// actually terminates the goroutines Run() started, within a bounded time —
// not just "eventually". Points AUTH_LOG_PATH at a nonexistent file so
// tail() takes the "file missing" branch, which is what happens on any host
// without /var/log/auth.log or /var/log/secure (e.g. a minimal container) or
// during a race with log rotation — the scenario that actually matters for a
// leak, since the happy-path tail loop exits immediately on ctx.Done().
func TestSessionTracker_StopReleasesGoroutinesPromptly(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	t.Setenv("AUTH_LOG_PATH", missing)

	tracker := New(func(eventType, severity string, details map[string]string) {})
	tracker.UpdateConfig(Config{Enabled: true})

	before := runtime.NumGoroutine()

	done := make(chan struct{})
	go func() {
		tracker.Run()
		close(done)
	}()

	// Let Run() spawn its tail + cleanup goroutines and let tail() hit its
	// first (immediate, since the file is missing) retry-sleep.
	time.Sleep(50 * time.Millisecond)

	tracker.Stop()

	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatalf("Run() did not return within 1s of Stop() — the tail goroutine is likely blocked in a retry sleep instead of observing ctx.Done()")
	}

	deadline := time.Now().Add(1 * time.Second)
	for {
		if runtime.NumGoroutine() <= before {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutine count did not settle within 1s of Stop(): before=%d after=%d", before, runtime.NumGoroutine())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestSessionTracker_RepeatedRunStopDoesNotAccumulateGoroutines guards
// against a slow per-cycle leak that a single Run/Stop pair might not show:
// runs several short-lived tracker lifecycles back to back and checks the
// goroutine count settles back to baseline, not upward with each cycle.
func TestSessionTracker_RepeatedRunStopDoesNotAccumulateGoroutines(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	t.Setenv("AUTH_LOG_PATH", missing)

	before := runtime.NumGoroutine()

	for i := 0; i < 5; i++ {
		tracker := New(func(eventType, severity string, details map[string]string) {})
		tracker.UpdateConfig(Config{Enabled: true})

		done := make(chan struct{})
		go func() {
			tracker.Run()
			close(done)
		}()

		time.Sleep(20 * time.Millisecond)
		tracker.Stop()

		select {
		case <-done:
		case <-time.After(6 * time.Second):
			t.Fatalf("iteration %d: Run() never returned after Stop()", i)
		}
	}

	deadline := time.Now().Add(1 * time.Second)
	for {
		if runtime.NumGoroutine() <= before {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutine count grew across repeated Run/Stop cycles: before=%d after=%d", before, runtime.NumGoroutine())
		}
		time.Sleep(10 * time.Millisecond)
	}
}
