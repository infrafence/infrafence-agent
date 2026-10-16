package backoff

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time      { return c.t }
func (c *fakeClock) add(d time.Duration) { c.t = c.t.Add(d) }
func newGate(r float64) (*Gate, *fakeClock, *[]string) {
	clk := &fakeClock{t: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	var logs []string
	g := NewWith(clk.now, func() float64 { return r }, func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) })
	return g, clk, &logs
}

func TestDelayBounds(t *testing.T) {
	for n := 1; n <= 12; n++ {
		for _, r := range []float64{0, 0.5, 0.999} {
			d := Delay(n, r)
			if d < Min || d > Max {
				t.Errorf("Delay(%d, %v) = %s, outside [%s, %s]", n, r, d, Min, Max)
			}
		}
	}
	if Delay(1, 0) != Min {
		t.Errorf("first delay without jitter = %s, want %s", Delay(1, 0), Min)
	}
	if got := Delay(2, 0); got != 2*Min {
		t.Errorf("second delay = %s, want doubled", got)
	}
	if Delay(1, 0.5) == Delay(1, 0) || Delay(20, 0.5) == Delay(20, 0) {
		t.Error("no jitter")
	}
	// Grows monotonically (same jitter) until the cap.
	prev := time.Duration(0)
	for n := 1; n <= 5; n++ {
		if d := Delay(n, 0); d <= prev {
			t.Errorf("Delay(%d) = %s, not above %s", n, d, prev)
		} else {
			prev = d
		}
	}
}

func TestGateBackoffAndReset(t *testing.T) {
	g, clk, logs := newGate(0)
	if g.Wait() != 0 {
		t.Fatal("a new gate holds requests")
	}
	if g.Refused(500, nil) != 0 || g.Wait() != 0 {
		t.Fatal("a server error is not a refusal")
	}
	w1 := g.Refused(401, []byte(`{"message":"Unauthenticated."}`))
	if w1 != Min || g.Wait() != Min {
		t.Fatalf("first refusal: wait %s / %s, want %s", w1, g.Wait(), Min)
	}
	clk.add(Min)
	if g.Wait() != 0 {
		t.Fatal("still held after the wait")
	}
	if w2 := g.Refused(401, nil); w2 != 2*Min {
		t.Fatalf("second refusal: %s, want %s", w2, 2*Min)
	}
	for i := 0; i < 10; i++ {
		clk.add(g.Wait())
		g.Refused(401, nil)
	}
	if w := g.Wait(); w > Max || w < Max-Max/10 {
		t.Fatalf("after many refusals: %s, want close to %s", w, Max)
	}
	if n := len(*logs); n != 1 || !strings.Contains((*logs)[0], "401") {
		t.Fatalf("refusals logged %d times (%v), want once", n, *logs)
	}
	if !g.OK() || g.Wait() != 0 {
		t.Fatal("success did not reset the backoff")
	}
	if g.OK() {
		t.Fatal("OK reported a refusal twice")
	}
	if w := g.Refused(403, []byte("<html>Forbidden</html>")); w != Min {
		t.Fatalf("after reset, first refusal waits %s, want %s", w, Min)
	}
}

func TestGateSuspended(t *testing.T) {
	g, clk, logs := newGate(0)
	body := []byte(`{"error":"suspended","message":"Organization suspended"}`)
	for i := 0; i < 3; i++ {
		if w := g.Refused(403, body); w != Suspended {
			t.Fatalf("suspended wait %s, want %s", w, Suspended)
		}
		clk.add(Suspended)
	}
	if code, susp := g.State(); code != 403 || !susp {
		t.Fatalf("state = %d %v", code, susp)
	}
	if len(*logs) != 1 || !strings.Contains((*logs)[0], "SUSPENDED") {
		t.Fatalf("logs = %v, want one SUSPENDED line", *logs)
	}
	// Another 403 body is a change: logged, and the normal backoff applies.
	g.Refused(403, []byte(`{"error":"agent_disabled"}`))
	if _, susp := g.State(); susp || len(*logs) != 2 {
		t.Fatalf("suspended=%v logs=%v", susp, *logs)
	}
}

func TestIsSuspended(t *testing.T) {
	for _, tc := range []struct {
		code int
		body string
		want bool
	}{
		{403, `{"error":"suspended"}`, true},
		{403, `{"error":" Suspended "}`, true},
		{401, `{"error":"suspended"}`, false},
		{403, `{"error":"forbidden"}`, false},
		{403, `suspended`, false},
		{403, ``, false},
	} {
		if got := IsSuspended(tc.code, []byte(tc.body)); got != tc.want {
			t.Errorf("IsSuspended(%d, %q) = %v", tc.code, tc.body, got)
		}
	}
}

// Heartbeat, sync and events wake together when the wait ends: their
// refusals are one try, not three steps of the backoff.
func TestGateOneStepPerRound(t *testing.T) {
	g, clk, _ := newGate(0)
	g.Refused(401, nil)
	clk.add(Min)
	for i := 0; i < 4; i++ {
		if w := g.Refused(401, nil); w != 2*Min {
			t.Fatalf("refusal %d of the round: wait %s, want %s", i, w, 2*Min)
		}
	}
	clk.add(2 * Min)
	if w := g.Refused(401, nil); w != 4*Min {
		t.Fatalf("next round: %s, want %s", w, 4*Min)
	}
}

// The refusal clock counts only while the dashboard answers with refusals:
// it starts at the first one, survives a restart (RestoreClock), is reset by
// any success, and an unreachable dashboard never counts.
func TestRefusalClock(t *testing.T) {
	g, clk, _ := newGate(0)
	changes := 0
	g.OnClockChange(func() { changes++ })
	start := clk.now()
	g.Refused(403, []byte(`{"error":"suspended"}`))
	if !g.RefusedSince().Equal(start) || changes != 1 {
		t.Fatalf("since %s changes %d", g.RefusedSince(), changes)
	}
	for i := 0; i < 48; i++ { // a day of refusals every 30 minutes
		clk.add(30 * time.Minute)
		g.Refused(403, []byte(`{"error":"suspended"}`))
	}
	if d := g.RefusedFor(time.Hour); d != 24*time.Hour || changes != 1 {
		t.Fatalf("refused for %s (changes %d), want 24h", d, changes)
	}
	// The latest answer must be fresh.
	clk.add(2 * time.Hour)
	if d := g.RefusedFor(time.Hour); d != 0 {
		t.Fatalf("stale refusal counted: %s", d)
	}
	// Unreachable after the latest refusal: not counted.
	g.Refused(403, nil)
	g.Unreachable()
	if d := g.RefusedFor(time.Hour); d != 0 {
		t.Fatalf("an unreachable dashboard counted as refusing: %s", d)
	}
	clk.add(time.Minute)
	g.Refused(403, nil)
	if d := g.RefusedFor(time.Hour); d == 0 {
		t.Fatal("refusal after the outage not counted")
	}

	// A restart keeps the start.
	g2, clk2, _ := newGate(0)
	clk2.t = clk.t
	g2.RestoreClock(start)
	g2.Refused(401, nil)
	if !g2.RefusedSince().Equal(start) {
		t.Fatalf("restored clock lost: %s", g2.RefusedSince())
	}
	// Any success resets it.
	accepted := make(chan struct{}, 1)
	g2.OnAccepted(func() { accepted <- struct{}{} })
	g2.OnClockChange(func() { changes++ })
	before := changes
	g2.OK()
	if !g2.RefusedSince().IsZero() || g2.RefusedFor(time.Hour) != 0 || changes != before+1 {
		t.Fatal("success did not reset the clock")
	}
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("OnAccepted not called")
	}
}

// After the switch-off the agent only asks every 30 minutes.
func TestGateIdle(t *testing.T) {
	g, _, _ := newGate(0)
	g.SetIdle(true)
	if w := g.Refused(401, nil); w != Suspended {
		t.Fatalf("idle wait %s, want %s", w, Suspended)
	}
}
