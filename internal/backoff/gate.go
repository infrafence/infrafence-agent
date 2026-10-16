// Package backoff holds the agent's reaction to the dashboard refusing it
// (401: token revoked or rotated, 403: organization suspended, agent
// disabled): every component that talks to the dashboard (heartbeat, sync,
// events, websocket) waits on the same Gate, so a refused agent does not keep
// hitting the dashboard every few seconds. Local protection is never touched
// by a refusal; only the requests wait.
package backoff

import (
	"encoding/json"
	"log"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// Min and Max bound the wait after a refusal: Min after the first one,
	// doubling up to Max.
	Min = time.Minute
	Max = 30 * time.Minute
	// Suspended is the wait while the organization is suspended
	// (403 {"error":"suspended"}): nothing changes before someone acts.
	Suspended = 30 * time.Minute
)

// Gate records the dashboard's refusals and says how long to wait before the
// next request. The zero value is not usable; call New.
type Gate struct {
	mu        sync.Mutex
	failures  int
	until     time.Time
	code      int
	suspended bool

	now  func() time.Time
	rand func() float64
	logf func(format string, args ...any)
}

// New returns a Gate that lets every request through.
func New() *Gate {
	return &Gate{now: time.Now, rand: rand.Float64, logf: log.Printf}
}

// NewWith is New with its clock, random source and logger replaced (tests).
func NewWith(now func() time.Time, random func() float64, logf func(string, ...any)) *Gate {
	return &Gate{now: now, rand: random, logf: logf}
}

// Refusal reports whether status is a refusal of the agent itself.
func Refusal(status int) bool {
	return status == http.StatusUnauthorized || status == http.StatusForbidden
}

// IsSuspended reports whether a 403 body says the organization is suspended:
// {"error":"suspended"} (the dashboard may add other fields).
func IsSuspended(status int, body []byte) bool {
	if status != http.StatusForbidden {
		return false
	}
	var v struct {
		Error string `json:"error"`
	}
	return json.Unmarshal(body, &v) == nil && strings.EqualFold(strings.TrimSpace(v.Error), "suspended")
}

// Delay is the wait after the n-th refusal in a row (n >= 1): Min doubled
// n-1 times, with up to 20% added at random so the agents of a suspended
// organization do not all come back at the same second, and never above Max
// (near Max, up to 10% is taken off instead).
func Delay(n int, r float64) time.Duration {
	base := Max
	if n < 1 {
		n = 1
	}
	if n <= 6 { // 1m << 5 = 32m > Max
		base = min(Min<<(n-1), Max)
	}
	d := base + time.Duration(r*float64(base)/5)
	if d > Max {
		d = Max - time.Duration(r*float64(Max)/10)
	}
	return max(d, Min)
}

// Refused records a 401 or 403 reply (other codes are ignored) and returns
// the wait before the next request. The first refusal, and a change between
// "suspended" and another refusal, are logged; the ones in between are not.
func (g *Gate) Refused(status int, body []byte) time.Duration {
	if !Refusal(status) {
		return 0
	}
	suspended := IsSuspended(status, body)
	g.mu.Lock()
	defer g.mu.Unlock()
	// Requests sent together when the wait ended (heartbeat, sync, events)
	// are one try: only the first refusal of a round extends the backoff.
	if now := g.now(); g.failures > 0 && now.Before(g.until) && suspended == g.suspended && status == g.code {
		return g.until.Sub(now)
	}
	changed := g.failures == 0 || suspended != g.suspended || status != g.code
	g.failures++
	g.code, g.suspended = status, suspended
	wait := Delay(g.failures, g.rand())
	if suspended {
		wait = Suspended - time.Duration(g.rand()*float64(Suspended)/10)
	}
	g.until = g.now().Add(wait)
	if changed {
		switch {
		case suspended:
			g.logf("[api] WARNING: the dashboard says this organization is SUSPENDED (403). Local protection stays in force (bans, allow list, country blocks); the agent asks again every 30 minutes.")
		case status == http.StatusUnauthorized:
			g.logf("[api] ERROR: the dashboard refused the agent token (401). Local protection stays in force; retrying in %s, backing off up to %s. Re-register the agent if the token was revoked.", wait.Round(time.Second), Max)
		default:
			g.logf("[api] ERROR: the dashboard refused the agent (403: %s). Local protection stays in force; retrying in %s, backing off up to %s.", snippet(body), wait.Round(time.Second), Max)
		}
	}
	return wait
}

// OK records an accepted request: the next ones go through at once. It
// reports whether the agent was being refused until now.
func (g *Gate) OK() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.failures == 0 {
		return false
	}
	g.logf("[api] the dashboard accepts the agent again after %d refusal(s)", g.failures)
	g.failures, g.code, g.suspended, g.until = 0, 0, false, time.Time{}
	return true
}

// Wait returns how long requests must still wait (zero: send now).
func (g *Gate) Wait() time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.failures == 0 {
		return 0
	}
	return max(g.until.Sub(g.now()), 0)
}

// State returns the last refusal: its status code (zero: not refused) and
// whether it said the organization is suspended.
func (g *Gate) State() (code int, suspended bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.code, g.suspended
}

func snippet(b []byte) string {
	s := strings.Join(strings.Fields(string(b)), " ")
	if len(s) > 120 {
		s = s[:120] + "..."
	}
	if s == "" {
		s = "no body"
	}
	return s
}
