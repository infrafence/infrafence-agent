package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/infrafence/infrafence-agent/internal/backoff"
)

func infoServer(t *testing.T, status *atomic.Int32, body *atomic.Value, gotURL *atomic.Value) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if gotURL != nil {
			gotURL.Store(r.URL.RequestURI() + " " + r.Header.Get("Authorization"))
		}
		w.WriteHeader(int(status.Load()))
		_, _ = w.Write([]byte(body.Load().(string)))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestAttackMap(t *testing.T) {
	var status atomic.Int32
	var body, got atomic.Value
	status.Store(http.StatusOK)
	body.Store(`{"hours":168,"generated_at":"2026-10-24T10:00:00.5+02:00","total":{"attacks":123},"extra":"ignored",
		"countries":[{"code":"US","attacks":12},{"code":"CN","attacks":40}],
		"categories":[{"cat":"web","attacks":5},{"cat":"ssh","attacks":30}]}`)
	c := New(infoServer(t, &status, &body, &got).URL, "tok")

	m, err := c.AttackMap(context.Background(), 168)
	if err != nil {
		t.Fatal(err)
	}
	if got.Load() != "/api/v1/agent/map?hours=168 Bearer tok" {
		t.Errorf("request: %v", got.Load())
	}
	out, _ := json.Marshal(m)
	want := `{"hours":168,"generated_at":"2026-10-24T08:00:00Z","total":{"attacks":123},` +
		`"countries":[{"code":"CN","attacks":40},{"code":"US","attacks":12}],"categories":[{"cat":"ssh","attacks":30},{"cat":"web","attacks":5}]}`
	if string(out) != want {
		t.Errorf("got  %s\nwant %s", out, want)
	}

	body.Store(`{"hours":24,"generated_at":"2026-10-24T10:00:00Z","total":{"attacks":0},"countries":null,"categories":null}`)
	if m, err := c.AttackMap(context.Background(), 24); err != nil || m.Countries == nil || m.Categories == nil {
		t.Errorf("empty map: %+v %v", m, err)
	}

	for name, b := range map[string]string{
		"other range":    `{"hours":24,"generated_at":"2026-10-24T10:00:00Z","total":{"attacks":1}}`,
		"no time":        `{"hours":168,"total":{"attacks":1}}`,
		"negative":       `{"hours":168,"generated_at":"2026-10-24T10:00:00Z","total":{"attacks":-1}}`,
		"lower case":     `{"hours":168,"generated_at":"2026-10-24T10:00:00Z","total":{"attacks":1},"countries":[{"code":"cn","attacks":1}]}`,
		"markup":         `{"hours":168,"generated_at":"2026-10-24T10:00:00Z","total":{"attacks":1},"categories":[{"cat":"<b>","attacks":1}]}`,
		"duplicate":      `{"hours":168,"generated_at":"2026-10-24T10:00:00Z","total":{"attacks":2},"countries":[{"code":"CN","attacks":1},{"code":"CN","attacks":1}]}`,
		"not json":       `<html>`,
		"too large":      `{"hours":168,"generated_at":"2026-10-24T10:00:00Z","x":"` + strings.Repeat("a", maxInfoBody) + `"}`,
		"too many lists": `{"hours":168,"generated_at":"2026-10-24T10:00:00Z","total":{"attacks":1},"categories":[` + strings.Repeat(`{"cat":"x","attacks":1},`, maxMapCategories) + `{"cat":"y","attacks":1}]}`,
	} {
		body.Store(b)
		if _, err := c.AttackMap(context.Background(), 168); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The map and the score never move the refusal backoff (a 401 there is
// left to the heartbeat), but are not sent while it holds the agent.
func TestPanelInfoLeavesTheGateAlone(t *testing.T) {
	var status, calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(int(status.Load()))
	}))
	defer srv.Close()
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	c := New(srv.URL, "tok")
	c.gate = backoff.NewWith(func() time.Time { return now }, func() float64 { return 0 }, t.Logf)
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusBadGateway} {
		status.Store(int32(code))
		if _, err := c.AttackMap(context.Background(), 24); err == nil {
			t.Errorf("%d: no error", code)
		}
		if _, err := c.SecurityScore(context.Background()); err == nil {
			t.Errorf("%d: no error", code)
		}
		if c.gate.Wait() != 0 {
			t.Fatalf("%d moved the refusal backoff", code)
		}
	}
	c.gate.Refused(http.StatusUnauthorized, nil)
	n := calls.Load()
	if _, err := c.AttackMap(context.Background(), 24); !IsHeld(err) {
		t.Errorf("held: %v", err)
	}
	if _, err := c.SecurityScore(context.Background()); !IsHeld(err) {
		t.Errorf("held: %v", err)
	}
	if calls.Load() != n {
		t.Error("sent while the dashboard refuses the agent")
	}
}

func TestSecurityScore(t *testing.T) {
	var status atomic.Int32
	var body, got atomic.Value
	status.Store(http.StatusOK)
	body.Store(`{"generated_at":"2026-10-24T10:00:00Z","score":72,"grade":"C",
		"items":[{"key":"exposed_ports","points":8,"detail":{"ports":[3306]},"action":{"kind":"close_port"}},
		         {"key":"hardening","points":12,"detail":{"failed":22,"total":43}},
		         {"key":"monitor_mode","points":10,"detail":{}},
		         {"key":"agent_outdated","points":5,"detail":{"version":"1.0.20","latest":null}}],
		"trend":[{"day":"2026-10-24","score":72},{"day":"2026-10-20","score":70}]}`)
	c := New(infoServer(t, &status, &body, &got).URL, "tok")
	s, err := c.SecurityScore(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Load() != "/api/v1/agent/score Bearer tok" {
		t.Errorf("request: %v", got.Load())
	}
	out, _ := json.Marshal(s)
	want := `{"generated_at":"2026-10-24T10:00:00Z","score":72,"grade":"C","items":[` +
		`{"key":"hardening","points":12,"detail":{"failed":22,"total":43}},` +
		`{"key":"monitor_mode","points":10,"detail":{}},` +
		`{"key":"exposed_ports","points":8,"detail":{"ports":[3306]}},` +
		`{"key":"agent_outdated","points":5,"detail":{"latest":null,"version":"1.0.20"}}],` +
		`"trend":[{"day":"2026-10-20","score":70},{"day":"2026-10-24","score":72}]}`
	if string(out) != want {
		t.Errorf("got  %s\nwant %s", out, want)
	}

	body.Store(`{"generated_at":"2026-10-24T10:00:00Z","score":100,"grade":"A","items":null,"trend":null}`)
	if s, err := c.SecurityScore(context.Background()); err != nil || s.Items == nil || s.Trend == nil {
		t.Errorf("perfect score: %+v %v", s, err)
	}

	for name, b := range map[string]string{
		"score":       `{"generated_at":"2026-10-24T10:00:00Z","score":101,"grade":"A"}`,
		"grade":       `{"generated_at":"2026-10-24T10:00:00Z","score":50,"grade":"Z"}`,
		"time":        `{"score":50,"grade":"E"}`,
		"key":         `{"generated_at":"2026-10-24T10:00:00Z","score":50,"grade":"E","items":[{"key":"Bad Key","points":1}]}`,
		"points":      `{"generated_at":"2026-10-24T10:00:00Z","score":50,"grade":"E","items":[{"key":"malware","points":-3}]}`,
		"nested":      `{"generated_at":"2026-10-24T10:00:00Z","score":50,"grade":"E","items":[{"key":"malware","points":3,"detail":{"x":{"y":1}}}]}`,
		"control":     `{"generated_at":"2026-10-24T10:00:00Z","score":50,"grade":"E","items":[{"key":"malware","points":3,"detail":{"x":"a\u0007b"}}]}`,
		"long text":   `{"generated_at":"2026-10-24T10:00:00Z","score":50,"grade":"E","items":[{"key":"malware","points":3,"detail":{"x":"` + strings.Repeat("a", 65) + `"}}]}`,
		"markup":      `{"generated_at":"2026-10-24T10:00:00Z","score":50,"grade":"E","items":[{"key":"malware","points":3,"detail":{"x":"<b>x</b>"}}]}`,
		"ampersand":   `{"generated_at":"2026-10-24T10:00:00Z","score":50,"grade":"E","items":[{"key":"malware","points":3,"detail":{"x":"a&b"}}]}`,
		"quote":       `{"generated_at":"2026-10-24T10:00:00Z","score":50,"grade":"E","items":[{"key":"malware","points":3,"detail":{"x":"a\"b"}}]}`,
		"apostrophe":  `{"generated_at":"2026-10-24T10:00:00Z","score":50,"grade":"E","items":[{"key":"malware","points":3,"detail":{"x":"a'b"}}]}`,
		"backtick":    `{"generated_at":"2026-10-24T10:00:00Z","score":50,"grade":"E","items":[{"key":"malware","points":3,"detail":{"x":"a` + "`" + `b"}}]}`,
		"list markup": `{"generated_at":"2026-10-24T10:00:00Z","score":50,"grade":"E","items":[{"key":"malware","points":3,"detail":{"x":["ok","<i>"]}}]}`,
		"trend day":   `{"generated_at":"2026-10-24T10:00:00Z","score":50,"grade":"E","trend":[{"day":"yesterday","score":1}]}`,
		"trend score": `{"generated_at":"2026-10-24T10:00:00Z","score":50,"grade":"E","trend":[{"day":"2026-10-20","score":900}]}`,
	} {
		body.Store(b)
		if _, err := c.SecurityScore(context.Background()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Errors (which end up in the agent's log) carry the status, never the
// dashboard's body, and at most a short quote of a refused value.
func TestPanelInfoErrorsAreShort(t *testing.T) {
	var status atomic.Int32
	var body atomic.Value
	status.Store(http.StatusInternalServerError)
	body.Store(strings.Repeat("BODY", 1024))
	c := New(infoServer(t, &status, &body, nil).URL, "tok")
	_, err := c.AttackMap(context.Background(), 24)
	if err == nil || strings.Contains(err.Error(), "BODY") || !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("status error: %v", err)
	}
	status.Store(http.StatusOK)
	body.Store(`{"hours":24,"generated_at":"2026-10-24T10:00:00Z","total":{"attacks":1},"countries":[{"code":"` + strings.Repeat("X", 3000) + `","attacks":1}]}`)
	_, err = c.AttackMap(context.Background(), 24)
	if err == nil || len(err.Error()) > 200 {
		t.Errorf("refused value: %d bytes: %.300v", len(err.Error()), err)
	}
}
