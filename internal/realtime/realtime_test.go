package realtime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// fakeServer speaks enough of the Phoenix/Realtime protocol for the client.
type fakeServer struct {
	t        *testing.T
	refuse   bool
	mu       sync.Mutex
	wmu      sync.Mutex // gorilla conns allow one writer at a time
	conns    []*websocket.Conn
	joins    []map[string]any
	query    []string
	beats    int
	joinedCh chan *websocket.Conn
}

func (s *fakeServer) handler(w http.ResponseWriter, r *http.Request) {
	up := websocket.Upgrader{}
	c, err := up.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	s.mu.Lock()
	s.conns = append(s.conns, c)
	s.query = append(s.query, r.URL.RawQuery)
	s.mu.Unlock()
	for {
		var m map[string]any
		if err := c.ReadJSON(&m); err != nil {
			return
		}
		switch m["event"] {
		case "phx_join":
			s.mu.Lock()
			s.joins = append(s.joins, m)
			s.mu.Unlock()
			status := "ok"
			if s.refuse {
				status = "error"
			}
			s.write(c, map[string]any{
				"topic": m["topic"], "event": "phx_reply", "ref": m["ref"],
				"payload": map[string]any{"status": status, "response": map[string]any{}},
			})
			if !s.refuse {
				s.joinedCh <- c
			}
		case "heartbeat":
			s.mu.Lock()
			s.beats++
			s.mu.Unlock()
			s.write(c, map[string]any{"topic": "phoenix", "event": "phx_reply", "ref": m["ref"],
				"payload": map[string]any{"status": "ok", "response": map[string]any{}}})
		}
	}
}

func (s *fakeServer) write(c *websocket.Conn, v any) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	_ = c.WriteJSON(v)
}

func (s *fakeServer) broadcast(c *websocket.Conn, topic, event string) {
	s.write(c, map[string]any{
		"topic": "realtime:" + topic, "event": "broadcast", "ref": nil,
		"payload": map[string]any{"type": "broadcast", "event": event, "payload": map[string]any{"reason": "org_settings"}},
	})
}

func start(t *testing.T, refuse bool) (*fakeServer, Config) {
	s := &fakeServer{t: t, refuse: refuse, joinedCh: make(chan *websocket.Conn, 8)}
	srv := httptest.NewServer(http.HandlerFunc(s.handler))
	t.Cleanup(srv.Close)
	return s, Config{URL: "ws" + strings.TrimPrefix(srv.URL, "http") + "/realtime/v1/websocket", Key: "pk_test", Topic: "agent-abc"}
}

type signals struct {
	mu  sync.Mutex
	got []string
	ch  chan string
}

func newSignals() *signals { return &signals{ch: make(chan string, 16)} }
func (s *signals) on(e string) {
	s.mu.Lock()
	s.got = append(s.got, e)
	s.mu.Unlock()
	s.ch <- e
}
func (s *signals) wait(t *testing.T, want string) {
	t.Helper()
	select {
	case e := <-s.ch:
		if e != want {
			t.Fatalf("signal = %q, want %q", e, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("no %q signal", want)
	}
}

func fast(c *Client) *Client {
	c.heartbeatEvery = 50 * time.Millisecond
	c.minBackoff = 20 * time.Millisecond
	c.maxBackoff = 50 * time.Millisecond
	return c
}

func TestJoinBroadcastAndHeartbeat(t *testing.T) {
	s, cfg := start(t, false)
	sig := newSignals()
	c := fast(New(cfg, sig.on))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)

	conn := <-s.joinedCh
	sig.wait(t, "resubscribed")
	if !c.Connected() {
		t.Error("not connected after join")
	}

	s.mu.Lock()
	join, q := s.joins[0], s.query[0]
	s.mu.Unlock()
	if join["topic"] != "realtime:agent-abc" {
		t.Errorf("join topic = %v", join["topic"])
	}
	cfgJSON, _ := json.Marshal(join["payload"])
	if !strings.Contains(string(cfgJSON), `"private":false`) {
		t.Errorf("join must request a public channel: %s", cfgJSON)
	}
	if !strings.Contains(q, "apikey=pk_test") || !strings.Contains(q, "vsn=1.0.0") {
		t.Errorf("query = %q", q)
	}

	s.broadcast(conn, "agent-abc", "sync")
	sig.wait(t, "sync")

	// Messages for another topic are ignored.
	s.broadcast(conn, "agent-other", "sync")
	select {
	case e := <-sig.ch:
		t.Fatalf("signal from another topic: %q", e)
	case <-time.After(150 * time.Millisecond):
	}

	s.mu.Lock()
	beats := s.beats
	s.mu.Unlock()
	if beats == 0 {
		t.Error("no heartbeats sent")
	}
}

func TestReconnectsAndResyncs(t *testing.T) {
	s, cfg := start(t, false)
	sig := newSignals()
	c := fast(New(cfg, sig.on))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)

	conn := <-s.joinedCh
	sig.wait(t, "resubscribed")
	conn.Close() // server drops the connection

	conn = <-s.joinedCh
	sig.wait(t, "resubscribed") // changes missed while away are synced
	s.broadcast(conn, "agent-abc", "sync")
	sig.wait(t, "sync")
}

func TestJoinRefusedRetries(t *testing.T) {
	s, cfg := start(t, true)
	c := fast(New(cfg, func(string) { t.Error("no signal expected when the join is refused") }))
	ctx, cancel := context.WithCancel(context.Background())
	go c.Run(ctx)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		n := len(s.joins)
		s.mu.Unlock()
		if n >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.joins) < 2 {
		t.Errorf("joins = %d, want retries", len(s.joins))
	}
	if c.Connected() {
		t.Error("connected after a refused join")
	}
}

func TestStopsOnCancel(t *testing.T) {
	s, cfg := start(t, false)
	c := fast(New(cfg, func(string) {}))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	<-s.joinedCh
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}
