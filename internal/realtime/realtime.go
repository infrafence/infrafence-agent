// Package realtime listens for "configuration changed" signals from the
// dashboard over Supabase Realtime (Phoenix channels, protocol 1.0.0).
//
// A signal is only a hint to sync now: the agent never acts on a message's
// contents, it fetches its configuration through the authenticated sync API.
// So a forged or replayed message can at most cause an early sync (which the
// caller rate-limits), and a lost one is caught by the heartbeat's config
// version and the periodic sync.
package realtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/url"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// Config comes from the dashboard's heartbeat reply.
type Config struct {
	URL   string // wss://<ref>.supabase.co/realtime/v1/websocket
	Key   string // public (publishable) API key
	Topic string // this agent's channel
}

// Client keeps one channel subscription alive, reconnecting with backoff.
type Client struct {
	cfg      Config
	onSignal func(event string)

	// Tunables (tests shorten them).
	heartbeatEvery time.Duration
	readTimeout    time.Duration
	minBackoff     time.Duration
	maxBackoff     time.Duration

	connected atomic.Bool
	ref       atomic.Uint64
}

// New returns a client; call Run to start it.
func New(cfg Config, onSignal func(event string)) *Client {
	return &Client{
		cfg:            cfg,
		onSignal:       onSignal,
		heartbeatEvery: 25 * time.Second,
		readTimeout:    60 * time.Second,
		minBackoff:     time.Second,
		maxBackoff:     2 * time.Minute,
	}
}

// Connected reports whether the channel is currently joined.
func (c *Client) Connected() bool { return c.connected.Load() }

// Run connects and stays subscribed until ctx is cancelled.
func (c *Client) Run(ctx context.Context) {
	backoff := c.minBackoff
	for ctx.Err() == nil {
		start := time.Now()
		err := c.session(ctx)
		c.connected.Store(false)
		if ctx.Err() != nil {
			return
		}
		// A session that lasted a while was healthy: start backing off again
		// from the minimum.
		if time.Since(start) > 5*time.Minute {
			backoff = c.minBackoff
		}
		wait := backoff/2 + time.Duration(rand.Int63n(int64(backoff/2)+1))
		log.Printf("[realtime] disconnected (%v) — reconnecting in %s", err, wait.Round(time.Second))
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if backoff *= 2; backoff > c.maxBackoff {
			backoff = c.maxBackoff
		}
	}
}

type message struct {
	Topic   string          `json:"topic"`
	Event   string          `json:"event"`
	Payload json.RawMessage `json:"payload"`
	Ref     *string         `json:"ref"`
	JoinRef *string         `json:"join_ref,omitempty"`
}

func (c *Client) nextRef() string { return strconv.FormatUint(c.ref.Add(1), 10) }

// session runs one connection: join, then read until an error.
func (c *Client) session(ctx context.Context) error {
	u, err := url.Parse(c.cfg.URL)
	if err != nil {
		return err
	}
	q := u.Query()
	q.Set("apikey", c.cfg.Key)
	q.Set("vsn", "1.0.0")
	u.RawQuery = q.Encode()

	dialCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	conn, resp, err := websocket.DefaultDialer.DialContext(dialCtx, u.String(), nil)
	cancel()
	if err != nil {
		if resp != nil {
			return fmt.Errorf("dial: %w (HTTP %d)", err, resp.StatusCode)
		}
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetReadLimit(1 << 20)

	// Close the connection when ctx ends so the blocking read returns.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.WriteControl(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
			conn.Close()
		case <-done:
		}
	}()

	topic := "realtime:" + c.cfg.Topic
	joinRef := c.nextRef()
	writes := make(chan message, 4)
	writeErr := make(chan error, 1)
	go func() {
		t := time.NewTicker(c.heartbeatEvery)
		defer t.Stop()
		for {
			var m message
			select {
			case <-done:
				return
			case m = <-writes:
			case <-t.C:
				r := c.nextRef()
				m = message{Topic: "phoenix", Event: "heartbeat", Payload: json.RawMessage(`{}`), Ref: &r}
			}
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := conn.WriteJSON(m); err != nil {
				writeErr <- err
				conn.Close()
				return
			}
		}
	}()

	join := json.RawMessage(`{"config":{"broadcast":{"ack":false,"self":false},"presence":{"enabled":false,"key":""},"postgres_changes":[],"private":false}}`)
	writes <- message{Topic: topic, Event: "phx_join", Payload: join, Ref: &joinRef, JoinRef: &joinRef}

	for {
		_ = conn.SetReadDeadline(time.Now().Add(c.readTimeout))
		var m message
		if err := conn.ReadJSON(&m); err != nil {
			select {
			case werr := <-writeErr:
				return fmt.Errorf("write: %w", werr)
			default:
			}
			return fmt.Errorf("read: %w", err)
		}
		if m.Topic != topic {
			continue // heartbeat replies ("phoenix") and anything else
		}
		switch m.Event {
		case "phx_reply":
			if m.Ref == nil || *m.Ref != joinRef {
				continue
			}
			var r struct {
				Status   string          `json:"status"`
				Response json.RawMessage `json:"response"`
			}
			_ = json.Unmarshal(m.Payload, &r)
			if r.Status != "ok" {
				return fmt.Errorf("join refused: %s", r.Response)
			}
			if !c.connected.Swap(true) {
				log.Printf("[realtime] subscribed — dashboard changes now reach this server immediately")
				// Anything that changed while disconnected is picked up by a
				// sync right after (re)joining.
				c.onSignal("resubscribed")
			}
		case "broadcast":
			var b struct {
				Event string `json:"event"`
			}
			_ = json.Unmarshal(m.Payload, &b)
			if b.Event == "" {
				b.Event = "broadcast"
			}
			c.onSignal(b.Event)
		case "phx_close", "phx_error":
			return errors.New(m.Event)
		}
	}
}
