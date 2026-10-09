package api

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// countingServer answers with the status returned by status() and counts the
// TCP connections clients open to it.
func countingServer(t *testing.T, status func() int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var conns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status())
		_, _ = w.Write([]byte(`{}`))
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, &conns
}

func TestConnectionReused(t *testing.T) {
	srv, conns := countingServer(t, func() int { return http.StatusOK })
	c := New(srv.URL, "tok")
	for i := 0; i < 3; i++ {
		if err := c.get("/x", &map[string]any{}); err != nil {
			t.Fatal(err)
		}
	}
	if n := conns.Load(); n != 1 {
		t.Fatalf("%d connections for 3 requests, want 1 (keep-alive)", n)
	}
}

func TestNewConnectionAfterServiceUnavailable(t *testing.T) {
	var calls atomic.Int32
	srv, conns := countingServer(t, func() int {
		if calls.Add(1) == 1 {
			return http.StatusServiceUnavailable // the old proxy after the move
		}
		return http.StatusOK
	})
	c := New(srv.URL, "tok")
	if err := c.post("/x", "tok", map[string]any{}, nil); err == nil {
		t.Fatal("want an error for 503")
	}
	if err := c.post("/x", "tok", map[string]any{}, nil); err != nil {
		t.Fatal(err)
	}
	if n := conns.Load(); n != 2 {
		t.Fatalf("%d connections, want 2: the request after a 503 must dial again", n)
	}
}

func TestOtherErrorsKeepTheConnection(t *testing.T) {
	srv, conns := countingServer(t, func() int { return http.StatusUnauthorized })
	c := New(srv.URL, "tok")
	for i := 0; i < 3; i++ {
		_ = c.post("/x", "tok", map[string]any{}, nil)
	}
	if n := conns.Load(); n != 1 {
		t.Fatalf("%d connections, want 1: a 401 comes from the right server", n)
	}
}

func TestOldConnectionsAreReplaced(t *testing.T) {
	srv, conns := countingServer(t, func() int { return http.StatusOK })
	c := New(srv.URL, "tok")
	if err := c.get("/x", &map[string]any{}); err != nil {
		t.Fatal(err)
	}
	// A connection busy every few seconds never goes idle; age alone retires it.
	c.lastRecycle.Store(time.Now().Add(-connMaxAge - time.Second).UnixNano())
	if err := c.get("/x", &map[string]any{}); err != nil {
		t.Fatal(err)
	}
	if err := c.get("/x", &map[string]any{}); err != nil {
		t.Fatal(err)
	}
	if n := conns.Load(); n != 2 {
		t.Fatalf("%d connections, want 2: one replaced after connMaxAge, then reused", n)
	}
}

func TestLongUploadsShareTheTransport(t *testing.T) {
	srv, conns := countingServer(t, func() int { return http.StatusOK })
	c := New(srv.URL, "tok")
	if err := c.postLong("/x", "tok", map[string]any{}, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.post("/x", "tok", map[string]any{}, nil); err != nil {
		t.Fatal(err)
	}
	if n := conns.Load(); n != 1 {
		t.Fatalf("%d connections, want 1", n)
	}
}
