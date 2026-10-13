package verify

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeHost points the probes at local test listeners: SSH "port" n is the
// listener in ssh[n], sites are served by one HTTP server.
func fakeHost(t *testing.T, ssh map[int]net.Listener, site http.Handler) {
	t.Helper()
	srv := httptest.NewServer(site)
	t.Cleanup(srv.Close)
	oldAddr, oldBase, oldDelay, oldSettle := sshAddr, httpBase, retryDelay, settleTime
	sshAddr = func(p int) string {
		if l, ok := ssh[p]; ok {
			return l.Addr().String()
		}
		return "127.0.0.1:1"
	}
	// No HTTPS unless a test sets it: nothing answers on port 1.
	httpBase = map[string]string{"http": srv.URL, "https": "https://127.0.0.1:1"}
	retryDelay = 10 * time.Millisecond
	settleTime = time.Second
	t.Cleanup(func() { sshAddr, httpBase, retryDelay, settleTime = oldAddr, oldBase, oldDelay, oldSettle })
}

func listen(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return l
}

func TestSnapshotAndCheckHealthy(t *testing.T) {
	l := listen(t)
	defer l.Close()
	fakeHost(t, map[int]net.Listener{22: l}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Host {
		case "down.example":
			w.WriteHeader(503)
		case "redirect.example":
			http.Redirect(w, r, "https://elsewhere.example/", http.StatusMovedPermanently)
		}
	}))
	before := Snapshot(context.Background(), []int{22, 2222}, []string{"ok.example", "redirect.example", "down.example", "*.wild.example", "ok.example"})
	if !before.SSH[22] || before.SSH[2222] {
		t.Fatalf("ssh snapshot = %v", before.SSH)
	}
	if before.Sites["ok.example"] != 200 || before.Sites["redirect.example"] != 301 || before.Sites["down.example"] != 503 {
		t.Fatalf("sites snapshot = %v", before.Sites)
	}
	if _, ok := before.Sites["*.wild.example"]; ok {
		t.Fatal("wildcard names must not be probed")
	}
	// 2222 never accepted and down.example was already failing: neither
	// counts against the change.
	if r := Check(context.Background(), before); !r.OK() {
		t.Fatalf("Check = %+v, want ok", r)
	}
}

func TestCheckDetectsSSHLoss(t *testing.T) {
	l := listen(t)
	fakeHost(t, map[int]net.Listener{22: l}, http.NotFoundHandler())
	before := Snapshot(context.Background(), []int{22}, nil)
	l.Close()
	r := Check(context.Background(), before)
	if r.SSHOK || !r.SitesOK || !strings.Contains(r.Details, "ssh port 22") {
		t.Fatalf("Check = %+v, want ssh failure", r)
	}
}

func TestCheckDetectsNew5xxAndRetries(t *testing.T) {
	var broken, calls atomic.Int32
	fakeHost(t, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if broken.Load() == 1 {
			w.WriteHeader(502)
		}
	}))
	before := Snapshot(context.Background(), nil, []string{"shop.example"})
	broken.Store(1)
	r := Check(context.Background(), before)
	if r.SitesOK || !strings.Contains(r.Details, "shop.example 502 (was 200)") {
		t.Fatalf("Check = %+v, want site failure", r)
	}
	if n := calls.Load(); n != 3 { // snapshot + check + one retry
		t.Fatalf("%d probes, want 3", n)
	}

	// A failure that clears within the retry passes.
	calls.Store(0)
	fakeHost(t, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 2 {
			w.WriteHeader(500)
		}
	}))
	before = Snapshot(context.Background(), nil, []string{"shop.example"})
	if r := Check(context.Background(), before); !r.OK() {
		t.Fatalf("transient failure should pass after the retry: %+v", r)
	}
}

func TestValidDomainsBounded(t *testing.T) {
	var many []string
	for i := 0; i < 50; i++ {
		many = append(many, "s"+string(rune('a'+i%26))+string(rune('a'+i/26))+".example")
	}
	if got := validDomains(append(many, "bad host", "x.example:8080", "_")); len(got) != maxSites {
		t.Fatalf("got %d domains, want %d", len(got), maxSites)
	}
}

// tlsSite serves handler over HTTPS as the "https" base.
func tlsSite(t *testing.T, handler http.Handler) {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	httpBase["https"] = srv.URL
}

func TestCheckHTTPSBrokenBehindRedirect(t *testing.T) {
	var broken atomic.Bool
	// Plain HTTP only redirects to another host name (kept as a 301), so
	// only the explicit HTTPS probe sees the site break.
	fakeHost(t, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://www.shop.example/", http.StatusMovedPermanently)
	}))
	tlsSite(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if broken.Load() {
			w.WriteHeader(503)
		}
	}))
	before := Snapshot(context.Background(), nil, []string{"shop.example"})
	if before.Sites["shop.example"] != 301 || before.SitesTLS["shop.example"] != 200 {
		t.Fatalf("snapshot = %v / %v", before.Sites, before.SitesTLS)
	}
	broken.Store(true)
	r := Check(context.Background(), before)
	if r.SitesOK || !strings.Contains(r.Details, "shop.example https 503 (was 200)") {
		t.Fatalf("Check = %+v, want https failure", r)
	}
}

func TestSameHostRedirectFollowedOnce(t *testing.T) {
	var broken atomic.Bool
	fakeHost(t, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, "/home", http.StatusFound)
		case "/home":
			if broken.Load() {
				w.WriteHeader(500)
				return
			}
			// A second redirect is not followed.
			http.Redirect(w, r, "http://Shop.Example:8080/again", http.StatusFound)
		}
	}))
	before := Snapshot(context.Background(), nil, []string{"shop.example"})
	if before.Sites["shop.example"] != 302 {
		t.Fatalf("snapshot = %v, want the second redirect's 302", before.Sites)
	}
	broken.Store(true)
	if r := Check(context.Background(), before); r.SitesOK || !strings.Contains(r.Details, "shop.example 500 (was 302)") {
		t.Fatalf("Check = %+v, want the redirect target's 500", r)
	}
}

func TestCheckAfterReloadWaitsForService(t *testing.T) {
	l := listen(t)
	addr := l.Addr().String()
	fakeHost(t, map[int]net.Listener{22: l}, http.NotFoundHandler())
	retryDelay = 50 * time.Millisecond
	before := Snapshot(context.Background(), []int{22}, nil)
	l.Close()
	// The service comes back after a moment, as after a restart.
	go func() {
		time.Sleep(300 * time.Millisecond)
		if l2, err := net.Listen("tcp", addr); err == nil {
			t.Cleanup(func() { l2.Close() })
			go func() {
				for {
					c, err := l2.Accept()
					if err != nil {
						return
					}
					c.Close()
				}
			}()
		}
	}()
	if r := Check(context.Background(), before); r.OK() {
		t.Fatalf("Check should not wait that long: %+v", r)
	}
	if r := CheckAfterReload(context.Background(), before); !r.OK() {
		t.Fatalf("CheckAfterReload = %+v, want ok once the service is back", r)
	}

	// Still down at the end of the settle time: a failure.
	l3 := listen(t)
	sshAddr = func(int) string { return l3.Addr().String() }
	before = Snapshot(context.Background(), []int{22}, nil)
	l3.Close()
	start := time.Now()
	if r := CheckAfterReload(context.Background(), before); r.SSHOK {
		t.Fatalf("CheckAfterReload = %+v, want ssh failure", r)
	}
	if d := time.Since(start); d < 500*time.Millisecond || d > 3*time.Second {
		t.Fatalf("gave up after %v, want about the settle time (1s)", d)
	}
}
