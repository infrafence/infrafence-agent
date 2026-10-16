package panel

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// sockDir returns a short temporary directory: Unix socket paths are
// limited to about 100 bytes.
func sockDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "ifp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func serve(t *testing.T, path string, h Handler) *Server {
	t.Helper()
	s, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	s.peerOK = func(net.Conn) error { return nil }
	go s.Serve(h)
	t.Cleanup(func() { s.Close() })
	return s
}

func TestSocketPermissions(t *testing.T) {
	path := filepath.Join(sockDir(t), "run", "panel.sock")
	s := serve(t, path, func(Request) Response { return OK(nil) })

	st, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != 0o600 {
		t.Errorf("socket mode %v, want socket 0600", st.Mode())
	}
	dst, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if dst.Mode().Perm() != 0o700 {
		t.Errorf("directory mode %v, want 0700", dst.Mode().Perm())
	}

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Errorf("socket left behind after Close: %v", err)
	}
}

func TestSocketDirectoryTightened(t *testing.T) {
	dir := filepath.Join(sockDir(t), "run")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	serve(t, filepath.Join(dir, "panel.sock"), func(Request) Response { return OK(nil) })
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o700 {
		t.Errorf("directory mode %v, want 0700", st.Mode().Perm())
	}
}

func TestStaleSocketReplacedOthersRefused(t *testing.T) {
	dir := sockDir(t)
	path := filepath.Join(dir, "panel.sock")

	// A socket left by a crashed agent: nobody listens, it is replaced.
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	ln.Close()
	s := serve(t, path, func(Request) Response { return OK(nil) })

	// A second agent must not take over a live socket.
	saved := bindRetry
	bindRetry = 300 * time.Millisecond
	defer func() { bindRetry = saved }()
	if _, err := Listen(path); err == nil || !strings.Contains(err.Error(), "in use") {
		t.Errorf("live socket taken over: %v", err)
	}
	s.Close()

	// A regular file at the path is never removed.
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(path); err == nil {
		t.Error("regular file replaced by the socket")
	}
	if data, _ := os.ReadFile(path); string(data) != "x" {
		t.Error("regular file changed")
	}
}

func TestCallRoundTrip(t *testing.T) {
	path := filepath.Join(sockDir(t), "panel.sock")
	var got Request
	serve(t, path, func(r Request) Response {
		got = r
		return OK(map[string]any{"ip": r.IP})
	})
	resp, err := Call(path, Request{Command: "unban", IP: "::ffff:203.0.113.7", Actor: "root"}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Succeeded() || resp["ip"] != "203.0.113.7" || got.Actor != "root" {
		t.Errorf("resp %v, handler got %+v", resp, got)
	}

	// The agent validates again: a request that skipped ParseArgs.
	resp, err = Call(path, Request{Command: "unban", IP: "203.0.113.0/24", Actor: "root"}, 5*time.Second)
	if err != nil || resp["error"] != ErrInvalidIP {
		t.Errorf("unvalidated request: %v %v", resp, err)
	}
}

func TestCallWithoutAgent(t *testing.T) {
	_, err := Call(filepath.Join(sockDir(t), "missing.sock"), Request{Command: "status"}, time.Second)
	if !errors.Is(err, ErrNotRunning) {
		t.Errorf("got %v, want ErrNotRunning", err)
	}
}

func TestNonRootPeerRefused(t *testing.T) {
	path := filepath.Join(sockDir(t), "panel.sock")
	s, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	s.peerOK = func(net.Conn) error { return errors.New("peer uid 1000 is not root") }
	called := false
	go s.Serve(func(Request) Response { called = true; return OK(nil) })
	defer s.Close()
	resp, err := Call(path, Request{Command: "status"}, 5*time.Second)
	if err != nil || resp.Succeeded() || called {
		t.Errorf("non-root peer served: %v %v called=%v", resp, err, called)
	}
}

func TestBadRequestsAndPanics(t *testing.T) {
	path := filepath.Join(sockDir(t), "panel.sock")
	serve(t, path, func(r Request) Response {
		if r.Command == "bans" {
			panic("boom")
		}
		return nil
	})
	raw := func(payload string) string {
		c, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		c.Write([]byte(payload))
		buf := make([]byte, 4096)
		n, _ := c.Read(buf)
		return string(buf[:n])
	}
	if out := raw(`{"command":"status","shell":"id"}` + "\n"); !strings.Contains(out, ErrBadRequest) {
		t.Errorf("unknown field accepted: %s", out)
	}
	if out := raw("not json\n"); !strings.Contains(out, ErrBadRequest) {
		t.Errorf("garbage accepted: %s", out)
	}
	if out := raw(`{"command":"status","note":"` + strings.Repeat("x", maxRequest) + `"}` + "\n"); !strings.Contains(out, "too large") {
		t.Errorf("oversized request: %.80s", out)
	}
	if out := raw(`{"command":"bans"}` + "\n"); !strings.Contains(out, ErrInternal) {
		t.Errorf("panic not contained: %s", out)
	}
	if out := raw(`{"command":"status"}` + "\n"); !strings.Contains(out, ErrInternal) {
		t.Errorf("nil answer: %s", out)
	}
}

// shorten sets a timeout variable for one test.
func shorten(t *testing.T, v *time.Duration, d time.Duration) {
	saved := *v
	*v = d
	t.Cleanup(func() { *v = saved })
}

// During a restart the old agent may still answer for a moment.
func TestListenWaitsForTheOldAgent(t *testing.T) {
	shorten(t, &bindRetry, 3*time.Second)
	path := filepath.Join(sockDir(t), "panel.sock")
	old, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	old.peerOK = func(net.Conn) error { return nil }
	go old.Serve(func(Request) Response { return OK(nil) })
	time.AfterFunc(500*time.Millisecond, func() { old.Close() })
	s, err := Listen(path)
	if err != nil {
		t.Fatalf("new agent could not bind: %v", err)
	}
	s.Close()
}

// A client that connects and sends nothing is dropped after readTimeout.
func TestSilentClientDropped(t *testing.T) {
	shorten(t, &readTimeout, 200*time.Millisecond)
	path := filepath.Join(sockDir(t), "panel.sock")
	serve(t, path, func(Request) Response { return OK(nil) })
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	start := time.Now()
	buf := make([]byte, 64)
	if _, err := c.Read(buf); err == nil || time.Since(start) > 2*time.Second {
		t.Errorf("not dropped: %v after %s", err, time.Since(start))
	}
}

// The write deadline starts after the handler: a handler slower than the
// read timeout still answers.
func TestSlowHandlerStillAnswers(t *testing.T) {
	shorten(t, &readTimeout, 200*time.Millisecond)
	shorten(t, &writeTimeout, 200*time.Millisecond)
	path := filepath.Join(sockDir(t), "panel.sock")
	serve(t, path, func(Request) Response { time.Sleep(600 * time.Millisecond); return OK(map[string]any{"slow": true}) })
	resp, err := Call(path, Request{Command: "status"}, 5*time.Second)
	if err != nil || resp["slow"] != true {
		t.Errorf("slow handler: %v %v", resp, err)
	}
}

// Close never waits longer than closeWait for a stuck request.
func TestCloseIsBounded(t *testing.T) {
	shorten(t, &closeWait, 300*time.Millisecond)
	path := filepath.Join(sockDir(t), "panel.sock")
	s, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	s.peerOK = func(net.Conn) error { return nil }
	release := make(chan struct{})
	started := make(chan struct{})
	go s.Serve(func(Request) Response { close(started); <-release; return OK(nil) })
	go Call(path, Request{Command: "status"}, 10*time.Second)
	<-started
	begin := time.Now()
	s.Close()
	if d := time.Since(begin); d > 2*time.Second {
		t.Errorf("Close took %s", d)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Errorf("socket left: %v", err)
	}
	close(release)
}
