package panel

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

const (
	maxRequest = 16 << 10
	maxConns   = 4
)

// Replaced in tests.
var (
	// readTimeout: the client sends its one-line request at once.
	readTimeout = 5 * time.Second
	// writeTimeout starts after the handler (which may wait on the
	// dashboard), so a slow handler never eats the time to answer.
	writeTimeout = 5 * time.Second
	// closeWait bounds how long Close waits for requests in progress: well
	// below systemd's stop timeout (90 s) used by install.sh.
	closeWait = 3 * time.Second
	// bindRetry: during a restart the old agent may still answer for a
	// moment; Listen waits for it this long.
	bindRetry = 5 * time.Second
)

// Handler answers one request.
type Handler func(Request) Response

// Server is the agent's end of the socket.
type Server struct {
	path   string
	ln     net.Listener
	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup
	sem    chan struct{}
	// peerOK checks the connecting process (root only); replaced in tests.
	peerOK func(net.Conn) error
	// Copied from readTimeout and writeTimeout by Listen.
	readTimeout, writeTimeout time.Duration
}

// Listen creates the socket at path: its directory is created 0700 (an
// existing one is tightened to 0700 when root owns it) so no other user can
// reach the socket even before its mode is set, a stale socket left by a
// crash is replaced, anything else at path is refused, and the socket gets
// mode 0600. Only root can connect.
func Listen(path string) (*Server, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}
	if err := ownedByUs(st); err != nil {
		return nil, fmt.Errorf("%s: %w", dir, err)
	}
	if st.Mode().Perm() != 0o700 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return nil, err
		}
	}
	if st, err := os.Lstat(path); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		if !waitUnused(path) {
			return nil, fmt.Errorf("%s is in use by another process", path)
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return nil, err
		}
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	// The socket file is removed by Close, not by the listener.
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	return &Server{path: path, ln: ln, sem: make(chan struct{}, maxConns), peerOK: peerIsRoot,
		readTimeout: readTimeout, writeTimeout: writeTimeout}, nil
}

// waitUnused waits up to bindRetry for nobody to answer on path (the
// previous agent shutting down).
func waitUnused(path string) bool {
	deadline := time.Now().Add(bindRetry)
	for {
		c, err := net.DialTimeout("unix", path, time.Second)
		if err != nil {
			return true
		}
		c.Close()
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// Serve answers connections until Close. One request per connection.
func (s *Server) Serve(h Handler) {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("[panel] accept: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		select {
		case s.sem <- struct{}{}:
		default:
			_ = c.SetWriteDeadline(time.Now().Add(time.Second))
			writeResponse(c, Fail(ErrInternal, "agent busy, try again"))
			c.Close()
			continue
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			<-s.sem
			c.Close()
			return
		}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer func() { <-s.sem; s.wg.Done() }()
			s.handle(c, h)
		}()
	}
}

func (s *Server) handle(c net.Conn, h Handler) {
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(s.readTimeout))
	reply := func(r Response) {
		_ = c.SetWriteDeadline(time.Now().Add(s.writeTimeout))
		writeResponse(c, r)
	}
	if err := s.peerOK(c); err != nil {
		log.Printf("[panel] refused connection: %v", err)
		reply(Fail(ErrBadRequest, "only root may use the panel socket"))
		return
	}
	line, err := bufio.NewReader(io.LimitReader(c, maxRequest+1)).ReadBytes('\n')
	if len(line) > maxRequest {
		reply(Fail(ErrBadRequest, "request too large"))
		return
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return
	}
	var req Request
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		reply(Fail(ErrBadRequest, "invalid request"))
		return
	}
	if resp := Validate(&req); resp != nil {
		reply(resp)
		return
	}
	reply(safeCall(h, req))
}

// safeCall keeps a panic in a handler from taking the agent down.
func safeCall(h Handler, req Request) (resp Response) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[panel] %s failed: %v", req.Command, r)
			resp = Fail(ErrInternal, "internal error")
		}
	}()
	resp = h(req)
	if resp == nil {
		resp = Fail(ErrInternal, "no answer")
	}
	return resp
}

func writeResponse(w io.Writer, r Response) {
	_ = json.NewEncoder(w).Encode(r)
}

// Close stops listening, waits up to closeWait for requests in progress
// and removes the socket file.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	err := s.ln.Close()
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(closeWait):
		log.Printf("[panel] shutting down with requests still in progress")
	}
	if rmErr := os.Remove(s.path); rmErr != nil && !os.IsNotExist(rmErr) && err == nil {
		err = rmErr
	}
	return err
}

// Call sends req to the agent at path and returns its answer. A missing
// socket or a refused connection means the agent is not running.
func Call(path string, req Request, timeout time.Duration) (Response, error) {
	c, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		// Only a missing socket or nobody listening means the agent is not
		// running; anything else (busy, permissions) is an error.
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) {
			return nil, ErrNotRunning
		}
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	data, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if _, err := c.Write(append(data, '\n')); err != nil {
		return nil, err
	}
	var resp Response
	if err := json.NewDecoder(io.LimitReader(c, 8<<20)).Decode(&resp); err != nil {
		return nil, fmt.Errorf("reading the agent's answer: %w", err)
	}
	return resp, nil
}

// ErrNotRunning: nothing answers on the socket.
var ErrNotRunning = errors.New("agent not running")
