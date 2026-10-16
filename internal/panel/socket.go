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
	maxRequest   = 16 << 10
	connDeadline = 60 * time.Second
	maxConns     = 4
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
		if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
			c.Close()
			return nil, fmt.Errorf("%s is in use by another process", path)
		}
		if err := os.Remove(path); err != nil {
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
	return &Server{path: path, ln: ln, sem: make(chan struct{}, maxConns), peerOK: peerIsRoot}, nil
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
	_ = c.SetDeadline(time.Now().Add(connDeadline))
	if err := s.peerOK(c); err != nil {
		log.Printf("[panel] refused connection: %v", err)
		writeResponse(c, Fail(ErrBadRequest, "only root may use the panel socket"))
		return
	}
	line, err := bufio.NewReader(io.LimitReader(c, maxRequest+1)).ReadBytes('\n')
	if len(line) > maxRequest {
		writeResponse(c, Fail(ErrBadRequest, "request too large"))
		return
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return
	}
	var req Request
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeResponse(c, Fail(ErrBadRequest, "invalid request"))
		return
	}
	if resp := Validate(&req); resp != nil {
		writeResponse(c, resp)
		return
	}
	writeResponse(c, safeCall(h, req))
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

// Close stops listening, waits for requests in progress and removes the
// socket file.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	err := s.ln.Close()
	s.wg.Wait()
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
