//go:build linux

package panel

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The real peer check: root is served, any other user is refused.
func TestPeerCredentials(t *testing.T) {
	path := filepath.Join(sockDir(t), "panel.sock")
	s, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(func(Request) Response { return OK(nil) })
	defer s.Close()
	resp, err := Call(path, Request{Command: "status"}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if root := os.Geteuid() == 0; resp.Succeeded() != root {
		t.Errorf("euid %d: answer %v", os.Geteuid(), resp)
	}
}
