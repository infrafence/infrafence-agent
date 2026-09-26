//go:build linux

package monitor

import (
	"net"
	"os"
	"testing"
)

// The socket owner lookup on a real /proc: a connected UDP socket of this
// test process must be traced back to it.
func TestSocketOwnersFindsThisProcess(t *testing.T) {
	conn, err := net.Dial("udp", "127.0.0.1:53")
	if err != nil {
		t.Skip(err)
	}
	defer conn.Close()
	port := uint16(conn.LocalAddr().(*net.UDPAddr).Port)

	flows, err := ParseProcNetUDP()
	if err != nil {
		t.Fatal(err)
	}
	var inode uint64
	for _, f := range flows {
		if f.LocalPort == port && f.RemotePort == 53 {
			inode = f.Inode
		}
	}
	if inode == 0 {
		t.Fatalf("socket on port %d not found in /proc/net/udp", port)
	}
	owner := socketOwners(map[uint64]bool{inode: true})[inode]
	if owner == nil || owner.PID != os.Getpid() || owner.Exe == "" {
		t.Fatalf("owner = %+v, want pid %d", owner, os.Getpid())
	}
	if d := owner.Details(); d["process"] == "" || d["pid"] == "" || d["user"] == "" {
		t.Errorf("details = %+v", d)
	}
}
