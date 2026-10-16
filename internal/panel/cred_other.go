//go:build !linux

package panel

import (
	"net"
	"os"
)

// The agent only runs on Linux; elsewhere (development builds) the socket's
// 0600 mode in a 0700 directory is the only check.
func peerIsRoot(net.Conn) error { return nil }

func ownedByUs(os.FileInfo) error { return nil }
