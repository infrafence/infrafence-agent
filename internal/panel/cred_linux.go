//go:build linux

package panel

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
)

// peerIsRoot reads the connecting process's credentials from the kernel
// (SO_PEERCRED): only uid 0 may use the socket.
func peerIsRoot(c net.Conn) error {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return errors.New("not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return err
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if credErr != nil {
		return credErr
	}
	if cred.Uid != 0 {
		return fmt.Errorf("peer uid %d (pid %d) is not root", cred.Uid, cred.Pid)
	}
	return nil
}

// ownedByUs refuses a socket directory another user owns (they could swap
// the socket).
func ownedByUs(st os.FileInfo) error {
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot read the owner")
	}
	if int(sys.Uid) != os.Geteuid() {
		return fmt.Errorf("owned by uid %d, not by the agent", sys.Uid)
	}
	return nil
}
