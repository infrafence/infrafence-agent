//go:build linux

package scanwatch

import (
	"context"
	"errors"
	"net"
	"syscall"
	"time"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

const packetHost = 0 // PACKET_HOST: addressed to this machine

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// capture reads incoming connection attempts until ctx ends.
func capture(ctx context.Context, ready func(), fn func(src net.IP, dstPort uint16)) error {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return err
	}
	defer func() { _ = syscall.Close(fd) }()
	raw, err := bpf.Assemble(SYNFilter())
	if err != nil {
		return err
	}
	prog := make([]unix.SockFilter, len(raw))
	for i, r := range raw {
		prog[i] = unix.SockFilter{Code: r.Op, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER,
		&unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}); err != nil {
		return err
	}
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 2<<20)
	tv := syscall.NsecToTimeval(int64(time.Second))
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return err
	}
	ready()
	buf := make([]byte, 128)
	for ctx.Err() == nil {
		n, from, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR) {
				continue
			}
			return err
		}
		ll, ok := from.(*syscall.SockaddrLinklayer)
		// Only packets addressed to this server; outgoing connections the
		// server makes itself are not scans of it.
		if !ok || n <= 0 || ll.Pkttype != packetHost {
			continue
		}
		if src, port, ok := ParseSYN(buf[:n]); ok {
			fn(src, port)
		}
	}
	return nil
}
