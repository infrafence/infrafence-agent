//go:build linux

package dnswatch

import (
	"context"
	"errors"
	"syscall"
	"time"
)

const packetOutgoing = 4 // PACKET_OUTGOING
const packetHost = 0     // PACKET_HOST

// dnsFilter is a classic BPF program run in the kernel: only UDP datagrams
// from or to port 53 (IPv4 without fragments, IPv6 without extension
// headers) reach the agent; everything else is dropped before copying. The
// socket delivers packets from the network header (SOCK_DGRAM).
func dnsFilter() []syscall.SockFilter {
	s := func(code uint16, k uint32) syscall.SockFilter { return *syscall.LsfStmt(int(code), int(k)) }
	j := func(code uint16, k uint32, jt, jf uint8) syscall.SockFilter {
		return *syscall.LsfJump(int(code), int(k), int(jt), int(jf))
	}
	const (
		ldB  = syscall.BPF_LD | syscall.BPF_B | syscall.BPF_ABS
		ldH  = syscall.BPF_LD | syscall.BPF_H | syscall.BPF_ABS
		ldHi = syscall.BPF_LD | syscall.BPF_H | syscall.BPF_IND
		ldxM = syscall.BPF_LDX | syscall.BPF_B | syscall.BPF_MSH
		rsh  = syscall.BPF_ALU | syscall.BPF_RSH | syscall.BPF_K
		jeq  = syscall.BPF_JMP | syscall.BPF_JEQ | syscall.BPF_K
		jset = syscall.BPF_JMP | syscall.BPF_JSET | syscall.BPF_K
		ret  = syscall.BPF_RET | syscall.BPF_K
	)
	return []syscall.SockFilter{
		/*  0 */ s(ldB, 0), // version
		/*  1 */ s(rsh, 4),
		/*  2 */ j(jeq, 4, 1, 0), // IPv4 -> 4
		/*  3 */ j(jeq, 6, 9, 16), // IPv6 -> 13, else drop
		/*  4 */ s(ldB, 9), // IPv4 protocol
		/*  5 */ j(jeq, 17, 0, 14),
		/*  6 */ s(ldH, 6), // flags + fragment offset
		/*  7 */ j(jset, 0x1fff, 12, 0), // fragment -> drop
		/*  8 */ s(ldxM, 0), // X = header length
		/*  9 */ s(ldHi, 0), // source port
		/* 10 */ j(jeq, 53, 8, 0),
		/* 11 */ s(ldHi, 2), // destination port
		/* 12 */ j(jeq, 53, 6, 7),
		/* 13 */ s(ldB, 6), // IPv6 next header
		/* 14 */ j(jeq, 17, 0, 5),
		/* 15 */ s(ldH, 40), // source port
		/* 16 */ j(jeq, 53, 2, 0),
		/* 17 */ s(ldH, 42), // destination port
		/* 18 */ j(jeq, 53, 0, 1),
		/* 19 */ s(ret, 1500), // accept
		/* 20 */ s(ret, 0), // drop
	}
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// capture reads DNS packets until ctx ends, calling fn for each one.
func capture(ctx context.Context, ready func(), fn func(p Packet)) error {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	if err := syscall.AttachLsf(fd, dnsFilter()); err != nil {
		return err
	}
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 2<<20)
	tv := syscall.NsecToTimeval(int64(time.Second))
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return err
	}
	ready()
	buf := make([]byte, 2048)
	for ctx.Err() == nil {
		n, from, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR) {
				continue
			}
			return err
		}
		ll, ok := from.(*syscall.SockaddrLinklayer)
		if !ok || n <= 0 {
			continue
		}
		p, ok := parseIP(buf[:n])
		if !ok {
			continue
		}
		// Loopback packets are seen twice (sent and received): keep the
		// sent copy only.
		if p.Src.IsLoopback() && p.Dst.IsLoopback() && ll.Pkttype == packetHost {
			continue
		}
		p.Outgoing = ll.Pkttype == packetOutgoing
		fn(p)
	}
	return nil
}
