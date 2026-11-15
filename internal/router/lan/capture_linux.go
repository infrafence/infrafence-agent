//go:build linux

package lan

import (
	"context"
	"errors"
	"net"
	"syscall"
	"time"
)

// dnsFilter is a classic BPF program run in the kernel: only UDP datagrams
// from or to port 53 (IPv4 without fragments, IPv6 without extension
// headers) are copied to the agent; everything else stays in the kernel.
// Same program as internal/dnswatch.
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
		/*  0 */ s(ldB, 0),
		/*  1 */ s(rsh, 4),
		/*  2 */ j(jeq, 4, 1, 0),
		/*  3 */ j(jeq, 6, 9, 16),
		/*  4 */ s(ldB, 9),
		/*  5 */ j(jeq, 17, 0, 14),
		/*  6 */ s(ldH, 6),
		/*  7 */ j(jset, 0x1fff, 12, 0),
		/*  8 */ s(ldxM, 0),
		/*  9 */ s(ldHi, 0),
		/* 10 */ j(jeq, 53, 8, 0),
		/* 11 */ s(ldHi, 2),
		/* 12 */ j(jeq, 53, 6, 7),
		/* 13 */ s(ldB, 6),
		/* 14 */ j(jeq, 17, 0, 5),
		/* 15 */ s(ldH, 40),
		/* 16 */ j(jeq, 53, 2, 0),
		/* 17 */ s(ldH, 42),
		/* 18 */ j(jeq, 53, 0, 1),
		/* 19 */ s(ret, 1500),
		/* 20 */ s(ret, 0),
	}
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

const packetOutgoing = 4 // PACKET_OUTGOING

// CaptureDNS reads the DNS packets crossing ifname (the LAN bridge) until
// ctx ends. Read-only: nothing is changed on the router.
func CaptureDNS(ctx context.Context, ifname string, fn func(DNSPacket)) error {
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		return err
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	if err := syscall.AttachLsf(fd, dnsFilter()); err != nil {
		return err
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(syscall.ETH_P_ALL), Ifindex: ifi.Index}); err != nil {
		return err
	}
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 256<<10)
	tv := syscall.NsecToTimeval(int64(time.Second))
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return err
	}
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
		if !ok {
			continue
		}
		if p, ok := ParseIPPacket(buf[:n]); ok {
			p.Outgoing = ll.Pkttype == packetOutgoing
			fn(p)
		}
	}
	return nil
}
