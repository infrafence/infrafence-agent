// Package dnswatch inspects the server's DNS traffic: every query and
// response on UDP port 53, captured read-only from a packet socket with a
// kernel filter (nothing is installed or changed on the host). It sees what
// the /proc-based DNS monitor can't (queries from unconnected sockets, the
// domain names, the answers) and reports queries to unconfigured or
// malicious resolvers, domains resolving to malicious IPs, DNS tunneling
// and DGA-style lookups, each attributed to the process that made it.
package dnswatch

import (
	"encoding/binary"
	"net"
)

// Packet is a UDP datagram to or from port 53.
type Packet struct {
	Src, Dst         net.IP
	SrcPort, DstPort uint16
	Payload          []byte
	Outgoing         bool // sent by this host (false: received)
}

// parseIP decodes an IPv4 or IPv6 packet carrying UDP (network layer first,
// as delivered by an AF_PACKET/SOCK_DGRAM socket). Fragments and IPv6
// extension headers are ignored.
func parseIP(b []byte) (Packet, bool) {
	var p Packet
	if len(b) < 1 {
		return p, false
	}
	var udp []byte
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return p, false
		}
		ihl := int(b[0]&0x0f) * 4
		if ihl < 20 || len(b) < ihl+8 || b[9] != 17 {
			return p, false
		}
		if binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 { // fragment
			return p, false
		}
		p.Src, p.Dst = net.IP(append([]byte(nil), b[12:16]...)), net.IP(append([]byte(nil), b[16:20]...))
		udp = b[ihl:]
	case 6:
		if len(b) < 48 || b[6] != 17 {
			return p, false
		}
		p.Src, p.Dst = net.IP(append([]byte(nil), b[8:24]...)), net.IP(append([]byte(nil), b[24:40]...))
		udp = b[40:]
	default:
		return p, false
	}
	p.SrcPort = binary.BigEndian.Uint16(udp[0:2])
	p.DstPort = binary.BigEndian.Uint16(udp[2:4])
	ulen := int(binary.BigEndian.Uint16(udp[4:6]))
	if ulen < 8 || ulen > len(udp) {
		ulen = len(udp)
	}
	// Copied: the capture reuses its read buffer for the next packet.
	p.Payload = append([]byte(nil), udp[8:ulen]...)
	return p, true
}
