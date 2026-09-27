package scanwatch

import (
	"encoding/binary"
	"net"
)

// ParseSYN reads the source address and destination port of a TCP SYN
// packet starting at the IP header. The kernel filter already checked the
// flags; this re-checks them so the parser is safe on its own.
func ParseSYN(b []byte) (net.IP, uint16, bool) {
	if len(b) < 1 {
		return nil, 0, false
	}
	var src net.IP
	var tcp []byte
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 || b[9] != 6 {
			return nil, 0, false
		}
		ihl := int(b[0]&0x0f) * 4
		if ihl < 20 || len(b) < ihl+14 {
			return nil, 0, false
		}
		src = net.IP(append([]byte(nil), b[12:16]...))
		tcp = b[ihl:]
	case 6:
		if len(b) < 40+14 || b[6] != 6 {
			return nil, 0, false
		}
		src = net.IP(append([]byte(nil), b[8:24]...))
		tcp = b[40:]
	default:
		return nil, 0, false
	}
	if tcp[13]&0x12 != 0x02 {
		return nil, 0, false
	}
	return src, binary.BigEndian.Uint16(tcp[2:4]), true
}
