package dnswatch

import (
	"encoding/binary"
	"net"
	"strings"
)

// Message is the part of a DNS message the inspector needs.
type Message struct {
	Response bool
	RCode    uint8 // 3 = NXDOMAIN
	Name     string
	QType    uint16
	Answers  []net.IP // A and AAAA records
}

const (
	typeA    = 1
	typeNULL = 10
	typeTXT  = 16
	typeAAAA = 28
	rcodeNX  = 3
)

// parseMessage decodes a DNS message's first question and its A/AAAA
// answers. It never reads outside b and gives up on anything malformed.
func parseMessage(b []byte) (Message, bool) {
	var m Message
	if len(b) < 12 {
		return m, false
	}
	flags := binary.BigEndian.Uint16(b[2:4])
	m.Response = flags&0x8000 != 0
	m.RCode = uint8(flags & 0x000f)
	qd := binary.BigEndian.Uint16(b[4:6])
	an := binary.BigEndian.Uint16(b[6:8])
	if qd == 0 {
		return m, false
	}
	off := 12
	name, n, ok := readName(b, off)
	if !ok || off+n+4 > len(b) {
		return m, false
	}
	m.Name = name
	off += n
	m.QType = binary.BigEndian.Uint16(b[off : off+2])
	off += 4
	// Skip any further questions.
	for i := 1; i < int(qd); i++ {
		_, n, ok := readName(b, off)
		if !ok || off+n+4 > len(b) {
			return m, true
		}
		off += n + 4
	}
	for i := 0; i < int(an) && i < 64; i++ {
		_, n, ok := readName(b, off)
		if !ok || off+n+10 > len(b) {
			break
		}
		off += n
		typ := binary.BigEndian.Uint16(b[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(b[off+8 : off+10]))
		off += 10
		if off+rdlen > len(b) {
			break
		}
		switch {
		case typ == typeA && rdlen == 4:
			m.Answers = append(m.Answers, net.IP(append([]byte(nil), b[off:off+4]...)))
		case typ == typeAAAA && rdlen == 16:
			m.Answers = append(m.Answers, net.IP(append([]byte(nil), b[off:off+16]...)))
		}
		off += rdlen
	}
	return m, true
}

// readName reads a (possibly compressed) domain name at off. It returns the
// name in lower case without the trailing dot and the number of bytes the
// name occupies at off.
func readName(b []byte, off int) (string, int, bool) {
	var labels []string
	consumed := -1
	pos, jumps, total := off, 0, 0
	for {
		if pos >= len(b) {
			return "", 0, false
		}
		l := int(b[pos])
		switch {
		case l == 0:
			if consumed < 0 {
				consumed = pos + 1 - off
			}
			return strings.ToLower(strings.Join(labels, ".")), consumed, true
		case l&0xc0 == 0xc0:
			if pos+1 >= len(b) || jumps > 16 {
				return "", 0, false
			}
			if consumed < 0 {
				consumed = pos + 2 - off
			}
			pos = int(binary.BigEndian.Uint16(b[pos:pos+2]) & 0x3fff)
			jumps++
		case l&0xc0 != 0:
			return "", 0, false
		default:
			if pos+1+l > len(b) {
				return "", 0, false
			}
			total += l + 1
			if total > 255 {
				return "", 0, false
			}
			labels = append(labels, string(b[pos+1:pos+1+l]))
			pos += 1 + l
		}
	}
}
