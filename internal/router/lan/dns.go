package lan

import (
	"encoding/binary"
	"net/netip"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// DNSPacket is a DNS message seen on the LAN interface.
type DNSPacket struct {
	Src, Dst         netip.Addr
	SrcPort, DstPort uint16
	Response         bool
	NXDomain         bool
	Name             string // first question, lower case, no trailing dot
	Answers          []netip.Addr
	// Outgoing: sent by the router itself (its dnsmasq answering, or a
	// reply it forwards). A LAN device can forge any source address but
	// not this.
	Outgoing bool
}

// ParseIPPacket decodes an IPv4/IPv6 UDP datagram carrying DNS (network
// header first, as an AF_PACKET/SOCK_DGRAM socket delivers it). Fragments
// and IPv6 extension headers are skipped.
func ParseIPPacket(b []byte) (DNSPacket, bool) {
	var p DNSPacket
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
		if ihl < 20 || len(b) < ihl+8 || b[9] != 17 || binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 {
			return p, false
		}
		p.Src = netip.AddrFrom4([4]byte(b[12:16]))
		p.Dst = netip.AddrFrom4([4]byte(b[16:20]))
		udp = b[ihl:]
	case 6:
		if len(b) < 48 || b[6] != 17 {
			return p, false
		}
		p.Src = netip.AddrFrom16([16]byte(b[8:24]))
		p.Dst = netip.AddrFrom16([16]byte(b[24:40]))
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
	if !parseDNS(udp[8:ulen], &p) {
		return p, false
	}
	return p, true
}

func parseDNS(msg []byte, p *DNSPacket) bool {
	var ps dnsmessage.Parser
	h, err := ps.Start(msg)
	if err != nil {
		return false
	}
	q, err := ps.Question()
	if err != nil {
		return false
	}
	p.Response = h.Response
	p.NXDomain = h.RCode == dnsmessage.RCodeNameError
	p.Name = strings.TrimSuffix(strings.ToLower(q.Name.String()), ".")
	if !h.Response {
		return true
	}
	if err := ps.SkipAllQuestions(); err != nil {
		return true
	}
	for i := 0; i < 32; i++ {
		ah, err := ps.AnswerHeader()
		if err != nil {
			break
		}
		switch ah.Type {
		case dnsmessage.TypeA:
			r, err := ps.AResource()
			if err != nil {
				return true
			}
			p.Answers = append(p.Answers, netip.AddrFrom4(r.A))
		case dnsmessage.TypeAAAA:
			r, err := ps.AAAAResource()
			if err != nil {
				return true
			}
			p.Answers = append(p.Answers, netip.AddrFrom16(r.AAAA))
		default:
			if err := ps.SkipAnswer(); err != nil {
				return true
			}
		}
	}
	return true
}

// Second-level labels under which domains are registered (co.uk, com.br...).
var secondLevel = map[string]bool{"co": true, "com": true, "net": true, "org": true, "gov": true, "ac": true, "edu": true, "or": true, "ne": true, "go": true}

// BaseDomain is the registered domain of a name: "a.b.evil.co.uk" -> "evil.co.uk".
func BaseDomain(name string) string {
	labels := strings.Split(name, ".")
	n := 2
	if len(labels) >= 3 && len(labels[len(labels)-1]) == 2 && secondLevel[labels[len(labels)-2]] {
		n = 3
	}
	if len(labels) <= n {
		return name
	}
	return strings.Join(labels[len(labels)-n:], ".")
}

// Services that legitimately use long random-looking names.
var dgaAllowlist = []string{
	"sophosxl.net", "e5.sk", "mcafee.com", "trendmicro.com", "eset.com", "kaspersky.com",
	"spamhaus.org", "spamhaus.net", "surbl.org", "uribl.com", "dnswl.org", "spamcop.net",
	"amazonaws.com", "cloudfront.net", "akamaiedge.net", "akamai.net", "edgekey.net", "azureedge.net",
	"cloudapp.net", "googleusercontent.com", "1e100.net", "in-addr.arpa", "ip6.arpa", "local", "lan", "home.arpa",
}

// RandomLooking says whether a non-existent name looks generated (DGA):
// a long first label of the registered domain made mostly of uncommon
// letter pairs.
func RandomLooking(name string) bool {
	base := BaseDomain(name)
	for _, a := range dgaAllowlist {
		if base == a || strings.HasSuffix(base, "."+a) || strings.HasSuffix(name, "."+a) {
			return false
		}
	}
	label, _, _ := strings.Cut(base, ".")
	return len(label) >= 12 && wordLikeness(label) < 0.55
}
