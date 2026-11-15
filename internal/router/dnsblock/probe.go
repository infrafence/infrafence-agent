package dnsblock

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// queryLocal sends one A query for name to 127.0.0.1:53 and says whether
// the answer is NXDOMAIN.
func queryLocal(name string) (bool, error) {
	var idb [2]byte
	_, _ = rand.Read(idb[:])
	id := binary.BigEndian.Uint16(idb[:])
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		return false, err
	}
	n, err := dnsmessage.NewName(name + ".")
	if err != nil {
		return false, err
	}
	if err := b.Question(dnsmessage.Question{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		return false, err
	}
	msg, err := b.Finish()
	if err != nil {
		return false, err
	}
	c, err := net.DialTimeout("udp", "127.0.0.1:53", 2*time.Second)
	if err != nil {
		return false, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write(msg); err != nil {
		return false, err
	}
	buf := make([]byte, 1500)
	for {
		k, err := c.Read(buf)
		if err != nil {
			return false, err
		}
		var p dnsmessage.Parser
		h, err := p.Start(buf[:k])
		if err != nil || h.ID != id || !h.Response {
			continue
		}
		if h.RCode == dnsmessage.RCodeServerFailure || h.RCode == dnsmessage.RCodeRefused {
			return false, errors.New("dnsmasq answered " + h.RCode.String())
		}
		return h.RCode == dnsmessage.RCodeNameError, nil
	}
}
