// Package mmdbtest writes small MaxMind DB country databases (IPv4) for
// tests: the agent's unit tests and test/distro (mkmmdb).
package mmdbtest

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// Network is an IPv4 network and its country code.
type Network struct {
	CIDR    string
	Country string
}

// Anchors are the networks of the addresses the agent checks a downloaded
// database with (geoip.Check): a test database needs them to be accepted.
var Anchors = []Network{{"8.8.8.0/24", "US"}, {"193.0.6.0/24", "NL"}, {"200.160.0.0/20", "BR"}}

type node struct {
	child [2]*node
	data  int
} // data: index+1 of a country record, 0 none

// Build returns a MaxMind DB (format 2.0, record size 24, IPv4 tree) of the
// given type ("GeoLite2-Country", "DBIP-Country-Lite") holding the networks,
// each with {"country": {"iso_code": code}}. Networks must not nest.
func Build(dbType string, networks []Network, now time.Time) ([]byte, error) {
	root := &node{}
	var countries []string
	index := map[string]int{}
	for _, nw := range networks {
		_, n, err := net.ParseCIDR(nw.CIDR)
		if err != nil || n.IP.To4() == nil {
			return nil, fmt.Errorf("need an IPv4 network: %q", nw.CIDR)
		}
		bits, _ := n.Mask.Size()
		if bits < 1 {
			return nil, fmt.Errorf("prefix too short: %s", nw.CIDR)
		}
		if len(nw.Country) == 0 || len(nw.Country) > 28 {
			return nil, fmt.Errorf("bad country %q", nw.Country)
		}
		if _, ok := index[nw.Country]; !ok {
			index[nw.Country] = len(countries)
			countries = append(countries, nw.Country)
		}
		ip := n.IP.To4()
		cur := root
		for i := 0; i < bits; i++ {
			if cur.data != 0 {
				return nil, fmt.Errorf("%s is inside another network", nw.CIDR)
			}
			b := ip[i/8] >> (7 - uint(i%8)) & 1
			if cur.child[b] == nil {
				cur.child[b] = &node{}
			}
			cur = cur.child[b]
		}
		if cur.child[0] != nil || cur.child[1] != nil {
			return nil, fmt.Errorf("%s holds another network", nw.CIDR)
		}
		cur.data = index[nw.Country] + 1
	}

	// Data section: one record per country.
	var data bytes.Buffer
	offsets := make([]int, len(countries))
	for i, c := range countries {
		offsets[i] = data.Len()
		data.Write(CountryRecord(c))
	}

	// Number the inner nodes (a node with data is a record, not a node).
	var order []*node
	num := map[*node]int{}
	var walk func(n *node)
	walk = func(n *node) {
		num[n] = len(order)
		order = append(order, n)
		for _, c := range n.child {
			if c != nil && c.data == 0 {
				walk(c)
			}
		}
	}
	walk(root)
	nodeCount := uint32(len(order))
	record := func(c *node) uint32 {
		switch {
		case c == nil:
			return nodeCount // no data
		case c.data != 0:
			return nodeCount + 16 + uint32(offsets[c.data-1])
		default:
			return uint32(num[c])
		}
	}
	var tree bytes.Buffer
	for _, n := range order {
		put24(&tree, record(n.child[0]))
		put24(&tree, record(n.child[1]))
	}
	return Assemble(dbType, nodeCount, tree.Bytes(), data.Bytes(), now), nil
}

// CountryRecord is the data section record {"country": {"iso_code": cc}}.
func CountryRecord(cc string) []byte {
	var b bytes.Buffer
	mapHeader(&b, 1)
	str(&b, "country")
	mapHeader(&b, 1)
	str(&b, "iso_code")
	str(&b, cc)
	return b.Bytes()
}

// Assemble writes a database from its parts: an IPv4 search tree of
// nodeCount nodes with 24-bit records, and the data section.
func Assemble(dbType string, nodeCount uint32, tree, data []byte, now time.Time) []byte {
	var b bytes.Buffer
	b.Write(tree)
	b.Write(make([]byte, 16)) // data section separator
	b.Write(data)

	b.WriteString("\xAB\xCD\xEFMaxMind.com")
	mapHeader(&b, 9)
	str(&b, "binary_format_major_version")
	uint16v(&b, 2)
	str(&b, "binary_format_minor_version")
	uint16v(&b, 0)
	str(&b, "build_epoch")
	b.Write([]byte{0x08, 0x02}) // uint64 (extended type 9), 8 bytes
	_ = binary.Write(&b, binary.BigEndian, uint64(now.Unix()))
	str(&b, "database_type")
	str(&b, dbType)
	str(&b, "description")
	mapHeader(&b, 1)
	str(&b, "en")
	str(&b, "InfraFence test database")
	str(&b, "ip_version")
	uint16v(&b, 4)
	str(&b, "languages")
	b.Write([]byte{0x01, 0x04}) // array (extended type 11), 1 element
	str(&b, "en")
	str(&b, "node_count")
	b.Write([]byte{0xC4}) // uint32, 4 bytes
	_ = binary.Write(&b, binary.BigEndian, nodeCount)
	str(&b, "record_size")
	uint16v(&b, 24)
	return b.Bytes()
}

// Put24 appends a 24-bit record.
func Put24(b *bytes.Buffer, v uint32) { put24(b, v) }

func put24(b *bytes.Buffer, v uint32) { b.Write([]byte{byte(v >> 16), byte(v >> 8), byte(v)}) }

func mapHeader(b *bytes.Buffer, n int) { b.WriteByte(0xE0 | byte(n)) }

// str writes a UTF-8 string shorter than 29 bytes.
func str(b *bytes.Buffer, s string) {
	b.WriteByte(0x40 | byte(len(s)))
	b.WriteString(s)
}

func uint16v(b *bytes.Buffer, v uint16) {
	if v == 0 {
		b.WriteByte(0xA0)
		return
	}
	if v < 256 {
		b.Write([]byte{0xA1, byte(v)})
		return
	}
	b.Write([]byte{0xA2, byte(v >> 8), byte(v)})
}
