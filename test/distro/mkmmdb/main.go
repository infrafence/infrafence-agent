// Command mkmmdb writes a minimal GeoLite2-Country style database (IPv4,
// one network) for test/distro: the test containers have no GeoIP database,
// and country blocks need one. Usage: mkmmdb -out FILE -cidr 198.51.100.0/25
// -country XX
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

func main() {
	out := flag.String("out", "", "database file to write")
	cidr := flag.String("cidr", "", "IPv4 network of the country")
	country := flag.String("country", "XX", "ISO code of that network")
	flag.Parse()
	data, err := build(*cidr, *country, time.Now())
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		log.Fatal(err)
	}
}

// build returns a MaxMind DB (format 2.0, record size 24, IPv4 tree) whose
// only network is cidr, with {"country": {"iso_code": country}}.
func build(cidr, country string, now time.Time) ([]byte, error) {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil || n.IP.To4() == nil {
		return nil, fmt.Errorf("need an IPv4 network: %q", cidr)
	}
	bits, _ := n.Mask.Size()
	if bits < 1 {
		return nil, fmt.Errorf("prefix too short: %s", cidr)
	}
	ip := n.IP.To4()
	nodeCount := uint32(bits)
	// One node per prefix bit; the side the network takes goes deeper, the
	// other side has no data (a record equal to nodeCount). The last node
	// points at the data section: nodeCount + 16 + offset 0.
	var tree bytes.Buffer
	for i := 0; i < bits; i++ {
		next := uint32(i + 1)
		if i == bits-1 {
			next = nodeCount + 16
		}
		left, right := nodeCount, nodeCount
		if ip[i/8]>>(7-uint(i%8))&1 == 0 {
			left = next
		} else {
			right = next
		}
		put24(&tree, left)
		put24(&tree, right)
	}
	var b bytes.Buffer
	b.Write(tree.Bytes())
	b.Write(make([]byte, 16)) // data section separator
	mapHeader(&b, 1)
	str(&b, "country")
	mapHeader(&b, 1)
	str(&b, "iso_code")
	str(&b, country)

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
	str(&b, "GeoLite2-Country")
	str(&b, "description")
	mapHeader(&b, 1)
	str(&b, "en")
	str(&b, "InfraFence distro test")
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
	return b.Bytes(), nil
}

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
