package geoip

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/oschwald/maxminddb-golang"
)

// A downloaded database is untrusted input: these checks bound the work and
// memory a crafted file can cost before and while the agent reads it.
// maxminddb-golang allocates a map or slice as large as a size field claims
// before reading its entries, and walks the search tree without noticing
// nodes shared between branches (2^32 paths from a few hundred bytes).

// maxMetadata bounds the metadata section (real ones are under 2 KB).
const maxMetadata = 64 << 10

var metadataMarker = []byte("\xAB\xCD\xEFMaxMind.com")

// checkMetadata refuses a metadata section that is too long, nested too
// deep, or whose maps, arrays and strings claim more entries or bytes than
// the section holds: maxminddb.FromBytes decodes it before anything else.
func checkMetadata(data []byte) error {
	i := bytes.LastIndex(data, metadataMarker)
	if i < 0 {
		return errors.New("no metadata")
	}
	meta := data[i+len(metadataMarker):]
	if len(meta) > maxMetadata {
		return errors.New("metadata section too large")
	}
	end, err := checkValue(meta, 0, 0)
	if err != nil {
		return err
	}
	if end > len(meta) {
		return errors.New("metadata truncated")
	}
	return nil
}

// checkValue checks the value at off and returns the offset after it.
func checkValue(b []byte, off, depth int) (int, error) {
	if depth > 32 {
		return 0, errors.New("metadata nested too deep")
	}
	if off >= len(b) {
		return 0, errors.New("metadata truncated")
	}
	ctrl := b[off]
	off++
	typ := int(ctrl >> 5)
	if typ == 1 { // pointer: its size bits say how many bytes follow; not followed
		return off + int((ctrl>>3)&3) + 1, nil
	}
	if typ == 0 { // extended type in the next byte
		if off >= len(b) {
			return 0, errors.New("metadata truncated")
		}
		typ = 7 + int(b[off])
		off++
	}
	size := int(ctrl & 0x1f)
	if size >= 29 {
		n := size - 28
		if off+n > len(b) {
			return 0, errors.New("metadata truncated")
		}
		v := 0
		for _, c := range b[off : off+n] {
			v = v<<8 | int(c)
		}
		switch size {
		case 29:
			size = 29 + v
		case 30:
			size = 285 + v
		default:
			size = 65821 + v
		}
		off += n
	}
	rest := len(b) - off
	switch typ {
	case 7: // map: at least two bytes (key and value) per entry
		if size > rest/2 {
			return 0, errors.New("metadata map larger than its section")
		}
		for range 2 * size {
			var err error
			if off, err = checkValue(b, off, depth+1); err != nil {
				return 0, err
			}
		}
		return off, nil
	case 11: // array: at least one byte per element
		if size > rest {
			return 0, errors.New("metadata array larger than its section")
		}
		for range size {
			var err error
			if off, err = checkValue(b, off, depth+1); err != nil {
				return 0, err
			}
		}
		return off, nil
	case 14: // boolean: the size is the value
		return off, nil
	default: // strings, bytes, numbers: size bytes of payload
		if size > rest {
			return 0, errors.New("metadata value larger than its section")
		}
		return off + size, nil
	}
}

// walkIPv4 calls fn for every IPv4 network of the database that has data,
// with its first and last address and the offset of its data. Each node of
// the IPv4 tree may be visited once: a tree whose branches share nodes, or
// deeper than 32 bits, is refused, so the walk costs at most NodeCount steps.
func walkIPv4(r *maxminddb.Reader, data []byte, fn func(first, last uint32, offset uintptr) error) error {
	nodeCount := uint64(r.Metadata.NodeCount)
	recordSize := uint64(r.Metadata.RecordSize)
	tree := nodeCount * recordSize / 4
	if tree > uint64(len(data)) {
		return errors.New("search tree larger than the file")
	}
	record := func(node uint64, right bool) uint64 {
		switch recordSize {
		case 24:
			b := data[node*6:]
			if right {
				b = b[3:]
			}
			return uint64(b[0])<<16 | uint64(b[1])<<8 | uint64(b[2])
		case 28:
			b := data[node*7:]
			if right {
				return uint64(b[3]&0x0F)<<24 | uint64(b[4])<<16 | uint64(b[5])<<8 | uint64(b[6])
			}
			return uint64(b[3]&0xF0)<<20 | uint64(b[0])<<16 | uint64(b[1])<<8 | uint64(b[2])
		default: // 32 (FromBytes refuses any other size)
			b := data[node*8:]
			if right {
				b = b[4:]
			}
			return uint64(b[0])<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3])
		}
	}
	leaf := func(rec uint64, first uint32, depth int) error {
		if rec == nodeCount {
			return nil // no data
		}
		if rec < nodeCount+16 {
			return errors.New("corrupt search tree")
		}
		last := first | uint32(uint64(1)<<(32-depth)-1)
		return fn(first, last, uintptr(rec-nodeCount-16))
	}

	// The IPv4 tree: the root of an IPv4 database, ::/96 in an IPv6 one.
	start := uint64(0)
	if r.Metadata.IPVersion == 6 {
		for i := 0; i < 96; i++ {
			if start >= nodeCount {
				return leaf(start, 0, 0)
			}
			start = record(start, false)
		}
	}
	if start >= nodeCount {
		return leaf(start, 0, 0)
	}

	type item struct {
		node   uint64
		prefix uint32
		depth  int
	}
	visited := make([]bool, nodeCount)
	stack := []item{{start, 0, 0}}
	for len(stack) > 0 {
		it := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if visited[it.node] {
			return errors.New("search tree branches share nodes")
		}
		visited[it.node] = true
		for side := 1; side >= 0; side-- { // left (0) first off the stack
			rec := record(it.node, side == 1)
			prefix := it.prefix | uint32(side)<<(31-it.depth)
			if rec < nodeCount {
				if it.depth+1 >= 32 {
					return errors.New("search tree deeper than 32 bits")
				}
				stack = append(stack, item{rec, prefix, it.depth + 1})
				continue
			}
			if err := leaf(rec, prefix, it.depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// countryAt decodes the country code of the data at offset, once per
// offset (a database holds one record per country).
type countryDecoder struct {
	r     *maxminddb.Reader
	cache map[uintptr]string
}

func (c *countryDecoder) at(offset uintptr) (string, error) {
	if cc, ok := c.cache[offset]; ok {
		return cc, nil
	}
	var rec countryRecord
	if err := c.r.Decode(offset, &rec); err != nil {
		return "", fmt.Errorf("corrupt data section: %w", err)
	}
	c.cache[offset] = rec.Country.ISOCode
	return rec.Country.ISOCode, nil
}
