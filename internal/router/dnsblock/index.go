package dnsblock

import (
	"hash/fnv"
	"sort"
	"strings"
)

// Category of a listed domain.
type Category uint8

const (
	CatNone Category = iota
	CatMalware
	CatC2
	CatMiner
	CatPhishing
	CatOther
)

var catNames = [...]string{"", "malware", "c2", "miner", "phishing", "other"}

func (c Category) String() string {
	if int(c) < len(catNames) {
		return catNames[c]
	}
	return "other"
}

func parseCategory(s string) Category {
	switch strings.ToLower(s) {
	case "", "malware":
		return CatMalware
	case "c2", "botnet", "cnc":
		return CatC2
	case "miner", "cryptominer", "mining":
		return CatMiner
	case "phishing":
		return CatPhishing
	default:
		return CatOther
	}
}

// Index answers "is this name (or a parent) listed, and as what" in 8 bytes
// per domain: a sorted slice of 61-bit FNV-1a hashes with the category in
// the low 3 bits. 100 000 domains cost 800 kB instead of ~8 MB of strings
// and map buckets on a 128 MB router. A false positive needs a 61-bit hash
// collision with one of the listed names.
type Index struct {
	entries []uint64
}

func hash(name string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(name))
	return h.Sum64() &^ 7
}

// indexBuilder collects entries before sorting.
type indexBuilder struct{ entries []uint64 }

func (b *indexBuilder) add(name string, c Category) {
	b.entries = append(b.entries, hash(name)|uint64(c&7))
}

func (b *indexBuilder) build() *Index {
	sort.Slice(b.entries, func(i, j int) bool { return b.entries[i] < b.entries[j] })
	// Duplicates: keep one, with the most specific category.
	out := b.entries[:0]
	for _, e := range b.entries {
		if n := len(out); n > 0 && out[n-1]&^7 == e&^7 {
			if priority(Category(e&7)) > priority(Category(out[n-1]&7)) {
				out[n-1] = e
			}
			continue
		}
		out = append(out, e)
	}
	return &Index{entries: append([]uint64(nil), out...)}
}

// priority orders categories when a domain is listed twice.
func priority(c Category) int {
	return [...]int{0, 2, 5, 4, 3, 1}[c%6]
}

func (ix *Index) Len() int {
	if ix == nil {
		return 0
	}
	return len(ix.entries)
}

func (ix *Index) find(name string) Category {
	h := hash(name)
	i := sort.Search(len(ix.entries), func(i int) bool { return ix.entries[i]&^7 >= h })
	if i < len(ix.entries) && ix.entries[i]&^7 == h {
		return Category(ix.entries[i] & 7)
	}
	return CatNone
}

// Lookup checks name and each parent domain (a listed domain blocks its
// subdomains, as dnsmasq's local=/domain/ does). It returns the listed
// domain that matched and its category.
func (ix *Index) Lookup(name string) (string, Category) {
	if ix.Len() == 0 {
		return "", CatNone
	}
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	for {
		if !strings.Contains(name, ".") {
			return "", CatNone
		}
		if c := ix.find(name); c != CatNone {
			return name, c
		}
		_, rest, _ := strings.Cut(name, ".")
		name = rest
	}
}
