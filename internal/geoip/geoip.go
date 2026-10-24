package geoip

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/bits"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/oschwald/maxminddb-golang"
)

// DefaultPath is where the agent keeps the country database it downloads
// from the dashboard (DB-IP "IP to Country Lite", CC BY 4.0; see update.go).
const DefaultPath = "/etc/infrafence/geoip-country.mmdb"

// LegacyPath is the MaxMind GeoLite2 file earlier versions looked for. It is
// still read when the downloaded database is not there.
const LegacyPath = "/etc/infrafence/GeoLite2-Country.mmdb"

// searchPaths are the files New reads when given no path, in order.
var searchPaths = []string{DefaultPath, LegacyPath}

// MaxSize bounds a database file the agent reads or downloads (the country
// databases are 5-10 MB).
const MaxSize = 32 << 20

// MaxCIDRs bounds the networks of one country (the United States, the
// largest, has about 155,000 in DB-IP): more is refused, not loaded.
const MaxCIDRs = 500000

// Lookup provides country code lookups from a country database (DB-IP or
// MaxMind GeoLite2, both in the MaxMind DB format).
type Lookup struct {
	mu      sync.RWMutex
	blocked map[string]bool // country codes that are blocked

	// cur is the database in use (nil: none). Replace swaps it whole: the
	// file is held in memory (not mapped), so a lookup still running on
	// the previous database finishes on it safely.
	cur atomic.Pointer[database]
}

type database struct {
	r    *maxminddb.Reader
	data []byte // the file, which r reads too
	path string

	mu        sync.Mutex
	cidrCache map[string][]string // CIDRs per country code, extracted once per database
}

type countryRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

// New creates a Lookup from dbPath or, when dbPath is "", from DefaultPath
// and else LegacyPath. Without a database lookups return "" until Replace
// installs one.
func New(dbPath string) *Lookup {
	l := &Lookup{blocked: make(map[string]bool)}
	paths := []string{dbPath}
	if dbPath == "" {
		paths = searchPaths
	}
	for _, p := range paths {
		r, err := Open(p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			log.Printf("[geoip] cannot use %s: %v", p, err)
			continue
		}
		l.Replace(r, p)
		return l
	}
	log.Printf("[geoip] no country database at %s — country blocking waits for one", strings.Join(paths, " or "))
	return l
}

// Open reads the database at path into memory: a MaxMind DB file of at
// most MaxSize whose type names countries. A file the operator installed
// (GEOIP_DB_PATH, LegacyPath) is taken as it is; Check is for downloads.
func Open(path string) (*DB, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}
	return parse(data)
}

func readFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > MaxSize {
		return nil, fmt.Errorf("not a regular file of at most %d MB", MaxSize>>20)
	}
	data := make([]byte, st.Size())
	if _, err := io.ReadFull(f, data); err != nil {
		return nil, err
	}
	return data, nil
}

// DB is a country database read into memory.
type DB struct {
	r    *maxminddb.Reader
	data []byte
}

func parse(data []byte) (*DB, error) {
	if err := checkMetadata(data); err != nil {
		return nil, fmt.Errorf("not a MaxMind DB file: %w", err)
	}
	r, err := maxminddb.FromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("not a MaxMind DB file: %w", err)
	}
	if !strings.Contains(strings.ToLower(r.Metadata.DatabaseType), "country") {
		return nil, fmt.Errorf("not a country database (%q)", r.Metadata.DatabaseType)
	}
	return &DB{r: r, data: data}, nil
}

// anchors are addresses whose country has not changed in decades (Google
// public DNS, RIPE NCC, NIC.br): a database that places them elsewhere is
// not a usable country database.
var anchors = map[string]string{"8.8.8.8": "US", "193.0.6.139": "NL", "200.160.2.3": "BR"}

// Check parses a downloaded database: what Open requires, a walk of the
// whole IPv4 tree decoding every country record (bounded: see walkIPv4),
// and the anchor addresses. maxminddb's own Verify is not used: it decodes
// into maps sized by the file and walks shared nodes without end.
func Check(data []byte) (*DB, error) {
	db, err := parse(data)
	if err != nil {
		return nil, err
	}
	dec := &countryDecoder{r: db.r, cache: map[uintptr]string{}}
	if err := walkIPv4(db.r, data, func(_, _ uint32, off uintptr) error {
		_, err := dec.at(off)
		return err
	}); err != nil {
		return nil, fmt.Errorf("corrupt database: %w", err)
	}
	for ip, want := range anchors {
		var rec countryRecord
		if err := db.r.Lookup(net.ParseIP(ip), &rec); err != nil || rec.Country.ISOCode != want {
			return nil, fmt.Errorf("%s resolves to %q, not %s", ip, rec.Country.ISOCode, want)
		}
	}
	return db, nil
}

// Replace makes db (read from path) the database in use. CIDRs extracted
// from the previous one are dropped.
func (l *Lookup) Replace(db *DB, path string) {
	l.cur.Store(&database{r: db.r, data: db.data, path: path, cidrCache: map[string][]string{}})
	log.Printf("[geoip] loaded %s from %s", db.r.Metadata.DatabaseType, path)
}

// Path returns the file of the database in use ("" when there is none).
func (l *Lookup) Path() string {
	if d := l.cur.Load(); d != nil {
		return d.path
	}
	return ""
}

// Close drops the database (lookups return "" afterwards).
func (l *Lookup) Close() {
	l.cur.Store(nil)
}

// Country returns the ISO 3166-1 alpha-2 country code for an IP, or "".
func (l *Lookup) Country(ipStr string) string {
	d := l.cur.Load()
	if d == nil {
		return ""
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}

	var record countryRecord
	if err := d.r.Lookup(ip, &record); err != nil {
		return ""
	}

	return record.Country.ISOCode
}

// SetBlocked replaces the set of blocked country codes. Every sync calls it;
// it logs only a change.
func (l *Lookup) SetBlocked(codes []string) {
	next := make(map[string]bool, len(codes))
	for _, c := range codes {
		next[strings.ToUpper(strings.TrimSpace(c))] = true
	}
	l.mu.Lock()
	same := len(next) == len(l.blocked)
	for c := range next {
		same = same && l.blocked[c]
	}
	l.blocked = next
	l.mu.Unlock()

	if !same {
		log.Printf("[geoip] blocking %d countries: %v", len(codes), codes)
	}
}

// IsBlocked returns true if the given IP belongs to a blocked country.
// Returns the country code and blocked status.
func (l *Lookup) IsBlocked(ipStr string) (string, bool) {
	cc := l.Country(ipStr)
	if cc == "" {
		return "", false
	}

	l.mu.RLock()
	defer l.mu.RUnlock()

	return cc, l.blocked[cc]
}

// ExtractCIDRs returns the IPv4 networks of the given country code, merged
// into the fewest CIDRs (ipset hash:net sets are IPv4 here and hold at most
// 131072 entries). Results are cached per database: the IPv4 tree is walked
// once per country.
func (l *Lookup) ExtractCIDRs(countryCode string) ([]string, error) {
	d := l.cur.Load()
	if d == nil {
		return nil, fmt.Errorf("geoip database not loaded")
	}

	countryCode = strings.ToUpper(strings.TrimSpace(countryCode))
	if countryCode == "" {
		return nil, fmt.Errorf("empty country code")
	}

	// One walk at a time: two at once would double the memory it takes.
	d.mu.Lock()
	defer d.mu.Unlock()
	if cached, ok := d.cidrCache[countryCode]; ok {
		return cached, nil
	}

	var ranges []v4range
	dec := &countryDecoder{r: d.r, cache: map[uintptr]string{}}
	err := walkIPv4(d.r, d.data, func(first, last uint32, off uintptr) error {
		cc, err := dec.at(off)
		if err == nil && cc == countryCode {
			if len(ranges) >= 2*MaxCIDRs {
				return fmt.Errorf("more than %d networks for %s", 2*MaxCIDRs, countryCode)
			}
			ranges = append(ranges, v4range{first, last})
		}
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("network iteration error: %w", err)
	}

	cidrs, ok := rangesToCIDRs(mergeRanges(ranges), MaxCIDRs)
	if !ok {
		return nil, fmt.Errorf("more than %d networks for %s: database refused", MaxCIDRs, countryCode)
	}
	d.cidrCache[countryCode] = cidrs
	log.Printf("[geoip] %s: %d IPv4 networks", countryCode, len(cidrs))
	return cidrs, nil
}

// v4range is an inclusive range of IPv4 addresses.
type v4range struct{ first, last uint32 }

// mergeRanges sorts ranges and joins those that overlap or touch.
func mergeRanges(in []v4range) []v4range {
	sort.Slice(in, func(i, j int) bool { return in[i].first < in[j].first })
	var out []v4range
	for _, r := range in {
		if n := len(out); n > 0 && uint64(r.first) <= uint64(out[n-1].last)+1 {
			out[n-1].last = max(out[n-1].last, r.last)
			continue
		}
		out = append(out, r)
	}
	return out
}

// rangesToCIDRs covers each range with the fewest CIDRs; ok is false when
// that takes more than limit.
func rangesToCIDRs(ranges []v4range, limit int) (out []string, ok bool) {
	for _, r := range ranges {
		cur, end := uint64(r.first), uint64(r.last)
		for cur <= end {
			// The largest block aligned on cur that ends within the range.
			size := 32
			if cur != 0 {
				size = min(bits.TrailingZeros64(cur), 32)
			}
			for cur+(uint64(1)<<size)-1 > end {
				size--
			}
			if len(out) >= limit {
				return nil, false
			}
			ip := make(net.IP, 4)
			binary.BigEndian.PutUint32(ip, uint32(cur))
			out = append(out, fmt.Sprintf("%s/%d", ip, 32-size))
			cur += uint64(1) << size
		}
	}
	return out, true
}
