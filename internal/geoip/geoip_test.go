package geoip

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/infrafence/infrafence-agent/internal/geoip/mmdbtest"
)

// testDB writes a database with the anchors and networks to dir/name.
func testDB(t testing.TB, dir, name, dbType string, networks ...mmdbtest.Network) string {
	t.Helper()
	data, err := mmdbtest.Build(dbType, append(networks, mmdbtest.Anchors...), time.Unix(1760000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNewPrefersTheDownloadedDatabase(t *testing.T) {
	dir := t.TempDir()
	newPath := filepath.Join(dir, "geoip-country.mmdb")
	legacy := testDB(t, dir, "GeoLite2-Country.mmdb", "GeoLite2-Country", mmdbtest.Network{CIDR: "198.51.100.0/24", Country: "XX"})
	old := searchPaths
	searchPaths = []string{newPath, legacy}
	t.Cleanup(func() { searchPaths = old })

	// Only the legacy file: it is used.
	if l := New(""); l.Path() != legacy || l.Country("198.51.100.1") != "XX" {
		t.Fatalf("legacy only: path %q, country %q", l.Path(), l.Country("198.51.100.1"))
	}
	// A file at the new path that is not a database: the legacy one.
	if err := os.WriteFile(newPath, []byte("not a database"), 0o644); err != nil {
		t.Fatal(err)
	}
	if l := New(""); l.Path() != legacy {
		t.Fatalf("broken new file: path %q", l.Path())
	}
	// Both: the downloaded one.
	testDB(t, dir, "geoip-country.mmdb", "DBIP-Country-Lite", mmdbtest.Network{CIDR: "198.51.100.0/24", Country: "YY"})
	if l := New(""); l.Path() != newPath || l.Country("198.51.100.1") != "YY" {
		t.Fatalf("both: path %q, country %q", l.Path(), l.Country("198.51.100.1"))
	}
	// Neither: no database, no country, no CIDRs.
	searchPaths = []string{filepath.Join(dir, "a"), filepath.Join(dir, "b")}
	l := New("")
	if l.Path() != "" || l.Country("8.8.8.8") != "" {
		t.Fatal("a database was loaded from nowhere")
	}
	if _, err := l.ExtractCIDRs("US"); err == nil {
		t.Fatal("ExtractCIDRs without a database")
	}
}

func TestOpenRefusesWhatIsNotACountryDatabase(t *testing.T) {
	dir := t.TempDir()
	city := testDB(t, dir, "city.mmdb", "GeoLite2-City")
	if _, err := Open(city); err == nil {
		t.Error("a city database was accepted")
	}
	junk := filepath.Join(dir, "junk.mmdb")
	_ = os.WriteFile(junk, []byte("\x00\x01junk"), 0o644)
	if _, err := Open(junk); err == nil {
		t.Error("junk was accepted")
	}
	if _, err := Open(dir); err == nil {
		t.Error("a directory was accepted")
	}
}

func TestCheckAnchors(t *testing.T) {
	good, _ := mmdbtest.Build("DBIP-Country-Lite", mmdbtest.Anchors, time.Now())
	if _, err := Check(good); err != nil {
		t.Fatalf("good database: %v", err)
	}
	wrong := []mmdbtest.Network{{CIDR: "8.8.8.0/24", Country: "RU"}, mmdbtest.Anchors[1], mmdbtest.Anchors[2]}
	bad, _ := mmdbtest.Build("DBIP-Country-Lite", wrong, time.Now())
	if _, err := Check(bad); err == nil {
		t.Fatal("a database placing 8.8.8.8 in RU was accepted")
	}
	if _, err := Check(good[:len(good)/2]); err == nil {
		t.Fatal("a truncated database was accepted")
	}
}

func TestExtractCIDRsMergesAndIsCachedPerDatabase(t *testing.T) {
	dir := t.TempDir()
	path := testDB(t, dir, "a.mmdb", "DBIP-Country-Lite",
		mmdbtest.Network{CIDR: "198.51.100.0/25", Country: "XX"},
		mmdbtest.Network{CIDR: "198.51.100.128/25", Country: "XX"},
		mmdbtest.Network{CIDR: "203.0.113.8/29", Country: "XX"},
		mmdbtest.Network{CIDR: "203.0.113.16/29", Country: "YY"})
	l := New(path)
	got, err := l.ExtractCIDRs(" xx ")
	if want := []string{"198.51.100.0/24", "203.0.113.8/29"}; err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("XX = %v, %v; want %v", got, err, want)
	}
	if got, _ := l.ExtractCIDRs("ZZ"); len(got) != 0 {
		t.Fatalf("ZZ = %v", got)
	}

	// A new database: the CIDRs come from it, not from the cache.
	path2 := testDB(t, dir, "b.mmdb", "DBIP-Country-Lite", mmdbtest.Network{CIDR: "192.0.2.0/24", Country: "XX"})
	r, err := Open(path2)
	if err != nil {
		t.Fatal(err)
	}
	l.Replace(r, path2)
	if got, _ := l.ExtractCIDRs("XX"); !reflect.DeepEqual(got, []string{"192.0.2.0/24"}) {
		t.Fatalf("after Replace: %v", got)
	}
}

func TestRangesToCIDRs(t *testing.T) {
	ip := func(a, b, c, d uint32) uint32 { return a<<24 | b<<16 | c<<8 | d }
	cases := []struct {
		in   []v4range
		want []string
	}{
		{[]v4range{{ip(1, 0, 0, 1), ip(1, 0, 0, 6)}}, []string{"1.0.0.1/32", "1.0.0.2/31", "1.0.0.4/31", "1.0.0.6/32"}},
		{[]v4range{{0, 0xFFFFFFFF}}, []string{"0.0.0.0/0"}},
		{[]v4range{{ip(255, 255, 255, 255), ip(255, 255, 255, 255)}}, []string{"255.255.255.255/32"}},
		// Overlapping, touching and unsorted ranges merge.
		{[]v4range{{ip(10, 0, 1, 0), ip(10, 0, 1, 255)}, {ip(10, 0, 0, 0), ip(10, 0, 0, 255)}, {ip(10, 0, 0, 128), ip(10, 0, 1, 10)}}, []string{"10.0.0.0/23"}},
	}
	if _, ok := rangesToCIDRs([]v4range{{ip(1, 0, 0, 1), ip(1, 0, 0, 6)}}, 3); ok {
		t.Error("4 CIDRs passed a limit of 3")
	}
	for _, c := range cases {
		if got, ok := rangesToCIDRs(mergeRanges(c.in), 100); !ok || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%v: got %v, want %v", c.in, got, c.want)
		}
	}
}

func TestSetBlocked(t *testing.T) {
	dir := t.TempDir()
	l := New(testDB(t, dir, "a.mmdb", "DBIP-Country-Lite"))
	l.SetBlocked([]string{"NL"})
	if cc, ok := l.IsBlocked("193.0.6.139"); cc != "NL" || !ok {
		t.Fatalf("IsBlocked = %q %v", cc, ok)
	}
	if _, ok := l.IsBlocked("8.8.8.8"); ok {
		t.Fatal("US is not blocked")
	}
	l.SetBlocked(nil)
	if _, ok := l.IsBlocked("193.0.6.139"); ok {
		t.Fatal("NL is no longer blocked")
	}
}

// GEOIP_BENCH_DB=/path/to/dbip-country-lite.mmdb go test -bench . -benchmem ./internal/geoip
// measures the walk for the largest country.
func BenchmarkExtractCIDRsUS(b *testing.B) {
	path := os.Getenv("GEOIP_BENCH_DB")
	if path == "" {
		b.Skip("GEOIP_BENCH_DB not set")
	}
	r, err := Open(path)
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		l := &Lookup{blocked: map[string]bool{}}
		l.Replace(r, path)
		cidrs, err := l.ExtractCIDRs("US")
		if err != nil || len(cidrs) == 0 {
			b.Fatal(len(cidrs), err)
		}
	}
}
