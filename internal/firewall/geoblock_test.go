package firewall

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// Country sets are dropped after the allow list (protected addresses, the
// server's own public addresses, the dashboard whitelist) has returned.
func TestCountryDropsComeAfterTheAllowList(t *testing.T) {
	AddProtectedIPs("203.0.113.200")
	t.Cleanup(func() {
		protMu.Lock()
		delete(protectedIPs, "203.0.113.200")
		protMu.Unlock()
	})
	s := &fwState{
		allow: []string{"198.51.100.7", "192.0.2.0/24"},
		bans:  map[string]banEntry{},
		geo:   map[string][]string{ipsetSetName("XX"): {"198.51.100.0/24", "192.0.2.0/24", "203.0.113.0/24"}},
	}
	allow := s.allowEntries()
	for _, want := range []string{"203.0.113.200/32", "198.51.100.7/32", "192.0.2.0/24"} {
		if !slices.Contains(allow, want) {
			t.Errorf("allow entries %v lack %s", allow, want)
		}
	}

	main, _ := s.desiredRules(true)
	allowAt, geoAt := -1, -1
	for i, l := range main {
		switch {
		case strings.Contains(l, "--match-set "+allowSetName+" src -j RETURN"):
			allowAt = i
		case strings.Contains(l, "--match-set "+ipsetSetName("XX")+" src -j DROP"):
			geoAt = i
		}
	}
	if allowAt < 0 || geoAt < 0 || allowAt > geoAt {
		t.Fatalf("allow RETURN at %d, country DROP at %d:\n%s", allowAt, geoAt, strings.Join(main, "\n"))
	}
}

func TestExcludeAddrs(t *testing.T) {
	cidrs := []string{"198.51.100.0/24", "203.0.113.8/31", "192.0.2.1/32", "2001:db8::/32"}
	got, n := excludeAddrs(cidrs, []string{"198.51.100.77", "203.0.113.9", "192.0.2.1", "10.9.9.9", "::ffff:198.51.100.77", "2001:db8::1", "junk"})
	want := []string{
		"198.51.100.0/26", "198.51.100.64/29", "198.51.100.72/30", "198.51.100.76/32",
		"198.51.100.78/31", "198.51.100.80/28", "198.51.100.96/27", "198.51.100.128/25",
		"203.0.113.8/32",
		"2001:db8::/32",
	}
	if !reflect.DeepEqual(got, want) || n != 3 {
		t.Fatalf("got %v (%d excluded), want %v", got, n, want)
	}
	if got, n := excludeAddrs(cidrs, nil); !reflect.DeepEqual(got, cidrs) || n != 0 {
		t.Fatalf("no exemption changed the list: %v", got)
	}
}

func TestNetSetMax(t *testing.T) {
	for n, want := range map[int]int{0: 131072, 131072: 131072, 131073: 262144, 155176: 262144, 300000: 524288, 5000000: 524288} {
		if got := netSetMax(n); got != want {
			t.Errorf("netSetMax(%d) = %d, want %d", n, got, want)
		}
	}
}

// A country whose CIDRs cannot be read yet (no database) is logged once,
// however many syncs retry it.
func TestGeoBlockLogsAProblemOnce(t *testing.T) {
	g := NewGeoBlocker(func(string) ([]string, error) { return nil, errors.New("geoip database not loaded") }, "")
	var logged []string
	for range 3 {
		g.addCountry("XX", nil)
		logged = append(logged, g.logged["XX"])
	}
	if len(g.logged) != 1 || logged[0] == "" || logged[0] != logged[2] || g.activeCountries["XX"] {
		t.Fatalf("logged %v, active %v", g.logged, g.activeCountries)
	}
}
