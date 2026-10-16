package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/infrafence/infrafence-agent/internal/geoip"
)

// The agent's own reader finds the country and its network.
func TestDatabaseReadsBack(t *testing.T) {
	data, err := build("198.51.100.0/25", "XX", time.Unix(1760000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "GeoLite2-Country.mmdb")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	l := geoip.New(path)
	defer l.Close()
	for ip, want := range map[string]string{"198.51.100.3": "XX", "198.51.100.127": "XX", "198.51.100.200": "", "203.0.113.1": ""} {
		if got := l.Country(ip); got != want {
			t.Errorf("Country(%s) = %q, want %q", ip, got, want)
		}
	}
	cidrs, err := l.ExtractCIDRs("XX")
	if err != nil || !reflect.DeepEqual(cidrs, []string{"198.51.100.0/25"}) {
		t.Fatalf("ExtractCIDRs = %v, %v", cidrs, err)
	}
}
