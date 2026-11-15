package main

import (
	"net/netip"
	"testing"
	"time"

	"github.com/infrafence/infrafence-agent/internal/router/fw"
)

func TestCacheRoundTrip(t *testing.T) {
	now := time.Now()
	els := []fw.Element{
		{Prefix: netip.MustParsePrefix("203.0.113.7/32"), Expires: now.Add(time.Hour)},
		{Prefix: netip.MustParsePrefix("198.51.100.0/24")},
		{Prefix: netip.MustParsePrefix("192.0.2.9/32"), Expires: now.Add(-time.Minute)}, // expired by now
	}
	src := map[netip.Prefix]string{netip.MustParsePrefix("198.51.100.0/24"): "feodo"}
	back, s := fromCached(toCached(els, src), now)
	if len(back) != 2 || s[netip.MustParsePrefix("198.51.100.0/24")] != "feodo" {
		t.Errorf("round trip = %v %v", back, s)
	}
	if !back[0].Expires.Equal(els[0].Expires) {
		t.Errorf("expiry = %v", back[0].Expires)
	}
}
