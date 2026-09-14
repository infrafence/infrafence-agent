package monitor

import (
	"testing"

	"github.com/infrafence/infrafence-agent/internal/api"
)

func TestThreatFeedIndex_IPMatch(t *testing.T) {
	idx := NewThreatFeedIndex()
	idx.Update([]api.ThreatEntry{
		{IP: strPtr("203.0.113.5"), Source: "spamhaus-drop"},
	})

	bad, source := idx.Lookup(mustParseIP("203.0.113.5"))
	if !bad || source != "spamhaus-drop" {
		t.Fatalf("expected match with source spamhaus-drop, got bad=%v source=%q", bad, source)
	}

	bad, _ = idx.Lookup(mustParseIP("203.0.113.6"))
	if bad {
		t.Fatalf("expected no match for unrelated IP")
	}
}

func TestThreatFeedIndex_CIDRMatch(t *testing.T) {
	idx := NewThreatFeedIndex()
	idx.Update([]api.ThreatEntry{
		{CIDR: strPtr("198.51.100.0/24"), Source: "feodo-tracker"},
	})

	bad, source := idx.Lookup(mustParseIP("198.51.100.42"))
	if !bad || source != "feodo-tracker" {
		t.Fatalf("expected CIDR match, got bad=%v source=%q", bad, source)
	}

	bad, _ = idx.Lookup(mustParseIP("198.51.101.42"))
	if bad {
		t.Fatalf("expected no match outside CIDR range")
	}
}

func TestThreatFeedIndex_UpdateReplaces(t *testing.T) {
	idx := NewThreatFeedIndex()
	idx.Update([]api.ThreatEntry{{IP: strPtr("1.1.1.1"), Source: "old"}})
	idx.Update([]api.ThreatEntry{{IP: strPtr("2.2.2.2"), Source: "new"}})

	if bad, _ := idx.Lookup(mustParseIP("1.1.1.1")); bad {
		t.Fatalf("expected old entry to be gone after Update")
	}
	if bad, _ := idx.Lookup(mustParseIP("2.2.2.2")); !bad {
		t.Fatalf("expected new entry to be present")
	}
}

func TestThreatFeedIndex_IgnoresInvalidCIDR(t *testing.T) {
	idx := NewThreatFeedIndex()
	idx.Update([]api.ThreatEntry{{CIDR: strPtr("not-a-cidr"), Source: "bogus"}})
	if bad, _ := idx.Lookup(mustParseIP("1.2.3.4")); bad {
		t.Fatalf("invalid CIDR should not match anything")
	}
}

func TestThreatFeedIndex_EmptyIndexNoMatch(t *testing.T) {
	idx := NewThreatFeedIndex()
	if bad, _ := idx.Lookup(mustParseIP("8.8.8.8")); bad {
		t.Fatalf("empty index should never match")
	}
}
