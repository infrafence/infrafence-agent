package monitor

import (
	"testing"

	"github.com/infrafence/infrafence-agent/internal/api"
)

func TestEgressDetector_FlagsThreatMatch(t *testing.T) {
	feed := NewThreatFeedIndex()
	feed.Update([]api.ThreatEntry{{IP: strPtr("203.0.113.9"), Source: "test-feed"}})

	d := NewEgressDetector(feed)
	d.connSource = func() ([]TCPConn, error) {
		return []TCPConn{
			{RemoteIP: mustParseIP("203.0.113.9"), RemotePort: 4444, LocalPort: 51000, State: TCPEstablished},
			{RemoteIP: mustParseIP("1.2.3.4"), RemotePort: 443, LocalPort: 51001, State: TCPEstablished},
		}, nil
	}

	result := d.Scan()
	if len(result.Events) != 1 {
		t.Fatalf("expected 1 event, got %d: %+v", len(result.Events), result.Events)
	}
	ev := result.Events[0]
	if ev.SourceIP != "203.0.113.9" || ev.Severity != "critical" || ev.Type != "egress_threat_match" {
		t.Errorf("unexpected event: %+v", ev)
	}
	if ev.Details["threat_source"] != "test-feed" {
		t.Errorf("expected threat_source detail, got %+v", ev.Details)
	}
}

func TestEgressDetector_IgnoresPrivateAndNonEstablished(t *testing.T) {
	feed := NewThreatFeedIndex()
	feed.Update([]api.ThreatEntry{
		{IP: strPtr("10.0.0.5"), Source: "test-feed"},
		{IP: strPtr("203.0.113.9"), Source: "test-feed"},
	})

	d := NewEgressDetector(feed)
	d.connSource = func() ([]TCPConn, error) {
		return []TCPConn{
			{RemoteIP: mustParseIP("10.0.0.5"), State: TCPEstablished}, // private, skipped despite feed match
			{RemoteIP: mustParseIP("203.0.113.9"), State: TCPSynRecv},  // not established
		}, nil
	}

	result := d.Scan()
	if len(result.Events) != 0 {
		t.Fatalf("expected 0 events, got %d: %+v", len(result.Events), result.Events)
	}
}

func TestEgressDetector_Cooldown(t *testing.T) {
	feed := NewThreatFeedIndex()
	feed.Update([]api.ThreatEntry{{IP: strPtr("203.0.113.9"), Source: "test-feed"}})

	d := NewEgressDetector(feed)
	d.connSource = func() ([]TCPConn, error) {
		return []TCPConn{{RemoteIP: mustParseIP("203.0.113.9"), State: TCPEstablished}}, nil
	}

	first := d.Scan()
	second := d.Scan()
	if len(first.Events) != 1 {
		t.Fatalf("expected first scan to report 1 event, got %d", len(first.Events))
	}
	if len(second.Events) != 0 {
		t.Fatalf("expected second scan (cooldown) to report 0 events, got %d", len(second.Events))
	}
}

func TestEgressDetector_NoFeedMatchNoEvents(t *testing.T) {
	feed := NewThreatFeedIndex() // empty feed
	d := NewEgressDetector(feed)
	d.connSource = func() ([]TCPConn, error) {
		return []TCPConn{{RemoteIP: mustParseIP("203.0.113.9"), State: TCPEstablished}}, nil
	}

	result := d.Scan()
	if len(result.Events) != 0 {
		t.Fatalf("expected 0 events with empty feed, got %d", len(result.Events))
	}
}
