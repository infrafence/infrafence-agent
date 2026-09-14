package monitor

import (
	"fmt"
	"testing"

	"github.com/infrafence/infrafence-agent/internal/api"
)

func TestDNSDetector_ThreatResolver(t *testing.T) {
	feed := NewThreatFeedIndex()
	feed.Update([]api.ThreatEntry{{IP: strPtr("203.0.113.53"), Source: "test-feed"}})

	d := NewDNSDetector(feed)
	d.configured = map[string]bool{"8.8.8.8": true}
	d.connSource = func() ([]UDPFlow, error) {
		return []UDPFlow{{RemoteIP: mustParseIP("203.0.113.53"), RemotePort: 53}}, nil
	}

	result := d.Scan()
	if len(result.Events) != 1 || result.Events[0].Type != "dns_threat_resolver" {
		t.Fatalf("expected 1 dns_threat_resolver event, got %+v", result.Events)
	}
	if result.Events[0].Severity != "critical" {
		t.Errorf("expected critical severity, got %q", result.Events[0].Severity)
	}
}

func TestDNSDetector_UnlistedResolver(t *testing.T) {
	feed := NewThreatFeedIndex()
	d := NewDNSDetector(feed)
	d.configured = map[string]bool{"8.8.8.8": true}
	d.connSource = func() ([]UDPFlow, error) {
		return []UDPFlow{{RemoteIP: mustParseIP("9.9.9.9"), RemotePort: 53}}, nil
	}

	result := d.Scan()
	if len(result.Events) != 1 || result.Events[0].Type != "dns_unlisted_resolver" {
		t.Fatalf("expected 1 dns_unlisted_resolver event, got %+v", result.Events)
	}
}

func TestDNSDetector_ConfiguredResolverIsSilent(t *testing.T) {
	feed := NewThreatFeedIndex()
	d := NewDNSDetector(feed)
	d.configured = map[string]bool{"8.8.8.8": true}
	d.connSource = func() ([]UDPFlow, error) {
		return []UDPFlow{{RemoteIP: mustParseIP("8.8.8.8"), RemotePort: 53}}, nil
	}

	result := d.Scan()
	if len(result.Events) != 0 {
		t.Fatalf("expected 0 events for configured resolver, got %+v", result.Events)
	}
}

func TestDNSDetector_UnknownConfiguredResolversSkipsUnlistedCheck(t *testing.T) {
	// When /etc/resolv.conf couldn't be read, `configured` is empty — the
	// detector must not flag every external resolver as "unlisted" in that case.
	feed := NewThreatFeedIndex()
	d := NewDNSDetector(feed)
	d.configured = map[string]bool{}
	d.connSource = func() ([]UDPFlow, error) {
		return []UDPFlow{{RemoteIP: mustParseIP("9.9.9.9"), RemotePort: 53}}, nil
	}

	result := d.Scan()
	for _, e := range result.Events {
		if e.Type == "dns_unlisted_resolver" {
			t.Fatalf("did not expect dns_unlisted_resolver when configured resolvers are unknown, got %+v", result.Events)
		}
	}
}

func TestDNSDetector_IgnoresNonDNSPortsAndPrivateIPs(t *testing.T) {
	feed := NewThreatFeedIndex()
	d := NewDNSDetector(feed)
	d.configured = map[string]bool{}
	d.connSource = func() ([]UDPFlow, error) {
		return []UDPFlow{
			{RemoteIP: mustParseIP("9.9.9.9"), RemotePort: 123}, // NTP, not DNS
			{RemoteIP: mustParseIP("10.0.0.1"), RemotePort: 53}, // private, skipped
		}, nil
	}

	result := d.Scan()
	if len(result.Events) != 0 {
		t.Fatalf("expected 0 events, got %+v", result.Events)
	}
}

func TestDNSDetector_ResolverHopping(t *testing.T) {
	feed := NewThreatFeedIndex()
	d := NewDNSDetector(feed)
	d.configured = map[string]bool{}

	flows := make([]UDPFlow, 0, dnsHopThreshold)
	for i := 0; i < dnsHopThreshold; i++ {
		flows = append(flows, UDPFlow{RemoteIP: mustParseIP(fmt.Sprintf("198.51.100.%d", i+1)), RemotePort: 53})
	}
	d.connSource = func() ([]UDPFlow, error) { return flows, nil }

	result := d.Scan()

	found := false
	for _, e := range result.Events {
		if e.Type == "dns_resolver_hopping" {
			found = true
			if e.Details["distinct_resolvers"] != fmt.Sprintf("%d", dnsHopThreshold) {
				t.Errorf("unexpected distinct_resolvers detail: %+v", e.Details)
			}
		}
	}
	if !found {
		t.Fatalf("expected dns_resolver_hopping event, got %+v", result.Events)
	}
}

func TestDNSDetector_BelowHoppingThresholdNoAlert(t *testing.T) {
	feed := NewThreatFeedIndex()
	d := NewDNSDetector(feed)
	d.configured = map[string]bool{}

	flows := make([]UDPFlow, 0, dnsHopThreshold-1)
	for i := 0; i < dnsHopThreshold-1; i++ {
		flows = append(flows, UDPFlow{RemoteIP: mustParseIP(fmt.Sprintf("198.51.100.%d", i+1)), RemotePort: 53})
	}
	d.connSource = func() ([]UDPFlow, error) { return flows, nil }

	result := d.Scan()
	for _, e := range result.Events {
		if e.Type == "dns_resolver_hopping" {
			t.Fatalf("did not expect resolver_hopping below threshold, got %+v", result.Events)
		}
	}
}
