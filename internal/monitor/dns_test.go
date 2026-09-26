package monitor

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
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

// Ubuntu with systemd-resolved: /etc/resolv.conf names only the stub
// 127.0.0.53; the upstream servers are in systemd's resolv.conf. Found on a
// real server, where every normal lookup was reported as "unlisted".
func TestConfiguredResolversIncludeSystemdUpstreams(t *testing.T) {
	dir := t.TempDir()
	etc := filepath.Join(dir, "etc-resolv.conf")
	sysd := filepath.Join(dir, "systemd-resolv.conf")
	os.WriteFile(etc, []byte("nameserver 127.0.0.53\noptions edns0 trust-ad\nsearch .\n"), 0o644)
	os.WriteFile(sysd, []byte("nameserver 195.179.224.53\nnameserver 209.126.15.53\n"), 0o644)
	got := readConfiguredResolvers([]string{etc, sysd, filepath.Join(dir, "missing")})
	for _, ip := range []string{"127.0.0.53", "195.179.224.53", "209.126.15.53"} {
		if !got[ip] {
			t.Errorf("%s not configured: %v", ip, got)
		}
	}
}

func dnsFlow(ip string, inode uint64) UDPFlow {
	return UDPFlow{RemoteIP: net.ParseIP(ip), RemotePort: dnsPort, LocalPort: 40000, Inode: inode}
}

func TestSystemResolverQueriesAreNotFlagged(t *testing.T) {
	d := NewDNSDetector(NewThreatFeedIndex())
	d.configured = map[string]bool{"127.0.0.53": true}
	// unbound doing full recursion talks to many root/TLD servers.
	var flows []UDPFlow
	for i, ip := range []string{"198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13", "192.203.230.10", "192.5.5.241"} {
		flows = append(flows, dnsFlow(ip, uint64(100+i)))
	}
	d.connSource = func() ([]UDPFlow, error) { return flows, nil }
	d.owners = func(in map[uint64]bool) map[uint64]*ProcInfo {
		out := map[uint64]*ProcInfo{}
		for ino := range in {
			out[ino] = &ProcInfo{PID: 700, Name: "unbound", Exe: "/usr/sbin/unbound", User: "unbound"}
		}
		return out
	}
	if ev := d.Scan().Events; len(ev) != 0 {
		t.Fatalf("the system resolver's own queries must not be reported (unlisted or hopping): %+v", ev)
	}
}

func TestFakeSystemResolverIsFlagged(t *testing.T) {
	d := NewDNSDetector(NewThreatFeedIndex())
	d.configured = map[string]bool{"127.0.0.53": true}
	d.connSource = func() ([]UDPFlow, error) { return []UDPFlow{dnsFlow("203.0.113.53", 7)}, nil }
	d.owners = func(map[uint64]bool) map[uint64]*ProcInfo {
		// Calls itself dnsmasq but runs from /tmp.
		return map[uint64]*ProcInfo{7: {PID: 4242, Name: "dnsmasq", Exe: "/tmp/.x/dnsmasq", User: "www-data"}}
	}
	ev := d.Scan().Events
	if len(ev) != 1 || ev[0].Type != "dns_unlisted_resolver" {
		t.Fatalf("expected an unlisted-resolver event, got %+v", ev)
	}
	det := ev[0].Details
	if det["process"] != "dnsmasq" || det["pid"] != "4242" || det["exe"] != "/tmp/.x/dnsmasq" || det["user"] != "www-data" {
		t.Errorf("process details: %+v", det)
	}
	if det["configured_resolvers"] != "127.0.0.53" || det["local_port"] != "40000" {
		t.Errorf("context details: %+v", det)
	}
}

func TestThreatResolverReportedEvenFromSystemResolver(t *testing.T) {
	feed := NewThreatFeedIndex()
	feed.Update([]api.ThreatEntry{{IP: strPtr("203.0.113.66"), Source: "test-feed"}})
	d := NewDNSDetector(feed)
	d.configured = map[string]bool{"203.0.113.66": true}
	d.connSource = func() ([]UDPFlow, error) { return []UDPFlow{dnsFlow("203.0.113.66", 9)}, nil }
	d.owners = func(map[uint64]bool) map[uint64]*ProcInfo {
		return map[uint64]*ProcInfo{9: {PID: 1, Name: "systemd-resolve", Exe: "/usr/lib/systemd/systemd-resolved"}}
	}
	ev := d.Scan().Events
	if len(ev) != 1 || ev[0].Type != "dns_threat_resolver" || ev[0].Details["process"] != "systemd-resolve" {
		t.Fatalf("a threat-listed resolver must always be reported, with its process: %+v", ev)
	}
}

func TestUnknownProcessIsSaid(t *testing.T) {
	d := NewDNSDetector(NewThreatFeedIndex())
	d.configured = map[string]bool{"127.0.0.53": true}
	d.connSource = func() ([]UDPFlow, error) { return []UDPFlow{dnsFlow("203.0.113.53", 11)}, nil }
	d.owners = func(map[uint64]bool) map[uint64]*ProcInfo { return map[uint64]*ProcInfo{} }
	ev := d.Scan().Events
	if len(ev) != 1 || ev[0].Details["process"] != "unknown" || ev[0].Details["process_note"] == "" {
		t.Fatalf("expected an explicit unknown process, got %+v", ev)
	}
}

func TestIsSystemResolver(t *testing.T) {
	for _, c := range []struct {
		p    *ProcInfo
		want bool
	}{
		{&ProcInfo{Name: "systemd-resolve", Exe: "/usr/lib/systemd/systemd-resolved"}, true},
		{&ProcInfo{Name: "dnsmasq", Exe: "/usr/sbin/dnsmasq"}, true},
		{&ProcInfo{Name: "dnsmasq", Exe: "/tmp/dnsmasq"}, false},
		{&ProcInfo{Name: "dnsmasq", Exe: "/usr/sbin/dnsmasq (deleted)"}, false},
		{&ProcInfo{Name: "curl", Exe: "/usr/bin/curl"}, false},
		{&ProcInfo{Name: "unbound"}, false}, // exe unreadable: no pass
		{nil, false},
	} {
		if got := isSystemResolver(c.p); got != c.want {
			t.Errorf("isSystemResolver(%+v) = %v, want %v", c.p, got, c.want)
		}
	}
}
