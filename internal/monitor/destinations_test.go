package monitor

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
)

func testLog(t *testing.T, path string, now *time.Time) *DestinationLog {
	t.Helper()
	l := &DestinationLog{path: path, days: map[string]map[int64]int{}, seen: map[string]int64{},
		now: func() time.Time { return *now }, conntrack: func() string { return "" },
		local: func() map[string]bool { return map[string]bool{"192.0.2.10": true} }}
	l.load()
	return l
}

func out(lport uint16, ip string, rport uint16) TCPConn {
	return TCPConn{LocalPort: lport, RemoteIP: mustParseIP(ip), RemotePort: rport, State: TCPEstablished}
}

// An API called every day becomes a regular destination after 3 days with
// 5 connections; inbound connections, private addresses and a connection
// seen again the same day do not count.
func TestDestinationLogRegular(t *testing.T) {
	now := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	l := testLog(t, "", &now)
	listen := TCPConn{LocalPort: 443, State: tcpListen}
	for d := 0; d < 3; d++ {
		for i := 0; i < 2; i++ {
			l.Observe([]TCPConn{listen,
				out(uint16(40000+10*d+i), "198.51.100.20", 443),
				out(uint16(40000+10*d+i), "198.51.100.20", 443), // the same socket twice
				out(443, "203.0.113.5", 51000),                  // a client of this server's 443
				out(41000, "10.0.0.9", 443),
			})
			l.Observe([]TCPConn{listen, out(uint16(40000+10*d+i), "198.51.100.20", 443)}) // still open
		}
		if d < 2 {
			if r, _, _ := l.Regular("198.51.100.20"); r {
				t.Fatalf("regular after %d day(s)", d+1)
			}
		}
		now = now.Add(24 * time.Hour)
	}
	now = now.Add(-24 * time.Hour)
	r, n, days := l.Regular("198.51.100.20")
	if !r || n != 6 || days != 3 {
		t.Fatalf("regular=%v n=%d days=%d", r, n, days)
	}
	for _, ip := range []string{"203.0.113.5", "10.0.0.9", "x"} {
		if r, _, _ := l.Regular(ip); r {
			t.Fatalf("%s regular", ip)
		}
	}
	// A week later without traffic it is no longer regular.
	now = now.Add(7 * 24 * time.Hour)
	l.Observe(nil)
	if r, _, _ := l.Regular("198.51.100.20"); r || len(l.days) != 0 {
		t.Fatalf("still regular after a week: %v", l.days)
	}
}

// A connection open for days counts once a day; TIME_WAIT is a connection
// that ended normally.
func TestDestinationLogLongConnectionAndTimeWait(t *testing.T) {
	now := time.Date(2026, 10, 20, 23, 0, 0, 0, time.UTC)
	l := testLog(t, "", &now)
	c := out(40001, "198.51.100.30", 5432)
	for d := 0; d < 3; d++ {
		l.Observe([]TCPConn{c})
		l.Observe([]TCPConn{c})
		now = now.Add(24 * time.Hour)
	}
	if _, n, days := l.Regular("198.51.100.30"); n != 3 || days != 3 {
		t.Fatalf("n=%d days=%d", n, days)
	}
	tw := out(40002, "198.51.100.31", 443)
	tw.State = TCPTimeWait
	l.Observe([]TCPConn{tw})
	if _, n, _ := l.Regular("198.51.100.31"); n != 1 {
		t.Fatalf("TIME_WAIT not counted: %d", n)
	}
}

// Containers' connections are only in conntrack; the host's own appear in
// both and count once; inbound flows (DNAT to a container) do not count.
func TestDestinationLogConntrack(t *testing.T) {
	now := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	l := testLog(t, "", &now)
	l.conntrack = func() string {
		return "ipv4     2 tcp      6 431999 ESTABLISHED src=172.18.0.5 dst=198.51.100.40 sport=50000 dport=443 src=198.51.100.40 dst=192.0.2.10 sport=443 dport=50000 [ASSURED] mark=0 use=1\n" +
			"ipv4     2 tcp      6 431999 ESTABLISHED src=192.0.2.10 dst=198.51.100.41 sport=40005 dport=443 src=198.51.100.41 dst=192.0.2.10 sport=443 dport=40005 [ASSURED] mark=0 use=1\n" +
			"ipv4     2 tcp      6 431999 ESTABLISHED src=203.0.113.9 dst=192.0.2.10 sport=50001 dport=8080 src=172.18.0.5 dst=203.0.113.9 sport=80 dport=50001 [ASSURED] mark=0 use=1\n" +
			"ipv4     2 udp      17 20 src=172.18.0.5 dst=198.51.100.42 sport=5000 dport=53 src=198.51.100.42 dst=192.0.2.10 sport=53 dport=5000 mark=0 use=1\n"
	}
	l.Observe([]TCPConn{out(40005, "198.51.100.41", 443)})
	for ip, want := range map[string]int{"198.51.100.40": 1, "198.51.100.41": 1, "203.0.113.9": 0, "198.51.100.42": 0, "192.0.2.10": 0} {
		if _, n, _ := l.Regular(ip); n != want {
			t.Errorf("%s: %d, want %d", ip, n, want)
		}
	}
}

// Saved 0600, loaded back; bounded.
func TestDestinationLogPersistAndBound(t *testing.T) {
	now := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "egress-destinations.json")
	l := testLog(t, path, &now)
	for d := 0; d < 3; d++ {
		l.Observe([]TCPConn{out(40000, "198.51.100.20", 443), out(40001, "198.51.100.20", 443)})
		now = now.Add(24 * time.Hour)
	}
	now = now.Add(-24 * time.Hour)
	l.Save()
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("saved: %v %v", st, err)
	}
	back := testLog(t, path, &now)
	if r, n, days := back.Regular("198.51.100.20"); !r || n != 6 || days != 3 {
		t.Fatalf("after load: %v %d %d", r, n, days)
	}
	conns := make([]TCPConn, 0, maxDestinations+10)
	for i := 0; i < maxDestinations+10; i++ {
		conns = append(conns, out(uint16(1024+i), "198.51."+strconv.Itoa(100+i/250)+"."+strconv.Itoa(1+i%250), 443))
	}
	now = now.Add(time.Hour)
	back.Observe(conns)
	if len(back.days) > maxDestinations {
		t.Fatalf("%d destinations kept", len(back.days))
	}
	_ = os.WriteFile(path, []byte("not json"), 0o600)
	if bad := testLog(t, path, &now); len(bad.days) != 0 {
		t.Fatal("invalid file loaded")
	}
}

// The threat match on a regular destination says so, and the direction.
func TestEgressDetectorRegularDestination(t *testing.T) {
	feed := NewThreatFeedIndex()
	feed.Update([]api.ThreatEntry{{IP: strPtr("198.51.100.20"), Source: "test-feed"}, {IP: strPtr("203.0.113.9"), Source: "test-feed"}})
	now := time.Now()
	l := testLog(t, "", &now)
	l.days["198.51.100.20"] = map[int64]int{day(now): 3, day(now) - 1: 2, day(now) - 3: 1}
	d := NewEgressDetector(feed)
	d.Destinations = l
	d.connSource = func() ([]TCPConn, error) {
		return []TCPConn{
			{LocalPort: 22, State: tcpListen},
			out(40000, "198.51.100.20", 443),
			out(22, "203.0.113.9", 51000),
		}, nil
	}
	got := map[string]map[string]string{}
	for _, ev := range d.Scan().Events {
		got[ev.SourceIP] = ev.Details
	}
	if r := got["198.51.100.20"]; r["regular_destination"] != "true" || r["regular_days"] != "3" || r["direction"] != "outbound" {
		t.Fatalf("regular: %v", r)
	}
	if r := got["203.0.113.9"]; r["regular_destination"] != "" || r["direction"] != "inbound" {
		t.Fatalf("inbound: %v", r)
	}
}
