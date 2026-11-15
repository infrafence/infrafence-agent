package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/router/dnsblock"
	"github.com/infrafence/infrafence-agent/internal/router/fw"
	"github.com/infrafence/infrafence-agent/internal/router/lan"
)

func testFindings(t *testing.T) (*findings, *[]api.EventRequest, *time.Time) {
	dir := t.TempDir()
	inv := lan.NewInventory([]byte("0123456789abcdef0123456789abcdef"))
	inv.Leases = filepath.Join(dir, "leases")
	inv.ARP, inv.ODHCPD = filepath.Join(dir, "none"), filepath.Join(dir, "none")
	os.WriteFile(inv.Leases, []byte("1 a4:83:e7:11:22:33 192.168.1.23 Lauras-iPhone *\n"), 0o644)
	inv.Refresh()
	now := time.Unix(1_000_000, 0)
	var sent []api.EventRequest
	f := newFindings(nil, inv, func() time.Time { return now })
	f.send = func(e []api.EventRequest) { sent = append(sent, e...) }
	return f, &sent, &now
}

func TestC2HitDedup(t *testing.T) {
	f, sent, now := testFindings(t)
	h := fw.Hit{Src: netip.MustParseAddr("192.168.1.23"), Dst: netip.MustParseAddr("192.0.2.66"), Packets: 3}
	f.c2Hit(h, "feodo", false)
	f.c2Hit(h, "feodo", false) // same packets: nothing new
	if len(*sent) != 1 {
		t.Fatalf("events = %d", len(*sent))
	}
	e := (*sent)[0]
	if e.Type != evC2 || e.Severity != "critical" || e.SourceIP != "192.0.2.66" || e.Details["action"] != "would_block" || e.Details["c2_source"] != "feodo" || e.Details["device_mac_oui"] != "A4:83:E7" {
		t.Errorf("event = %+v", e)
	}
	if _, ok := e.Details["device_name"]; ok {
		t.Error("device name sent without opt-in")
	}
	// Still sending after the cooldown: reported again, with the name now
	// that the organization opted in.
	f.setShareNames(true)
	f.setMode(fw.Full)
	*now = now.Add(2 * time.Hour)
	h.Packets = 10
	f.c2Hit(h, "feodo", false)
	if len(*sent) != 2 || (*sent)[1].Details["device_name"] != "Lauras-iPhone" || (*sent)[1].Details["action"] != "blocked" {
		t.Errorf("events = %+v", *sent)
	}
	if f.flaggedCount() != 1 {
		t.Errorf("flagged = %d", f.flaggedCount())
	}
}

func TestBlockedDomainAggregation(t *testing.T) {
	f, sent, now := testFindings(t)
	dev := netip.MustParseAddr("192.168.1.23")
	for i := 0; i < 50; i++ {
		f.listedLookup(dev, "x.evil.example.com", "evil.example.com", dnsblock.CatMalware, true)
	}
	if len(*sent) != 1 || (*sent)[0].Details["count"] != "1" || (*sent)[0].Details["window"] != "first" {
		t.Fatalf("events = %+v", *sent)
	}
	f.flush()
	if len(*sent) != 1 {
		t.Fatal("flushed before the window ended")
	}
	*now = now.Add(blockedWindow)
	f.flush()
	if len(*sent) != 2 || (*sent)[1].Details["count"] != "49" || (*sent)[1].Details["window"] != "summary" {
		t.Errorf("summary = %+v", *sent)
	}
	// A blocked lookup alone does not flag the device.
	if f.flaggedCount() != 0 {
		t.Errorf("flagged = %d", f.flaggedCount())
	}
	// A miner domain does, with its own event.
	f.listedLookup(dev, "pool.miner.example.net", "miner.example.net", dnsblock.CatMiner, false)
	types := map[string]int{}
	for _, e := range *sent {
		types[e.Type]++
	}
	if types[evMiner] != 1 || f.flaggedCount() != 1 {
		t.Errorf("types = %v flagged=%d", types, f.flaggedCount())
	}
}

func TestDGATracker(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	tr := newDGATracker(func() time.Time { return now })
	dev := netip.MustParseAddr("192.168.1.23")
	var fired bool
	for i := 0; i < dgaDistinct; i++ {
		_, _, fired = tr.add(dev, "x"+string(rune('a'+i))+"qzkvwpj.com")
	}
	if !fired {
		t.Error("threshold not reached")
	}
}

func TestBlockRule(t *testing.T) {
	ip, port, cc := "203.0.113.7", 22, "CN"
	if _, ok := blockRule(api.Rule{Type: "block", Status: "pending", Protocol: "all", IPAddress: &ip}); !ok {
		t.Error("block rule refused")
	}
	for _, r := range []api.Rule{
		{Type: "allow", Status: "pending", IPAddress: &ip},
		{Type: "block", Status: "pending", IPAddress: &ip, Port: &port},
		{Type: "block", Status: "pending", CountryCode: &cc},
		{Type: "block", Status: "removed", IPAddress: &ip},
		{Type: "block", Status: "pending", Protocol: "tcp", IPAddress: &ip},
	} {
		if _, ok := blockRule(r); ok {
			t.Errorf("rule %+v accepted", r)
		}
	}
}

func TestCheckServerURL(t *testing.T) {
	if err := checkServerURL("https://infrafence.com"); err != nil {
		t.Error(err)
	}
	for _, bad := range []string{"http://infrafence.com", "ftp://x", "https://", "https://u:p@infrafence.com", "https://infrafence.com/?x=1"} {
		if checkServerURL(bad) == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	t.Setenv("INFRAFENCE_ALLOW_HTTP", "1")
	if err := checkServerURL("http://10.0.2.2:8080"); err != nil {
		t.Error(err)
	}
}

func TestMinPositive(t *testing.T) {
	if minPositive(0, 5, 3, 0) != 3 || minPositive(0, 0) != 0 {
		t.Error("minPositive")
	}
}

func TestEventRateLimit(t *testing.T) {
	f, sent, now := testFindings(t)
	for i := 0; i < 500; i++ {
		f.emit([]api.EventRequest{event(evFWReset, "warning", "", nil, f.now())})
	}
	if len(*sent) != eventBurst {
		t.Errorf("burst: %d events", len(*sent))
	}
	*now = now.Add(time.Minute)
	for i := 0; i < 500; i++ {
		f.emit([]api.EventRequest{event(evFWReset, "warning", "", nil, f.now())})
	}
	if len(*sent) != eventBurst+eventRate {
		t.Errorf("after a minute: %d events", len(*sent))
	}
}
