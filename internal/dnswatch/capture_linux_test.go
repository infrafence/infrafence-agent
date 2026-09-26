//go:build linux

package dnswatch

import (
	"context"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// Real capture through the kernel filter. Needs root (CAP_NET_RAW); run in
// a container.
func TestCaptureSeesDNSOnlyIncludingUnconnectedSockets(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var (
		mu  sync.Mutex
		got []Packet
	)
	ready := make(chan struct{})
	go func() {
		err := capture(ctx, func() { close(ready) }, func(p Packet) {
			mu.Lock()
			got = append(got, p)
			mu.Unlock()
		})
		if err != nil && ctx.Err() == nil {
			t.Errorf("capture: %v", err)
		}
	}()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("capture didn't start")
	}

	// 1. Unconnected socket (sendto): invisible to /proc/net/udp's remote
	//    address, which is why the packet-level inspection exists.
	u, _ := net.ListenUDP("udp4", nil)
	u.WriteToUDP(dnsQuery("unconnected.example", typeA), &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53})
	// 2. Connected socket, IPv6.
	if c6, err := net.Dial("udp6", "[::1]:53"); err == nil {
		c6.Write(dnsQuery("ipv6.example", typeA))
		c6.Close()
	}
	// 3. Not DNS: must be dropped by the kernel filter.
	o, _ := net.Dial("udp4", "127.0.0.1:5353")
	o.Write([]byte("not dns"))

	time.Sleep(500 * time.Millisecond)
	cancel()
	u.Close()
	o.Close()

	mu.Lock()
	defer mu.Unlock()
	names := map[string]int{}
	for _, p := range got {
		if p.DstPort != 53 && p.SrcPort != 53 {
			t.Errorf("non-DNS packet passed the filter: %+v", p)
		}
		if m, ok := parseMessage(p.Payload); ok {
			names[m.Name]++
		}
	}
	if names["unconnected.example"] != 1 {
		t.Errorf("unconnected-socket query seen %d times (want exactly 1: loopback copies deduplicated); got %v", names["unconnected.example"], names)
	}
	if names["ipv6.example"] != 1 {
		t.Errorf("IPv6 query seen %d times; got %v", names["ipv6.example"], names)
	}
	for _, p := range got {
		if m, _ := parseMessage(p.Payload); m.Name == "unconnected.example" && !p.Outgoing {
			t.Errorf("query not marked as outgoing: %+v", p)
		}
	}
}

// The owner of a live UDP socket is found through the port.
func TestOwnerFinderFindsThisProcess(t *testing.T) {
	c, err := net.Dial("udp4", "127.0.0.1:53")
	if err != nil {
		t.Skip(err)
	}
	defer c.Close()
	port := uint16(c.LocalAddr().(*net.UDPAddr).Port)
	p := newOwnerFinder().Lookup(port, false)
	if p == nil || p.PID != os.Getpid() {
		t.Fatalf("owner = %+v, want pid %d", p, os.Getpid())
	}
}
