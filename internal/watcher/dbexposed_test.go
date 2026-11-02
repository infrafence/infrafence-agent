package watcher

import (
	"net"
	"testing"

	"github.com/infrafence/infrafence-agent/internal/netstate"
)

func listenSock(ip string, port int) netstate.Conn {
	return netstate.Conn{LocalIP: net.ParseIP(ip), LocalPort: port, State: 0x0A}
}

func v4(ip string) net.IP { return net.ParseIP(ip).To4() }

func TestExposedDBPorts(t *testing.T) {
	socks := []netstate.Conn{
		{LocalIP: v4("0.0.0.0"), LocalPort: 3306, State: 0x0A},
		listenSock("::", 3306),
		{LocalIP: v4("127.0.0.1"), LocalPort: 5432, State: 0x0A},
		listenSock("::1", 5432),
		{LocalIP: v4("203.0.113.10"), LocalPort: 6379, State: 0x0A},
		{LocalIP: v4("10.0.0.5"), LocalPort: 27017, State: 0x0A},
		// An established connection to 27017 is not a listener.
		{LocalIP: v4("203.0.113.10"), LocalPort: 27017, State: 0x01},
	}
	got := exposedDBPorts(socks, true)
	if len(got) != 2 {
		t.Fatalf("got %+v", got)
	}
	if got[0].Port != 3306 || got[0].BindAddress != "0.0.0.0:3306, [::]:3306" || got[0].Warning != "MySQL/MariaDB is exposed publicly on port 3306" {
		t.Errorf("mysql: %+v", got[0])
	}
	if got[1].Port != 6379 || got[1].BindAddress != "203.0.113.10:6379" {
		t.Errorf("redis: %+v", got[1])
	}
}

func TestExposedDBPortsIPv6Only(t *testing.T) {
	// [::] alone: dual stack, exposed even without a public IPv6 address.
	got := exposedDBPorts([]netstate.Conn{listenSock("::", 5432)}, false)
	if len(got) != 1 || got[0].BindAddress != "[::]:5432" {
		t.Fatalf("got %+v", got)
	}
	// [::] next to an IPv4 loopback socket is IPv6-only: exposed only with
	// a public IPv6 address.
	socks := []netstate.Conn{{LocalIP: v4("127.0.0.1"), LocalPort: 5432, State: 0x0A}, listenSock("::", 5432)}
	if got := exposedDBPorts(socks, false); len(got) != 0 {
		t.Errorf("no public IPv6: %+v", got)
	}
	if got := exposedDBPorts(socks, true); len(got) != 1 {
		t.Errorf("public IPv6: %+v", got)
	}
	// A public IPv6 address.
	if got := exposedDBPorts([]netstate.Conn{listenSock("2001:db8:1::10", 27017)}, true); len(got) != 1 || got[0].BindAddress != "[2001:db8:1::10]:27017" {
		t.Errorf("public v6 bind: %+v", got)
	}
}
