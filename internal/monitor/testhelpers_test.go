package monitor

import "net"

func strPtr(s string) *string { return &s }

func mustParseIP(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		panic("bad test IP: " + s)
	}
	return ip
}
