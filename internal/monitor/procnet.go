package monitor

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

const (
	TCPEstablished = 0x01
	TCPSynRecv     = 0x02
	TCPTimeWait    = 0x06
)

type TCPConn struct {
	LocalIP    net.IP
	RemoteIP   net.IP
	LocalPort  uint16
	RemotePort uint16
	State      uint8
}

// UDPFlow is a UDP socket entry from /proc/net/udp. UDP is connectionless,
// so State reflects the kernel's internal socket state rather than a real
// connection — kept for completeness but not meaningful the way TCP's is.
type UDPFlow struct {
	LocalIP    net.IP
	RemoteIP   net.IP
	LocalPort  uint16
	RemotePort uint16
	State      uint8
}

// procNetEntry is the shared row shape of /proc/net/tcp and /proc/net/udp —
// both kernel files use the identical "sl local_address rem_address st ..."
// column layout, only the socket semantics differ.
type procNetEntry struct {
	LocalIP    net.IP
	RemoteIP   net.IP
	LocalPort  uint16
	RemotePort uint16
	State      uint8
}

// parseProcNet parses a /proc/net/{tcp,udp}-formatted file at path.
func parseProcNet(path string) ([]procNetEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	lines := strings.Split(string(data), "\n")
	var entries []procNetEntry

	for i, line := range lines {
		if i == 0 {
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		localIP, localPort, err := parseHexAddr(fields[1])
		if err != nil {
			continue
		}

		remoteIP, remotePort, err := parseHexAddr(fields[2])
		if err != nil {
			continue
		}

		state, err := strconv.ParseUint(fields[3], 16, 8)
		if err != nil {
			continue
		}

		entries = append(entries, procNetEntry{
			LocalIP:    localIP,
			RemoteIP:   remoteIP,
			LocalPort:  localPort,
			RemotePort: remotePort,
			State:      uint8(state),
		})
	}

	return entries, nil
}

// ParseProcNetTCP reads active TCP connections from /proc/net/tcp.
func ParseProcNetTCP() ([]TCPConn, error) {
	entries, err := parseProcNet("/proc/net/tcp")
	if err != nil {
		return nil, err
	}

	conns := make([]TCPConn, 0, len(entries))
	for _, e := range entries {
		conns = append(conns, TCPConn{
			LocalIP:    e.LocalIP,
			RemoteIP:   e.RemoteIP,
			LocalPort:  e.LocalPort,
			RemotePort: e.RemotePort,
			State:      e.State,
		})
	}
	return conns, nil
}

// ParseProcNetUDP reads UDP socket entries from /proc/net/udp.
func ParseProcNetUDP() ([]UDPFlow, error) {
	entries, err := parseProcNet("/proc/net/udp")
	if err != nil {
		return nil, err
	}

	flows := make([]UDPFlow, 0, len(entries))
	for _, e := range entries {
		flows = append(flows, UDPFlow{
			LocalIP:    e.LocalIP,
			RemoteIP:   e.RemoteIP,
			LocalPort:  e.LocalPort,
			RemotePort: e.RemotePort,
			State:      e.State,
		})
	}
	return flows, nil
}

func parseHexAddr(s string) (net.IP, uint16, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return nil, 0, fmt.Errorf("invalid addr: %s", s)
	}

	ipHex := parts[0]
	if len(ipHex) != 8 {
		return nil, 0, fmt.Errorf("invalid ip hex: %s", ipHex)
	}

	ipBytes, err := hex.DecodeString(ipHex)
	if err != nil {
		return nil, 0, err
	}

	// /proc/net/tcp uses little-endian for IPv4
	ip := net.IPv4(ipBytes[3], ipBytes[2], ipBytes[1], ipBytes[0])

	port, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return nil, 0, err
	}

	return ip, uint16(port), nil
}

func IsPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() {
		return true
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	if ip4[0] == 10 {
		return true
	}
	if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
		return true
	}
	if ip4[0] == 192 && ip4[1] == 168 {
		return true
	}
	return false
}
