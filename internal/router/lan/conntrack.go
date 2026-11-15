package lan

import (
	"bufio"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// Conntrack findings.
const (
	FindMinerPort = "miner_port" // connections to well-known mining-pool ports
	FindFanOut    = "fan_out"    // one device to very many hosts on one port (scanning, botnet)
	FindSMTP      = "smtp"       // a device sending mail directly to many servers (spam bot)
)

// Finding is a suspicious pattern of one LAN device.
type Finding struct {
	Kind    string
	Device  netip.Addr
	Port    int
	Count   int        // distinct remote hosts
	Example netip.Addr // one of them
}

// Stratum ports used by mining pools and nothing common in a home.
var minerPorts = map[int]bool{3333: true, 4444: true, 5555: true, 7777: true, 14433: true, 14444: true, 45560: true, 45700: true}

// Ports a device legitimately reaches on many hosts.
var commonPorts = map[int]bool{53: true, 80: true, 123: true, 443: true, 853: true, 3478: true, 5228: true, 5223: true, 8080: true, 8443: true, 19302: true}

const (
	fanOutMin = 128 // distinct hosts on one uncommon port in one conntrack pass
	smtpMin   = 20
	minerMin  = 1
	maxPairs  = 50000 // bound on the pass's memory
)

// ScanConntrack streams the conntrack table (never read whole: it can hold
// tens of thousands of entries) and returns the patterns found. isLAN says
// whether an address is a LAN device.
func ScanConntrack(path string, isLAN func(netip.Addr) bool) ([]Finding, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	return scanConntrack(f, isLAN)
}

type devPort struct {
	dev  netip.Addr
	port int
}

func scanConntrack(r io.Reader, isLAN func(netip.Addr) bool) ([]Finding, int, error) {
	hosts := map[devPort]map[netip.Addr]struct{}{}
	pairs := 0
	total := 0
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024), 4096)
	for sc.Scan() {
		total++
		// "ipv4 2 tcp 6 431999 ESTABLISHED src=.. dst=.. sport=.. dport=.. ..."
		line := sc.Text()
		var src, dst, dport string
		for _, w := range strings.Fields(line) {
			switch {
			case src == "" && strings.HasPrefix(w, "src="):
				src = w[4:]
			case dst == "" && strings.HasPrefix(w, "dst="):
				dst = w[4:]
			case dport == "" && strings.HasPrefix(w, "dport="):
				dport = w[6:]
			}
			if src != "" && dst != "" && dport != "" {
				break
			}
		}
		s, err1 := netip.ParseAddr(src)
		d, err2 := netip.ParseAddr(dst)
		port, err3 := strconv.Atoi(dport)
		if err1 != nil || err2 != nil || err3 != nil || !isLAN(s) || !public(d) {
			continue
		}
		k := devPort{s, port}
		set := hosts[k]
		if set == nil {
			if len(hosts) >= maxPairs {
				continue
			}
			set = map[netip.Addr]struct{}{}
			hosts[k] = set
		}
		if _, ok := set[d]; !ok && pairs < maxPairs {
			set[d] = struct{}{}
			pairs++
		}
	}
	if err := sc.Err(); err != nil {
		return nil, total, err
	}
	var out []Finding
	for k, set := range hosts {
		n := len(set)
		var ex netip.Addr
		for a := range set {
			if !ex.IsValid() || a.Less(ex) {
				ex = a
			}
		}
		switch {
		case minerPorts[k.port] && n >= minerMin:
			out = append(out, Finding{Kind: FindMinerPort, Device: k.dev, Port: k.port, Count: n, Example: ex})
		case k.port == 25 && n >= smtpMin:
			out = append(out, Finding{Kind: FindSMTP, Device: k.dev, Port: 25, Count: n, Example: ex})
		case !commonPorts[k.port] && n >= fanOutMin:
			out = append(out, Finding{Kind: FindFanOut, Device: k.dev, Port: k.port, Count: n, Example: ex})
		}
	}
	return out, total, nil
}

// public says whether an address is on the internet (not private, local,
// CGNAT or multicast).
func public(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() {
		return false
	}
	if a.Is4() && cgnat.Contains(a) {
		return false
	}
	return true
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// Public is exported for the agent (C2 answers, hits).
func Public(a netip.Addr) bool { return public(a) }
