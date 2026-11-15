package main

import (
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/infrafence/infrafence-agent/internal/router/fw"
	"github.com/infrafence/infrafence-agent/internal/router/sysinfo"
	"github.com/infrafence/infrafence-agent/internal/router/uci"
)

// settings are the router owner's choices in /etc/config/infrafence (UCI,
// editable from LuCI). The agent token is not here: UCI is readable
// through rpcd, the token lives in /etc/infrafence/config.json (0600).
type settings struct {
	ServerURL   string
	DNSCapture  bool   // read DNS packets on the LAN bridge
	DNSBlocking bool   // enforce the domain list through dnsmasq (Full protection only)
	LANIf       string // the LAN bridge ("" = detect)
	MaxBans     int    // 0 = from RAM
	MaxDomains  int
	// DeviceNames: "dashboard" (send DHCP names when the organization opted
	// in) or "never".
	DeviceNames string
}

func loadSettings() settings {
	m := uci.Show("infrafence")
	get := func(k, def string) string {
		if v, ok := m["infrafence.main."+k]; ok && v != "" {
			return v
		}
		return def
	}
	atoi := func(s string) int {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			return 0
		}
		return n
	}
	s := settings{
		ServerURL:   strings.TrimRight(get("server_url", defaultURL), "/"),
		DNSCapture:  get("dns_capture", "1") == "1",
		DNSBlocking: get("dns_blocking", "1") == "1",
		LANIf:       get("lan_interface", ""),
		MaxBans:     atoi(get("max_bans", "0")),
		MaxDomains:  atoi(get("max_domains", "0")),
		DeviceNames: get("device_names", "dashboard"),
	}
	if s.DeviceNames != "never" {
		s.DeviceNames = "dashboard"
	}
	return s
}

// minPositive is the smallest of the values above zero (0 if none).
func minPositive(vs ...int) int {
	out := 0
	for _, v := range vs {
		if v > 0 && (out == 0 || v < out) {
			out = v
		}
	}
	return out
}

// lanInterface is the LAN bridge: the setting, else br-lan, else UCI's
// network.lan.device.
func lanInterface(s settings) string {
	if s.LANIf != "" {
		return s.LANIf
	}
	if _, err := net.InterfaceByName("br-lan"); err == nil {
		return "br-lan"
	}
	m := uci.Show("network")
	for _, k := range []string{"network.lan.device", "network.lan.ifname"} {
		if v := strings.Fields(m[k]); len(v) > 0 {
			if _, err := net.InterfaceByName(v[0]); err == nil {
				return v[0]
			}
		}
	}
	return ""
}

// lanPrefixes are the LAN interface's networks: devices are addresses in
// them.
func lanPrefixes(ifname string) []netip.Prefix {
	var out []netip.Prefix
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil
	}
	addrs, _ := ifi.Addrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			ones, _ := n.Mask.Size()
			if ip, ok := netip.AddrFromSlice(n.IP); ok {
				out = append(out, netip.PrefixFrom(ip.Unmap(), ones).Masked())
			}
		}
	}
	return out
}

// primaryAddress is the router's first global address (WAN), else its
// first non-loopback IPv4.
func primaryAddress() string {
	addrs, _ := net.InterfaceAddrs()
	var fallback string
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		if ip.Is4() && fallback == "" {
			fallback = ip.String()
		}
		if ip.IsGlobalUnicast() && !ip.IsPrivate() && ip.Is4() {
			return ip.String()
		}
	}
	return fallback
}

// chooseBackend picks the firewall backend: nftables with fw4 (22.03+),
// iptables + ipset with fw3, plain nftables otherwise; nil when neither is
// usable (detect only).
func chooseBackend(info sysinfo.Info) fw.Backend {
	switch {
	case info.Firewall == "fw4" && info.HasNFT:
		return fw.NewNFT()
	case info.Firewall == "fw3" && info.HasIPSet:
		return fw.NewIPT(info.HasIP6Tables)
	case info.HasNFT && info.Firewall != "fw3":
		return fw.NewNFT()
	}
	return nil
}

// capabilities are what this router can do, for the dashboard to show
// only those features (the server agent's are not listed: a router has
// no WAF, malware scan, hardening scan, SSH logins...).
func capabilities(info sysinfo.Info) []string {
	c := []string{"learning_mode", "lan_devices", "conntrack_heuristics"}
	if chooseBackend(info) != nil {
		c = append(c, "ip_bans", "threat_feed", "c2_blocking")
	}
	c = append(c, "c2_detection", "dns_detection")
	if fileExists("/etc/init.d/dnsmasq") {
		c = append(c, "dns_blocking")
	}
	return c
}
