package opnsense

import (
	"net"
	"strings"
)

// ConfigPath is OPNsense's configuration.
const ConfigPath = "/conf/config.xml"

// Interface is one configured interface.
type Interface struct {
	Name     string `json:"name"` // wan, lan, opt1
	Descr    string `json:"descr,omitempty"`
	Device   string `json:"device,omitempty"` // vtnet0, igb1
	Enabled  bool   `json:"enabled"`
	IPv4     string `json:"ipv4,omitempty"` // "192.168.1.1/24", "dhcp"
	IPv6     string `json:"ipv6,omitempty"`
	Gateway  string `json:"-"`
	External bool   `json:"external"` // WAN-like: gets a gateway or a dynamic address
}

// Rule is one filter rule (legacy <filter> or the MVC rules).
type Rule struct {
	Action    string // pass, block, reject
	Interface []string
	Floating  bool
	Direction string // in, out, any
	IPProto   string
	Proto     string // any, tcp, udp, tcp/udp, ...
	Src       string // any, an alias, a network name (lan), an address
	SrcNot    bool
	Dst       string
	DstNot    bool
	DstPort   string
	Enabled   bool
	Descr     string
}

// User is one local user. The password hash is only compared with the
// factory default, never sent anywhere.
type User struct {
	Name     string
	UID      string
	Disabled bool
	OTP      bool
	Admin    bool
	hash     string
}

// Config is what the agent reads from config.xml.
type Config struct {
	Hostname   string
	Interfaces []Interface
	Rules      []Rule
	Users      []User
	WebGUI     struct {
		Protocol   string
		Port       string
		Interfaces []string // empty: all
		AuthModes  []string
	}
	SSH struct {
		Enabled      bool
		Port         string
		Interfaces   []string
		PermitRoot   bool
		PasswordAuth bool
	}
	TOTPServers []string
	DNSServers  []string
	Gateways    []string
	Peers       []string // VPN remote endpoints given as addresses
	IDSEnabled  bool
	IPSMode     bool
	CARP        bool
	Backups     []string // off-box configuration backups switched on
	Plugin      struct {
		Enabled    bool
		Interfaces []string
	}
	Aliases map[string]string // name: type
}

// LoadConfig reads and parses config.xml at path.
func LoadConfig(path string) (*Config, error) {
	root, err := LoadXML(path)
	if err != nil {
		return nil, err
	}
	return ParseConfig(root), nil
}

func on(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "yes", "on", "enabled", "true":
		return true
	}
	return false
}

func list(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ParseConfig reads the tree of config.xml.
func ParseConfig(root *Node) *Config {
	c := &Config{Aliases: map[string]string{}}
	c.Hostname = root.Str("system/hostname")

	if ifs := root.Child("interfaces"); ifs != nil {
		for _, n := range ifs.Children {
			it := Interface{Name: n.Name, Descr: n.Str("descr"), Device: n.Str("if"), Enabled: n.Has("enable"), // isset() in OPNsense
				Gateway: n.Str("gateway")}
			if v := n.Str("ipaddr"); v != "" {
				it.IPv4 = v
				if s := n.Str("subnet"); s != "" && net.ParseIP(v) != nil {
					it.IPv4 = v + "/" + s
				}
			}
			if v := n.Str("ipaddrv6"); v != "" {
				it.IPv6 = v
				if s := n.Str("subnetv6"); s != "" && net.ParseIP(v) != nil {
					it.IPv6 = v + "/" + s
				}
			}
			switch strings.ToLower(n.Str("ipaddr")) {
			case "dhcp", "pppoe", "pptp", "l2tp", "ppp":
				it.External = true
			}
			if it.Name == "wan" || it.Gateway != "" {
				it.External = true
			}
			c.Interfaces = append(c.Interfaces, it)
		}
	}

	// Legacy rules.
	for _, n := range root.All("filter/rule") {
		r := Rule{Action: n.Str("type"), Interface: list(n.Str("interface")), Floating: on(n.Str("floating")),
			Direction: n.Str("direction"), IPProto: n.Str("ipprotocol"), Proto: n.Str("protocol"),
			Enabled: !n.Has("disabled"), Descr: n.Str("descr")} // isset() in OPNsense
		r.Src, r.SrcNot, _ = legacyAddr(n.Child("source"))
		var port string
		r.Dst, r.DstNot, port = legacyAddr(n.Child("destination"))
		r.DstPort = port
		c.Rules = append(c.Rules, r)
	}
	// MVC rules (Firewall › Rules [new], default from 25.x/26.x).
	for _, n := range root.All("OPNsense/Firewall/Filter/rules/rule") {
		r := Rule{Action: n.Str("action"), Interface: list(n.Str("interface")), Floating: on(n.Str("floating")) || strings.Contains(n.Str("interface"), ","),
			Direction: n.Str("direction"), IPProto: n.Str("ipprotocol"), Proto: n.Str("protocol"),
			Src: n.Str("source_net"), SrcNot: on(n.Str("source_not")), Dst: n.Str("destination_net"), DstNot: on(n.Str("destination_not")),
			DstPort: n.Str("destination_port"), Enabled: n.Str("enabled") != "0", Descr: n.Str("description")}
		c.Rules = append(c.Rules, r)
	}

	admins := map[string]bool{}
	for _, g := range root.All("system/group") {
		isAdmin := g.Str("name") == "admins"
		for _, p := range g.All("priv") {
			if p.Text == "page-all" {
				isAdmin = true
			}
		}
		if isAdmin {
			for _, m := range g.All("member") {
				for _, uid := range list(m.Text) {
					admins[uid] = true
				}
			}
		}
	}
	for _, n := range root.All("system/user") {
		u := User{Name: n.Str("name"), UID: n.Str("uid"), Disabled: n.Has("disabled") && (n.Str("disabled") == "" || on(n.Str("disabled"))),
			OTP: n.Str("otp_seed") != "", hash: n.Str("password")}
		u.Admin = admins[u.UID] || u.UID == "0"
		for _, p := range n.All("priv") {
			if p.Text == "page-all" {
				u.Admin = true
			}
		}
		c.Users = append(c.Users, u)
	}

	c.WebGUI.Protocol = root.Str("system/webgui/protocol")
	c.WebGUI.Port = root.Str("system/webgui/port")
	if c.WebGUI.Port == "" {
		if c.WebGUI.Protocol == "http" {
			c.WebGUI.Port = "80"
		} else {
			c.WebGUI.Port = "443"
		}
	}
	c.WebGUI.Interfaces = list(root.Str("system/webgui/interfaces"))
	c.WebGUI.AuthModes = list(root.Str("system/webgui/authmode"))
	for _, a := range root.All("system/authserver") {
		if a.Str("type") == "totp" {
			c.TOTPServers = append(c.TOTPServers, a.Str("name"))
		}
	}

	ssh := root.Get("system/ssh")
	c.SSH.Enabled = ssh != nil && (ssh.Str("enabled") == "enabled" || on(ssh.Str("enabled")))
	c.SSH.Port = ssh.Str("port")
	if c.SSH.Port == "" {
		c.SSH.Port = "22"
	}
	c.SSH.Interfaces = list(ssh.Str("interfaces"))
	c.SSH.PermitRoot = on(ssh.Str("permitrootlogin"))
	c.SSH.PasswordAuth = on(ssh.Str("passwordauth"))

	for _, d := range root.All("system/dnsserver") {
		if net.ParseIP(d.Text) != nil {
			c.DNSServers = append(c.DNSServers, d.Text)
		}
	}
	for _, p := range []string{"gateways/gateway_item", "OPNsense/Gateways/gateway_item"} {
		for _, g := range root.All(p) {
			if ip := g.Str("gateway"); net.ParseIP(ip) != nil {
				c.Gateways = append(c.Gateways, ip)
			}
		}
	}
	// VPN peers given as addresses (hostnames are not resolved here).
	addPeer := func(s string) {
		for _, p := range list(s) {
			if net.ParseIP(p) != nil {
				c.Peers = append(c.Peers, p)
			}
		}
	}
	for _, p := range root.All("ipsec/phase1") {
		addPeer(p.Str("remote-gateway"))
	}
	for _, p := range root.All("OPNsense/Swanctl/remotes/remote") {
		addPeer(p.Str("addrs"))
	}
	for _, p := range root.All("openvpn/openvpn-client") {
		addPeer(p.Str("server_addr"))
	}
	for _, p := range root.All("OPNsense/OpenVPN/Instances/Instance") {
		addPeer(p.Str("remote"))
	}
	for _, p := range root.All("OPNsense/wireguard/client/clients/client") {
		addPeer(p.Str("serveraddress"))
	}

	c.IDSEnabled = on(root.Str("OPNsense/IDS/general/enabled"))
	// IPS: "ips" up to 25.x, "mode" (pcap = IDS, netmap/divert = IPS) in 26.x.
	switch root.Str("OPNsense/IDS/general/mode") {
	case "netmap", "divert":
		c.IPSMode = true
	default:
		c.IPSMode = on(root.Str("OPNsense/IDS/general/ips"))
	}
	for _, v := range root.All("virtualip/vip") {
		if v.Str("mode") == "carp" {
			c.CARP = true
		}
	}

	// Off-box configuration backups: the legacy Google Drive one and the
	// MVC Backup providers (Nextcloud, Git, SFTP, ...), each "enabled".
	if on(root.Str("system/remotebackup/GDriveEnabled")) {
		c.Backups = append(c.Backups, "Google Drive")
	}
	if b := root.Get("OPNsense/Backup"); b != nil {
		for _, p := range b.Children {
			if on(p.Str("enabled")) {
				c.Backups = append(c.Backups, strings.TrimSuffix(p.Name, "Settings"))
			}
		}
	}
	if b := root.Get("OPNsense/GDrive"); b != nil && on(b.Str("enabled")) {
		c.Backups = append(c.Backups, "Google Drive")
	}

	c.Plugin.Enabled = on(root.Str("OPNsense/infrafence/general/enabled"))
	c.Plugin.Interfaces = list(root.Str("OPNsense/infrafence/general/interfaces"))
	if len(c.Plugin.Interfaces) == 0 {
		c.Plugin.Interfaces = []string{"wan"}
	}
	for _, a := range root.All("OPNsense/Firewall/Alias/aliases/alias") {
		c.Aliases[a.Str("name")] = a.Str("type")
	}
	return c
}

// legacyAddr reads a legacy rule's <source>/<destination>.
func legacyAddr(n *Node) (addr string, not bool, port string) {
	if n == nil {
		return "any", false, ""
	}
	not = n.Has("not")
	port = n.Str("port")
	switch {
	case n.Has("any"):
		addr = "any"
	case n.Str("network") != "":
		addr = n.Str("network")
	case n.Str("address") != "":
		addr = n.Str("address")
	default:
		addr = "any"
	}
	return addr, not, port
}

// Interface returns the interface called name.
func (c *Config) Interface(name string) (Interface, bool) {
	for _, it := range c.Interfaces {
		if it.Name == name {
			return it, true
		}
	}
	return Interface{}, false
}

// ExternalNames are the WAN-like interfaces.
func (c *Config) ExternalNames() []string {
	var out []string
	for _, it := range c.Interfaces {
		if it.External && it.Enabled {
			out = append(out, it.Name)
		}
	}
	return out
}

// InternalNets are the networks of the enabled internal interfaces with a
// static address (LAN, OPTx, DMZ): never banned, so blocking can never cut
// the firewall off from its own networks.
func (c *Config) InternalNets() []string {
	var out []string
	for _, it := range c.Interfaces {
		if it.External || !it.Enabled {
			continue
		}
		for _, a := range []string{it.IPv4, it.IPv6} {
			if _, n, err := net.ParseCIDR(a); err == nil {
				out = append(out, n.String())
			}
		}
	}
	return out
}

// DefaultRootHash is root's password hash in OPNsense's factory
// config.xml.sample: the documented default password "opnsense".
var DefaultRootHash = []string{"$2y$10$YRVoF4SgskIsrXOvOQjGieB9XqHPRra9R7d80B3BZdbY/j21TwBfS"}

func (u User) defaultPassword() bool {
	for _, h := range DefaultRootHash {
		if u.hash == h {
			return true
		}
	}
	return false
}
