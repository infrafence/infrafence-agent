// Package sysinfo detects what kind of OpenWrt (or GL.iNet) router the
// agent runs on: release, board, package manager, firewall generation, flow
// offloading, memory and flash. Everything is read-only.
package sysinfo

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/infrafence/infrafence-agent/internal/router/uci"
)

// Info is the router's description.
type Info struct {
	Release        string // "OpenWrt 24.10.8"
	Version        string // "24.10.8"
	Target         string // "ramips/mt7621"
	Arch           string // "mipsel_24kc"
	Board          string // "glinet,gl-mt3000"
	Model          string // "GL.iNet GL-MT3000"
	Hostname       string
	Vendor         string // "glinet" or "openwrt"
	PackageManager string // "apk" or "opkg"
	Firewall       string // "fw4", "fw3" or "none"
	HasNFT         bool
	HasIPSet       bool
	HasIP6Tables   bool
	HasConntrack   bool // the conntrack tool (to drop offloaded flows on a ban)
	FlowOffload    bool
	FlowOffloadHW  bool
	Dnsmasq        string // version, e.g. "2.93"
	MemTotal       uint64 // bytes
	OverlayFree    uint64 // bytes
	Coexisting     []string
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// Root is prepended to every path (tests).
var Root = ""

// Detect reads the router's description.
func Detect() Info {
	var in Info
	rel := readKV(Root + "/etc/openwrt_release")
	in.Release = strings.TrimSpace(rel["DISTRIB_DESCRIPTION"])
	in.Version = rel["DISTRIB_RELEASE"]
	in.Target = rel["DISTRIB_TARGET"]
	in.Arch = rel["DISTRIB_ARCH"]
	if in.Release == "" {
		in.Release = strings.TrimSpace(rel["DISTRIB_ID"] + " " + in.Version)
	}
	if b, err := os.ReadFile(Root + "/tmp/sysinfo/board_name"); err == nil {
		in.Board = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile(Root + "/tmp/sysinfo/model"); err == nil {
		in.Model = strings.TrimSpace(string(b))
	}
	if in.Board == "" || in.Model == "" {
		if out, err := exec.Command("ubus", "call", "system", "board").Output(); err == nil {
			var sb struct {
				Model     string `json:"model"`
				BoardName string `json:"board_name"`
			}
			if json.Unmarshal(out, &sb) == nil {
				if in.Board == "" {
					in.Board = sb.BoardName
				}
				if in.Model == "" {
					in.Model = sb.Model
				}
			}
		}
	}
	in.Hostname, _ = os.Hostname()
	in.Vendor = "openwrt"
	if exists(Root+"/etc/glversion") || strings.HasPrefix(strings.ToLower(in.Board), "glinet") || strings.HasPrefix(in.Model, "GL.iNet") || strings.HasPrefix(in.Model, "GL-") {
		in.Vendor = "glinet"
	}
	switch {
	case exists(Root + "/usr/bin/apk"):
		in.PackageManager = "apk"
	case exists(Root + "/bin/opkg"), exists(Root + "/usr/bin/opkg"):
		in.PackageManager = "opkg"
	}
	in.HasNFT = lookPath("nft")
	in.HasIPSet = lookPath("ipset") && lookPath("iptables")
	in.HasIP6Tables = lookPath("ip6tables")
	in.HasConntrack = lookPath("conntrack")
	switch {
	case exists(Root + "/sbin/fw4"):
		in.Firewall = "fw4"
	case exists(Root + "/sbin/fw3"):
		in.Firewall = "fw3"
	default:
		in.Firewall = "none"
	}
	fwc := uci.Show("firewall")
	if v, _ := uci.First(fwc, "firewall", "defaults", "flow_offloading"); v == "1" {
		in.FlowOffload = true
	}
	if v, _ := uci.First(fwc, "firewall", "defaults", "flow_offloading_hw"); v == "1" {
		in.FlowOffloadHW = true
	}
	if out, err := exec.Command("dnsmasq", "--version").Output(); err == nil {
		in.Dnsmasq = dnsmasqVersion(string(out))
	}
	in.MemTotal = memTotal(Root + "/proc/meminfo")
	in.OverlayFree = free("/overlay")
	if in.OverlayFree == 0 {
		in.OverlayFree = free("/")
	}
	in.Coexisting = coexisting()
	return in
}

func lookPath(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func readKV(path string) map[string]string {
	m := map[string]string{}
	b, err := os.ReadFile(path)
	if err != nil {
		return m
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		m[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `'"`)
	}
	return m
}

func memTotal(path string) uint64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "MemTotal:") {
			fs := strings.Fields(l)
			if len(fs) >= 2 {
				kb, _ := strconv.ParseUint(fs[1], 10, 64)
				return kb * 1024
			}
		}
	}
	return 0
}

func free(path string) uint64 {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0
	}
	return uint64(st.Bavail) * uint64(st.Bsize)
}

// Other blockers and DNS services the agent coexists with (it never edits
// their configuration; the dashboard shows them).
var others = []struct{ name, initScript string }{
	{"adblock", "adblock"},
	{"adblock-fast", "adblock-fast"},
	{"simple-adblock", "simple-adblock"},
	{"banip", "banip"},
	{"adguardhome", "adguardhome"},
	{"https-dns-proxy", "https-dns-proxy"},
	{"stubby", "stubby"},
	{"unbound", "unbound"},
	{"pbr", "pbr"},
}

func coexisting() []string {
	var out []string
	for _, o := range others {
		if !exists(Root + "/etc/init.d/" + o.initScript) {
			continue
		}
		// Enabled: an S??name link in /etc/rc.d.
		m, _ := globAny(Root + "/etc/rc.d/S*" + o.initScript)
		if m {
			out = append(out, o.name)
		}
	}
	// GL.iNet's built-in AdGuard Home.
	if exists(Root+"/etc/AdGuardHome") || exists(Root+"/usr/bin/AdGuardHome") {
		if !contains(out, "adguardhome") {
			out = append(out, "adguardhome")
		}
	}
	return out
}

func globAny(pattern string) (bool, error) {
	dir := pattern[:strings.LastIndex(pattern, "/")]
	suffix := pattern[strings.LastIndex(pattern, "*")+1:]
	ents, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	for _, e := range ents {
		n := e.Name()
		if strings.HasPrefix(n, "S") && strings.HasSuffix(n, suffix) && len(n) == len(suffix)+3 {
			return true, nil
		}
	}
	return false, nil
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// GoArch is the binary's architecture (for the heartbeat when the release
// file has no DISTRIB_ARCH).
func GoArch() string { return runtime.GOARCH }

// dnsmasqVersion reads "Dnsmasq version 2.85  Copyright ...".
func dnsmasqVersion(out string) string {
	fs := strings.Fields(out)
	for i := 0; i+2 < len(fs); i++ {
		if fs[i] == "Dnsmasq" && fs[i+1] == "version" {
			return fs[i+2]
		}
	}
	return ""
}

// OldDnsmasq: before 2.86 dnsmasq looks local=/domain/ entries up one by
// one, so a long list costs CPU on every query (a slow MIPS router).
func OldDnsmasq(v string) bool {
	maj, min, ok := strings.Cut(v, ".")
	if !ok {
		return false
	}
	a, err1 := strconv.Atoi(maj)
	b, err2 := strconv.Atoi(strings.TrimRightFunc(min, func(r rune) bool { return r < '0' || r > '9' }))
	if err1 != nil || err2 != nil {
		return false
	}
	return a < 2 || a == 2 && b < 86
}

// DefaultCaps are the ban, C2 and domain caps for the router's RAM: a
// 128 MB device keeps InfraFence under ~25 MB in total.
func DefaultCaps(memTotal uint64) (bans, c2, domains int) {
	if memTotal > 0 && memTotal <= 192<<20 {
		return 20000, 20000, 100000
	}
	return 100000, 50000, 300000
}
