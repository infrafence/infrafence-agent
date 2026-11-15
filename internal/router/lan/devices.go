// Package lan knows the router's LAN: which devices are on it (DHCP leases,
// neighbour table), what they look up (DNS packets, read from a kernel-
// filtered packet socket) and where they connect (conntrack).
//
// Privacy: a device is known to the dashboard by an HMAC of its MAC address
// under a secret that never leaves the router, the MAC's manufacturer
// prefix (OUI) and its LAN address. Host names ("Laura's iPhone") are
// personal data and are sent only when the organization opted in. No DNS
// history leaves the router: only lookups of listed malicious domains.
package lan

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Device is one LAN device.
type Device struct {
	Key       string // HMAC(secret, MAC), 16 hex digits
	OUI       string // "A4:83:E7"; empty for a locally administered (randomized) MAC
	Random    bool
	IP        netip.Addr
	IPv6      netip.Addr
	Name      string // DHCP host name (never sent unless opted in)
	FirstSeen time.Time
	LastSeen  time.Time
}

// Inventory tracks LAN devices.
type Inventory struct {
	secret []byte
	// Paths (overridable in tests).
	Leases, ODHCPD, ARP string
	Now                 func() time.Time
	// Max devices kept (oldest last-seen dropped first).
	Max int
	// LANIf: only neighbours on this interface are LAN devices (the WAN
	// modem is not); empty: all.
	LANIf string

	mu    sync.Mutex
	byMAC map[string]*Device
	byIP  map[netip.Addr]*Device
}

// LoadSecret reads the per-router device key secret, creating it (32
// random bytes, 0600) on first use. It lives in /etc/infrafence so device
// keys stay the same across reboots and upgrades.
func LoadSecret(path string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil {
		if s, err := hex.DecodeString(strings.TrimSpace(string(b))); err == nil && len(s) >= 16 {
			return s, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	s := make([]byte, 32)
	if _, err := rand.Read(s); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(hex.EncodeToString(s)+"\n"), 0o600); err != nil {
		return nil, err
	}
	return s, os.Rename(tmp, path)
}

func NewInventory(secret []byte) *Inventory {
	return &Inventory{
		secret: secret,
		Leases: "/tmp/dhcp.leases",
		ODHCPD: "/tmp/hosts/odhcpd",
		ARP:    "/proc/net/arp",
		Now:    time.Now,
		Max:    1024,
		byMAC:  map[string]*Device{},
		byIP:   map[netip.Addr]*Device{},
	}
}

// KeyFor is the device key of a MAC address.
func (inv *Inventory) KeyFor(mac string) string {
	m := hmac.New(sha256.New, inv.secret)
	m.Write([]byte(strings.ToLower(mac)))
	return hex.EncodeToString(m.Sum(nil))[:16]
}

// KeyForIP is the key of a device known only by its address (static
// address, no neighbour entry yet).
func (inv *Inventory) KeyForIP(ip netip.Addr) string {
	m := hmac.New(sha256.New, inv.secret)
	m.Write([]byte("ip:" + ip.String()))
	return hex.EncodeToString(m.Sum(nil))[:16]
}

func normMAC(s string) (string, bool) {
	hw, err := net.ParseMAC(s)
	if err != nil || len(hw) != 6 {
		return "", false
	}
	if hw.String() == "00:00:00:00:00:00" {
		return "", false
	}
	return hw.String(), true
}

func oui(mac string) (string, bool) {
	hw, _ := net.ParseMAC(mac)
	if len(hw) < 3 {
		return "", false
	}
	if hw[0]&0x02 != 0 { // locally administered: randomized
		return "", true
	}
	return strings.ToUpper(hw[:3].String()), false
}

// Refresh reads leases and the neighbour table.
func (inv *Inventory) Refresh() {
	now := inv.Now()
	inv.mu.Lock()
	defer inv.mu.Unlock()
	// dnsmasq: "<expiry> <mac> <ip> <hostname|*> <client-id|*>"
	readLines(inv.Leases, func(fs []string) {
		if len(fs) < 4 {
			return
		}
		ip, err := netip.ParseAddr(fs[2])
		if err != nil {
			return
		}
		name := fs[3]
		if name == "*" {
			name = ""
		}
		inv.seen(fs[1], ip, name, now)
	})
	// /proc/net/arp: "IP HWtype Flags HWaddress Mask Device"
	readLines(inv.ARP, func(fs []string) {
		if len(fs) < 6 || fs[0] == "IP" || fs[2] == "0x0" || inv.LANIf != "" && fs[5] != inv.LANIf {
			return
		}
		ip, err := netip.ParseAddr(fs[0])
		if err != nil {
			return
		}
		inv.seen(fs[3], ip, "", now)
	})
	// odhcpd: "# <iface> <duid> <iaid> <hostname> <expiry> <..> <..> <ip/len>..."
	readLines(inv.ODHCPD, func(fs []string) {
		if len(fs) < 9 || fs[0] != "#" {
			return
		}
		name := fs[4]
		if name == "-" {
			name = ""
		}
		for _, a := range fs[8:] {
			s, _, _ := strings.Cut(a, "/")
			ip, err := netip.ParseAddr(s)
			if err != nil || !ip.Is6() {
				continue
			}
			// No MAC in odhcpd's file: attach to a device with that name.
			for _, d := range inv.byMAC {
				if name != "" && d.Name == name {
					d.IPv6 = ip
					inv.byIP[ip] = d
				}
			}
		}
	})
	inv.trim()
}

func (inv *Inventory) seen(macStr string, ip netip.Addr, name string, now time.Time) {
	mac, ok := normMAC(macStr)
	if !ok {
		return
	}
	d := inv.byMAC[mac]
	if d == nil {
		o, random := oui(mac)
		d = &Device{Key: inv.KeyFor(mac), OUI: o, Random: random, FirstSeen: now}
		inv.byMAC[mac] = d
	}
	d.LastSeen = now
	if name != "" {
		d.Name = name
	}
	if ip.Is4() {
		if old := d.IP; old.IsValid() && old != ip && inv.byIP[old] == d {
			delete(inv.byIP, old)
		}
		d.IP = ip
	} else {
		d.IPv6 = ip
	}
	inv.byIP[ip] = d
}

func (inv *Inventory) trim() {
	if len(inv.byMAC) <= inv.Max {
		return
	}
	type kv struct {
		mac string
		d   *Device
	}
	var l []kv
	for m, d := range inv.byMAC {
		l = append(l, kv{m, d})
	}
	sort.Slice(l, func(i, j int) bool { return l[i].d.LastSeen.After(l[j].d.LastSeen) })
	for _, e := range l[inv.Max:] {
		delete(inv.byMAC, e.mac)
		for ip, d := range inv.byIP {
			if d == e.d {
				delete(inv.byIP, ip)
			}
		}
	}
}

// Lookup finds the device using an address; ok is false for an address
// with no lease or neighbour entry (the key is then derived from the IP).
func (inv *Inventory) Lookup(ip netip.Addr) (Device, bool) {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	if d := inv.byIP[ip.Unmap()]; d != nil {
		return *d, true
	}
	return Device{Key: inv.KeyForIP(ip.Unmap()), IP: ip.Unmap()}, false
}

// List returns the devices, most recently seen first.
func (inv *Inventory) List() []Device {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	out := make([]Device, 0, len(inv.byMAC))
	for _, d := range inv.byMAC {
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func (inv *Inventory) Len() int {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	return len(inv.byMAC)
}

func readLines(path string, fn func([]string)) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4096), 64<<10)
	for n := 0; sc.Scan() && n < 10000; n++ {
		fn(strings.Fields(sc.Text()))
	}
}
