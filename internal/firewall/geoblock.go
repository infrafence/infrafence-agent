package firewall

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"
	"sync"
)

// CIDRProvider is a function that returns CIDRs for a given country code.
// This avoids importing geoip in the firewall package.
type CIDRProvider func(countryCode string) ([]string, error)

// GeoBlocker manages ipset-based country blocking.
// Each blocked country gets its own ipset hash:net set, dropped from the
// INFRAFENCE chain (see chain.go).
type GeoBlocker struct {
	mu              sync.Mutex
	activeCountries map[string]bool // currently blocked country codes (uppercase)
	cidrProvider    CIDRProvider
	// exempt returns the addresses left out of every country set: the
	// sources of the SSH sessions open when a set is loaded.
	exempt func() []string
	// reload: the sets of the active countries are loaded again at the
	// next ApplyCountryBlocks (a new country database).
	reload bool
	// logged is the last problem logged per country ("" key: ipset
	// missing): every sync retries, the log says it once.
	logged map[string]string
}

// logOnce logs msg unless it is the last one logged for key.
func (g *GeoBlocker) logOnce(key, msg string) {
	if g.logged[key] == msg {
		return
	}
	g.logged[key] = msg
	log.Print(msg)
}

// SetExempt sets the addresses a country set never holds (see exempt).
func (g *GeoBlocker) SetExempt(fn func() []string) {
	g.mu.Lock()
	g.exempt = fn
	g.mu.Unlock()
}

// Reload makes the next ApplyCountryBlocks load the sets of the countries
// already blocked again, from the current database (each set is swapped
// whole, so the block never lapses).
func (g *GeoBlocker) Reload() {
	g.mu.Lock()
	g.reload = true
	g.mu.Unlock()
}

// NewGeoBlocker creates a GeoBlocker with the given CIDR provider.
// panelURL is the InfraFence panel URL — its IPs are added to the protected
// IPs, which the INFRAFENCE chain never blocks.
func NewGeoBlocker(provider CIDRProvider, panelURL string) *GeoBlocker {
	gb := &GeoBlocker{
		activeCountries: make(map[string]bool),
		cidrProvider:    provider,
		logged:          make(map[string]string),
	}
	if panelURL != "" {
		if u, err := url.Parse(panelURL); err == nil && u.Hostname() != "" {
			if ips, err := net.LookupHost(u.Hostname()); err == nil {
				AddProtectedIPs(ips...)
			}
		}
	}
	return gb
}

// ApplyCountryBlocks synchronizes the ipset country blocks with the desired list.
func (g *GeoBlocker) ApplyCountryBlocks(countries []string) {
	if Disabled() {
		return // protection is off; re-applied by the first sync after Enable
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	if !HasIpset() {
		if len(countries) > 0 {
			g.logOnce("", fmt.Sprintf("[geoblock] WARNING: %d countries configured for blocking but ipset is not installed — country blocks NOT applied at kernel level (falling back to reactive per-IP blocking)", len(countries)))
		}
		return
	}

	desired := make(map[string]bool, len(countries))
	for _, cc := range countries {
		cc = strings.ToUpper(strings.TrimSpace(cc))
		if cc != "" && len(cc) == 2 {
			desired[cc] = true
		}
	}
	for cc := range g.activeCountries {
		if !desired[cc] {
			g.removeCountry(cc)
		}
	}
	var exempt []string
	exemptRead := false
	for cc := range desired {
		if !g.activeCountries[cc] || g.reload {
			if !exemptRead && g.exempt != nil {
				exempt, exemptRead = g.exempt(), true
			}
			g.addCountry(cc, exempt)
		}
	}
	g.reload = false
}

// addCountry loads the country's CIDRs, without the exempt addresses, into
// its set and adds it to the chain. A country already blocked keeps its set
// when loading the new one fails.
func (g *GeoBlocker) addCountry(cc string, exempt []string) {
	setName := ipsetSetName(cc)
	active := g.activeCountries[cc]

	cidrs, err := g.cidrProvider(cc)
	if err != nil {
		g.logOnce(cc, fmt.Sprintf("[geoblock] %s not blocked yet: %v", cc, err))
		return
	}
	if len(cidrs) == 0 {
		g.logOnce(cc, fmt.Sprintf("[geoblock] no CIDRs found for %s — skipping", cc))
		return
	}
	if kept, n := excludeAddrs(cidrs, exempt); n > 0 {
		log.Printf("[geoblock] %s: %d address(es) with an SSH session open now left out", cc, n)
		cidrs = kept
	}

	if err := replaceNetSet(setName, cidrs); err != nil {
		log.Printf("[geoblock] failed to load set %s with %d CIDRs: %v", setName, len(cidrs), err)
		if !active {
			_ = destroyIpset(setName)
		}
		return
	}
	fw.Lock()
	fw.geo[setName] = cidrs
	fw.Unlock()
	if _, err := Ensure(); err != nil {
		log.Printf("[geoblock] failed to add %s to the %s chain: %v", setName, chainName, err)
		if !active {
			fw.Lock()
			delete(fw.geo, setName)
			fw.Unlock()
			_ = destroyIpset(setName)
		}
		return
	}

	g.activeCountries[cc] = true
	delete(g.logged, cc)
	log.Printf("[geoblock] ✓ blocked %s: %d CIDRs loaded into %s", cc, ipsetEntryCount(setName), setName)
}

// removeCountry removes the country from the chain, then destroys its set.
func (g *GeoBlocker) removeCountry(cc string) {
	setName := ipsetSetName(cc)

	fw.Lock()
	delete(fw.geo, setName)
	fw.Unlock()
	// The chain must stop referencing the set before it can be destroyed.
	if _, err := Ensure(); err != nil {
		log.Printf("[geoblock] warning: failed to remove %s from the %s chain: %v", setName, chainName, err)
	}
	_ = flushIpset(setName)
	if err := destroyIpset(setName); err != nil {
		log.Printf("[geoblock] warning: failed to destroy set %s: %v", setName, err)
	}

	delete(g.activeCountries, cc)
	log.Printf("[geoblock] ✓ unblocked %s: set %s removed", cc, setName)
}

// ActiveCountries returns the list of currently blocked countries.
func (g *GeoBlocker) ActiveCountries() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	result := make([]string, 0, len(g.activeCountries))
	for cc := range g.activeCountries {
		result = append(result, cc)
	}
	return result
}

// SetWhitelistedIPs exempts the whitelist from every InfraFence block (geo
// included) through the chain's allow list. It does not open anything in
// the host firewall for those IPs.
func (g *GeoBlocker) SetWhitelistedIPs(ips []string) {
	SetAllowList(ips)
}

// Cleanup removes all geoblock ipset sets and chain rules (used on shutdown).
func (g *GeoBlocker) Cleanup() {
	g.mu.Lock()
	defer g.mu.Unlock()
	for cc := range g.activeCountries {
		g.removeCountry(cc)
	}
}

// excludeAddrs returns cidrs without the IPv4 addresses in ips (a network
// holding one is split into the smaller networks around it), and how many
// of those addresses were in cidrs.
func excludeAddrs(cidrs, ips []string) (out []string, excluded int) {
	var ex []uint32
	seen := map[uint32]bool{}
	for _, ip := range ips {
		if p := net.ParseIP(ip).To4(); p != nil && !seen[binary.BigEndian.Uint32(p)] {
			seen[binary.BigEndian.Uint32(p)] = true
			ex = append(ex, binary.BigEndian.Uint32(p))
		}
	}
	if len(ex) == 0 {
		return cidrs, 0
	}
	out = make([]string, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil || n.IP.To4() == nil {
			out = append(out, c)
			continue
		}
		ones, _ := n.Mask.Size()
		base := binary.BigEndian.Uint32(n.IP.To4())
		for _, a := range ex {
			if inNet(a, base, ones) {
				excluded++
			}
		}
		out = appendWithout(out, base, ones, ex)
	}
	return out, excluded
}

// inNet reports whether address a is in the network base/ones.
func inNet(a, base uint32, ones int) bool {
	return uint64(a) >= uint64(base) && uint64(a) < uint64(base)+uint64(1)<<(32-ones)
}

// appendWithout appends the network base/ones, split around the addresses
// in ex.
func appendWithout(out []string, base uint32, ones int, ex []uint32) []string {
	hit := false
	for _, a := range ex {
		if inNet(a, base, ones) {
			hit = true
			break
		}
	}
	if !hit {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, base)
		return append(out, (&net.IPNet{IP: ip, Mask: net.CIDRMask(ones, 32)}).String())
	}
	if ones == 32 {
		return out // the address itself
	}
	out = appendWithout(out, base, ones+1, ex)
	return appendWithout(out, base+uint32(1)<<(31-ones), ones+1, ex)
}
