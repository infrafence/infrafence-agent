package firewall

import (
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
}

// NewGeoBlocker creates a GeoBlocker with the given CIDR provider.
// panelURL is the InfraFence panel URL — its IPs are added to the protected
// IPs, which the INFRAFENCE chain never blocks.
func NewGeoBlocker(provider CIDRProvider, panelURL string) *GeoBlocker {
	gb := &GeoBlocker{
		activeCountries: make(map[string]bool),
		cidrProvider:    provider,
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
	if !HasIpset() {
		if len(countries) > 0 {
			log.Printf("[geoblock] WARNING: %d countries configured for blocking but ipset is not installed — country blocks NOT applied at kernel level (falling back to reactive per-IP blocking)", len(countries))
		}
		return
	}

	g.mu.Lock()
	defer g.mu.Unlock()

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
	for cc := range desired {
		if !g.activeCountries[cc] {
			g.addCountry(cc)
		}
	}
}

// addCountry loads the country's CIDRs into its set and adds it to the chain.
func (g *GeoBlocker) addCountry(cc string) {
	setName := ipsetSetName(cc)

	cidrs, err := g.cidrProvider(cc)
	if err != nil {
		log.Printf("[geoblock] error getting CIDRs for %s: %v", cc, err)
		return
	}
	if len(cidrs) == 0 {
		log.Printf("[geoblock] no CIDRs found for %s — skipping", cc)
		return
	}

	if err := replaceNetSet(setName, cidrs); err != nil {
		log.Printf("[geoblock] failed to load set %s with %d CIDRs: %v", setName, len(cidrs), err)
		_ = destroyIpset(setName)
		return
	}
	fw.Lock()
	fw.geo[setName] = cidrs
	fw.Unlock()
	if _, err := Ensure(); err != nil {
		log.Printf("[geoblock] failed to add %s to the %s chain: %v", setName, chainName, err)
		fw.Lock()
		delete(fw.geo, setName)
		fw.Unlock()
		_ = destroyIpset(setName)
		return
	}

	g.activeCountries[cc] = true
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
