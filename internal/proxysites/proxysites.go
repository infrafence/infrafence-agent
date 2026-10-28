// Package proxysites lists the domains of the containers a reverse proxy
// serves, from the labels the proxy itself reads: Traefik's router rules
// (traefik.http.routers.<name>.rule), caddy-docker-proxy's site addresses
// (caddy, caddy_<n>) and InfraFence's own infrafence.domain. This is how
// Coolify (coolify-proxy, Traefik or Caddy), Dokploy and plain Traefik or
// Caddy setups declare their sites; such a site has no document root on
// the host, so its trust badge is verified with a DNS TXT record.
//
// Read only: one container listing through the Docker (or Podman) API,
// bounded and cached; nothing is run inside a container.
package proxysites

import (
	"context"
	"log"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/infrafence/infrafence-agent/internal/monitor"
	"github.com/infrafence/infrafence-agent/internal/trust"
)

// Sources of a domain, reported as is.
const (
	SourceTraefik = "traefik"
	SourceCaddy   = "caddy"
	SourceLabel   = "label"
)

const (
	// maxContainers and maxDomains bound one listing (the dashboard keeps
	// 500 entries of a heartbeat list).
	maxContainers = 1000
	maxDomains    = 500
	// perContainer: one container cannot crowd the others out.
	perContainer = 50
	// maxLabel: a longer label value is not a site address.
	maxLabel = 4096
	// RefreshEvery is how often the cache lists the containers again.
	RefreshEvery = 2 * time.Minute
)

// Domain is a domain a container is served under, and the label it came
// from.
type Domain struct {
	Domain string
	Source string
}

var (
	// Host(`a`), Host(`a`, `b`), HostHeader(...); never HostRegexp or
	// HostSNI (TCP), and not a negated !Host(...).
	traefikHostRe = regexp.MustCompile("(!?)\\b(?:Host|HostHeader)\\(([^)]*)\\)")
	quotedRe      = regexp.MustCompile("`([^`]*)`|\"([^\"]*)\"")
	// caddy, caddy_0, caddy_12: the site address labels (not their
	// directives, caddy_0.reverse_proxy and so on).
	caddySiteRe = regexp.MustCompile(`^caddy(_[0-9]+)?$`)
	// traefik.http.routers.<name>.rule (label keys are case-insensitive).
	traefikRuleRe = regexp.MustCompile(`^traefik\.http\.routers\.[^.]+\.rule$`)
)

// TraefikHosts returns the host names a Traefik rule matches exactly:
// every Host(...) of the rule, whatever the && / || around it. Path
// matchers are ignored; HostRegexp, HostSNI and negated hosts give none,
// and a rule with a negated group gives none at all.
func TraefikHosts(rule string) []string {
	// A negated group (!(Host(...) || ...)) is not worth parsing: such a
	// rule gives no name.
	if strings.Contains(strings.ReplaceAll(rule, " ", ""), "!(") {
		return nil
	}
	var out []string
	for _, m := range traefikHostRe.FindAllStringSubmatch(rule, -1) {
		if m[1] == "!" {
			continue
		}
		for _, q := range quotedRe.FindAllStringSubmatch(m[2], -1) {
			out = append(out, q[1]+q[2])
		}
	}
	return out
}

// CaddyHosts returns the host names of a caddy-docker-proxy site address
// list ("https://a.example.com, b.example.com:443"): scheme, port and path
// removed. Wildcards, placeholders and bare ports give none.
func CaddyHosts(v string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		if strings.ContainsAny(f, "{}*") {
			continue
		}
		if i := strings.Index(f, "://"); i >= 0 {
			f = f[i+3:]
		}
		if i := strings.IndexByte(f, '/'); i >= 0 {
			f = f[:i]
		}
		if i := strings.LastIndexByte(f, ':'); i >= 0 {
			f = f[:i]
		}
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// FromLabels returns the domains of one container's labels, each once
// (the first source wins: Traefik, then Caddy, then infrafence.domain).
func FromLabels(labels map[string]string) []Domain {
	var out []Domain
	seen := map[string]bool{}
	add := func(src string, names []string) {
		for _, n := range names {
			if d := normDomain(n); d != "" && !seen[d] {
				seen[d] = true
				out = append(out, Domain{Domain: d, Source: src})
			}
		}
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if on, ok := labelValue(labels, "traefik.enable"); !ok || !strings.EqualFold(on, "false") {
		for _, k := range keys {
			if v := labels[k]; len(v) <= maxLabel && traefikRuleRe.MatchString(strings.ToLower(k)) {
				add(SourceTraefik, TraefikHosts(v))
			}
		}
	}
	for _, k := range keys {
		if v := labels[k]; len(v) <= maxLabel && caddySiteRe.MatchString(k) {
			add(SourceCaddy, CaddyHosts(v))
		}
	}
	if v, ok := labels["infrafence.domain"]; ok && len(v) <= maxLabel {
		add(SourceLabel, strings.Split(v, ","))
	}
	return out
}

// normDomain is trust.NormDomain without IPv4 addresses: the top-level
// domain starts with a letter (as the dashboard requires).
func normDomain(n string) string {
	d := trust.NormDomain(n)
	if tld := d[strings.LastIndexByte(d, '.')+1:]; tld == "" || tld[0] < 'a' || tld[0] > 'z' {
		return ""
	}
	return d
}

func labelValue(labels map[string]string, key string) (string, bool) {
	for k, v := range labels {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return "", false
}

// proxyRepos are the images of the proxies themselves (Coolify runs
// traefik and lucaslorentz/caddy-docker-proxy). Only an exact repository
// counts: an application image merely named after a proxy stays watched.
var proxyRepos = map[string]string{
	"traefik":                         "traefik",
	"library/traefik":                 "traefik",
	"caddy":                           "caddy",
	"library/caddy":                   "caddy",
	"lucaslorentz/caddy-docker-proxy": "caddy",
}

// Flavour is the reverse proxy an image runs: "traefik", "caddy" or "".
// Neither runs nginx, so nginx -T is never tried in them.
func Flavour(image string) string {
	image = strings.ToLower(image)
	// The repository, without registry, tag or digest.
	if i := strings.IndexByte(image, '@'); i >= 0 {
		image = image[:i]
	}
	if i := strings.LastIndexByte(image, ':'); i > strings.LastIndexByte(image, '/') {
		image = image[:i]
	}
	if first, rest, ok := strings.Cut(image, "/"); ok && (strings.ContainsAny(first, ".:") || first == "localhost") {
		image = rest
	}
	return proxyRepos[image]
}

// FromContainers returns the domains of the running containers, at most
// perContainer each and maxDomains in all (in container order), sorted by
// domain. A container labelled infrafence.monitor=false is left out.
func FromContainers(cs []monitor.DockerContainer) []Domain {
	if len(cs) > maxContainers {
		cs = cs[:maxContainers]
	}
	seen := map[string]bool{}
	var out []Domain
	for _, c := range cs {
		if v := strings.ToLower(c.Labels["infrafence.monitor"]); v == "false" || v == "0" || v == "no" {
			continue
		}
		ds := FromLabels(c.Labels)
		if len(ds) > perContainer {
			ds = ds[:perContainer]
		}
		for _, d := range ds {
			if len(out) == maxDomains {
				break
			}
			if !seen[d.Domain] {
				seen[d.Domain] = true
				out = append(out, d)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}

// Cache holds the last listing; Run refreshes it.
type Cache struct {
	list func() ([]monitor.DockerContainer, error)

	mu      sync.RWMutex
	domains []Domain
}

// NewCache lists the containers with list (monitor.ListDockerContainers
// when nil).
func NewCache(list func() ([]monitor.DockerContainer, error)) *Cache {
	if list == nil {
		list = monitor.ListDockerContainers
	}
	return &Cache{list: list}
}

// Refresh lists the containers now. On an error the last listing is kept
// (a daemon restarting does not empty the list).
func (c *Cache) Refresh() {
	cs, err := c.list()
	if err != nil {
		return
	}
	ds := FromContainers(cs)
	c.mu.Lock()
	defer c.mu.Unlock()
	added, removed := diff(c.domains, ds)
	c.domains = ds
	if added+removed > 0 {
		log.Printf("[proxysites] %d container domain(s) (%d new, %d gone)", len(ds), added, removed)
	}
}

// diff counts the domains of b not in a, and of a not in b.
func diff(a, b []Domain) (added, removed int) {
	in := make(map[string]bool, len(a))
	for _, d := range a {
		in[d.Domain] = true
	}
	for _, d := range b {
		if !in[d.Domain] {
			added++
		}
		delete(in, d.Domain)
	}
	return added, len(in)
}

// Run refreshes the cache now and every RefreshEvery until ctx ends. It
// does nothing on a host without a Docker or Podman socket.
func (c *Cache) Run(ctx context.Context) {
	if !monitor.HasDockerSocket() {
		return
	}
	c.Refresh()
	t := time.NewTicker(RefreshEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.Refresh()
		}
	}
}

// Domains returns the last listing (a copy).
func (c *Cache) Domains() []Domain {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]Domain(nil), c.domains...)
}

// Has reports whether domain is in the last listing.
func (c *Cache) Has(domain string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, d := range c.domains {
		if d.Domain == domain {
			return true
		}
	}
	return false
}
