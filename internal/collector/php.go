package collector

import (
	"regexp"
	"sort"
	"strings"

	"github.com/infrafence/infrafence-agent/internal/phpconf"
)

// PHPRuntime is one PHP installation that serves web requests (PHP-FPM,
// mod_php, CGI), with the sites that use it. The CLI version
// (KeySoftware "PHP") can differ from all of them.
type PHPRuntime struct {
	ID      string    `json:"id"`      // "debian-8.2-fpm", "ea-php82-fpm"...
	Version string    `json:"version"` // "8.2.12" when the binary says it, else "8.2" ("" unknown)
	SAPI    string    `json:"sapi"`    // fpm, apache2handler, cgi
	Family  string    `json:"family,omitempty"`
	Panel   string    `json:"panel,omitempty"`
	Status  string    `json:"status"` // up_to_date, outdated, eol, unknown
	Pools   []PHPPool `json:"pools,omitempty"`
	// Sites served by the runtime as a whole (mod_php: every Apache
	// virtual host that doesn't send PHP to PHP-FPM).
	Sites []string `json:"sites,omitempty"`
	Roots []string `json:"roots,omitempty"`
}

// PHPPool is one PHP-FPM pool and the sites whose PHP requests go to it.
type PHPPool struct {
	Name  string   `json:"name"`
	User  string   `json:"user,omitempty"`
	Sites []string `json:"sites,omitempty"`
	Roots []string `json:"roots,omitempty"`
}

// Bounds of the PHP runtime inventory.
const (
	maxPHPRuntimes = 50
	maxPHPPools    = 100
	maxPHPSites    = 200
)

var phpVersionRe = regexp.MustCompile(`\bPHP (\d+\.\d+\.\d+)`)

// collectPHPRuntimes lists the PHP runtimes discovery finds (internal/phpconf)
// and the sites mapped to each. Read only: configuration files, and
// "<binary> -v" (10 s timeout) for the exact version.
func collectPHPRuntimes(env phpconf.Env) []PHPRuntime {
	h := phpconf.Discover(env)
	out := []PHPRuntime{}
	versions := map[string]string{} // binary -> version
	exact := func(bin string) string {
		if bin == "" || !env.Exists(bin) {
			return ""
		}
		if v, ok := versions[bin]; ok {
			return v
		}
		v := ""
		if o, err := env.Run(bin, "-v"); err == nil {
			if m := phpVersionRe.FindStringSubmatch(o); m != nil {
				v = m[1]
			}
		}
		versions[bin] = v
		return v
	}
	for _, rt := range h.Runtimes {
		if rt.SAPI == "cli" || len(out) >= maxPHPRuntimes {
			continue
		}
		r := PHPRuntime{ID: rt.ID, SAPI: rt.SAPI, Family: rt.Family, Panel: rt.Panel, Version: rt.Version}
		bin := rt.CLI
		if rt.SAPI == "fpm" && rt.FPM != "" {
			bin = rt.FPM
		}
		if v := exact(bin); v != "" && (r.Version == "" || strings.HasPrefix(v, r.Version+".")) {
			r.Version = v
		}
		r.Status = phpStatus(r.Version)
		switch rt.SAPI {
		case "fpm":
			for _, p := range rt.Pools {
				if len(r.Pools) >= maxPHPPools {
					break
				}
				sites := h.Web.SitesFor(p.Listen)
				r.Pools = append(r.Pools, PHPPool{Name: p.Name, User: p.User, Sites: siteNames(sites), Roots: capList(phpconf.Roots(sites))})
			}
		case "apache2handler":
			var sites []phpconf.Site
			for _, s := range h.Web.ApacheSites() {
				if s.Backend == "" {
					sites = append(sites, s)
				}
			}
			r.Sites, r.Roots = siteNames(sites), capList(phpconf.Roots(sites))
		}
		out = append(out, r)
	}
	return out
}

// phpStatus: 8.1 and older are past their end of life (8.1 ended
// 2025-12-31), 8.2 gets security fixes only.
func phpStatus(version string) string {
	major, minor := parseMajorMinor(version)
	switch {
	case major == 0:
		return "unknown"
	case major < 8 || (major == 8 && minor < 2):
		return "eol"
	case major == 8 && minor == 2:
		return "outdated"
	}
	return "up_to_date"
}

func siteNames(sites []phpconf.Site) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range sites {
		name := s.Root
		if len(s.Names) > 0 {
			name = s.Names[0]
		}
		if name != "" && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return capList(out)
}

func capList(l []string) []string {
	if len(l) > maxPHPSites {
		return l[:maxPHPSites]
	}
	return l
}
