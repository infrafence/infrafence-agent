package preflight

import (
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Hosting accounts and their domains, read from the panel's own files (or,
// on Plesk, a read-only query of its database). Shown by "infrafence-agent
// panel sites". Nothing is changed and nothing fails without a panel.

// Site is one domain hosted on the server.
type Site struct {
	Account      string `json:"account,omitempty"`
	Domain       string `json:"domain"`
	Kind         string `json:"kind"` // main, addon, sub, parked, site
	DocumentRoot string `json:"document_root,omitempty"`
}

const maxSites = 20000

var (
	domainRe  = regexp.MustCompile(`^[A-Za-z0-9*_]([A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$`)
	accountRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
)

func validDomain(d string) bool  { return domainRe.MatchString(d) && strings.Contains(d, ".") }
func validAccount(a string) bool { return accountRe.MatchString(a) && a != "." && a != ".." }
func validRoot(p string) bool {
	return filepath.IsAbs(p) && filepath.Clean(p) == p && p != "/" && !strings.ContainsAny(p, "\n\r\t\x00")
}

// DetectSites lists the sites of the hosting panel on this host.
func DetectSites(panelID string) []Site { return DetectSitesEnv(hostEnv{}, panelID) }

// DetectSitesEnv lists the sites through env.
func DetectSitesEnv(env Env, panelID string) []Site {
	var sites []Site
	switch panelID {
	case "cpanel":
		sites = cpanelSites(env)
	case "plesk":
		sites = pleskSites(env)
	case "directadmin":
		sites = directAdminSites(env)
	}
	if len(sites) > maxSites {
		sites = sites[:maxSites]
	}
	sort.SliceStable(sites, func(i, j int) bool {
		if sites[i].Account != sites[j].Account {
			return sites[i].Account < sites[j].Account
		}
		return sites[i].Domain < sites[j].Domain
	})
	if sites == nil {
		sites = []Site{}
	}
	return sites
}

// cpanelSites reads /var/cpanel/users (the accounts), each account's
// userdata (domains and document roots) and, for accounts without
// userdata, /etc/trueuserdomains.
func cpanelSites(env Env) []Site {
	var sites []Site
	done := map[string]bool{}
	for _, p := range env.Glob("/var/cpanel/users/*") {
		user := filepath.Base(p)
		if !validAccount(user) || user == "system" || strings.HasPrefix(user, ".") {
			continue
		}
		main, err := env.ReadFile("/var/cpanel/userdata/" + user + "/main")
		if err != nil {
			continue
		}
		done[user] = true
		ud := parseCpanelMain(main)
		root := func(domain string) string {
			s, err := env.ReadFile("/var/cpanel/userdata/" + user + "/" + domain)
			if err != nil {
				return ""
			}
			if v := yamlScalar(s, "documentroot"); validRoot(v) {
				return v
			}
			return ""
		}
		if validDomain(ud.main) {
			mainRoot := root(ud.main)
			sites = append(sites, Site{Account: user, Domain: ud.main, Kind: "main", DocumentRoot: mainRoot})
			for _, d := range ud.parked {
				if validDomain(d) {
					sites = append(sites, Site{Account: user, Domain: d, Kind: "parked", DocumentRoot: mainRoot})
				}
			}
		}
		// An addon domain is served by its subdomain's vhost.
		addonOf := map[string]string{}
		for addon, sub := range ud.addons {
			if validDomain(addon) && validDomain(sub) {
				addonOf[sub] = addon
				sites = append(sites, Site{Account: user, Domain: addon, Kind: "addon", DocumentRoot: root(sub)})
			}
		}
		for _, d := range ud.subs {
			if validDomain(d) && addonOf[d] == "" {
				sites = append(sites, Site{Account: user, Domain: d, Kind: "sub", DocumentRoot: root(d)})
			}
		}
	}
	if tud, err := env.ReadFile("/etc/trueuserdomains"); err == nil {
		for _, line := range strings.Split(tud, "\n") {
			d, u, ok := strings.Cut(line, ":")
			d, u = strings.TrimSpace(d), strings.TrimSpace(u)
			if !ok || done[u] || !validDomain(d) || !validAccount(u) {
				continue
			}
			s := Site{Account: u, Domain: d, Kind: "main"}
			if r := "/home/" + u + "/public_html"; env.Exists(r) {
				s.DocumentRoot = r
			}
			sites = append(sites, s)
		}
	}
	return sites
}

type cpanelUserdata struct {
	main   string
	parked []string
	subs   []string
	addons map[string]string
}

// parseCpanelMain reads the few keys needed from userdata/<user>/main, a
// small YAML file of this shape:
//
//	addon_domains:
//	  addon.com: addon.example.com
//	main_domain: example.com
//	parked_domains:
//	  - parked.com
//	sub_domains:
//	  - addon.example.com
func parseCpanelMain(s string) cpanelUserdata {
	ud := cpanelUserdata{addons: map[string]string{}}
	section := ""
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "---") {
			continue
		}
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "-") {
			k, v, _ := strings.Cut(line, ":")
			section = strings.TrimSpace(k)
			if section == "main_domain" {
				ud.main = unquote(v)
			}
			continue
		}
		item := strings.TrimSpace(line)
		switch section {
		case "parked_domains":
			ud.parked = append(ud.parked, unquote(strings.TrimPrefix(item, "-")))
		case "sub_domains":
			ud.subs = append(ud.subs, unquote(strings.TrimPrefix(item, "-")))
		case "addon_domains":
			if k, v, ok := strings.Cut(item, ":"); ok {
				ud.addons[unquote(k)] = unquote(v)
			}
		}
	}
	return ud
}

// yamlScalar returns a top-level "key: value" of a simple YAML file.
func yamlScalar(s, key string) string {
	for _, line := range strings.Split(s, "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok && k == key {
			return unquote(v)
		}
	}
	return ""
}

func unquote(s string) string { return strings.Trim(strings.TrimSpace(s), `'"`) }

// pleskQuery lists every domain with hosting, its document root and system
// user. Read-only.
const pleskQuery = "SELECT d.name, h.www_root, IFNULL(s.login, '') FROM domains d " +
	"JOIN hosting h ON h.dom_id = d.id LEFT JOIN sys_users s ON s.id = h.sys_user_id ORDER BY d.name"

// pleskSites queries the Plesk database read-only; when that fails, it
// lists the sites with "plesk bin site --list" and the default document
// root under /var/www/vhosts.
func pleskSites(env Env) []Site {
	plesk := firstExisting(env, pleskPaths)
	if plesk == "" {
		return nil
	}
	var sites []Site
	if out, err := env.Run(plesk, "db", "-Ne", pleskQuery); err == nil {
		for _, line := range strings.Split(out, "\n") {
			f := strings.Split(line, "\t")
			if len(f) != 3 || !validDomain(f[0]) {
				continue
			}
			s := Site{Domain: f[0], Kind: "site"}
			if validRoot(f[1]) {
				s.DocumentRoot = f[1]
			}
			if validAccount(f[2]) {
				s.Account = f[2]
			}
			sites = append(sites, s)
		}
		if len(sites) > 0 {
			return sites
		}
	}
	out, err := env.Run(plesk, "bin", "site", "--list")
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(out, "\n") {
		d := strings.TrimSpace(line)
		if !validDomain(d) {
			continue
		}
		s := Site{Domain: d, Kind: "site"}
		if r := "/var/www/vhosts/" + d + "/httpdocs"; env.Exists(r) {
			s.DocumentRoot = r
		}
		sites = append(sites, s)
	}
	return sites
}

// directAdminSites reads each user's domains.list.
func directAdminSites(env Env) []Site {
	var sites []Site
	for _, p := range env.Glob("/usr/local/directadmin/data/users/*/domains.list") {
		user := filepath.Base(filepath.Dir(p))
		if !validAccount(user) {
			continue
		}
		list, err := env.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(list, "\n") {
			d := strings.TrimSpace(line)
			if !validDomain(d) {
				continue
			}
			s := Site{Account: user, Domain: d, Kind: "site"}
			if r := "/home/" + user + "/domains/" + d + "/public_html"; env.Exists(r) {
				s.DocumentRoot = r
			}
			sites = append(sites, s)
		}
	}
	return sites
}
