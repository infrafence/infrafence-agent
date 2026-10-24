package phpconf

import (
	"path"
	"regexp"
	"sort"
	"strings"
)

// Site is one web server virtual host.
type Site struct {
	Names []string
	Root  string
	HTTPS bool
	// Backend is where it sends PHP requests (a normalized FPM listen
	// address), "" for mod_php or none.
	Backend string
	Server  string // nginx or apache
}

// WebMap is what the web server configuration says about PHP.
type WebMap struct {
	Nginx  bool // nginx is installed
	Apache bool
	Sites  []Site
}

// SitesFor returns the sites whose PHP requests go to listen.
func (w WebMap) SitesFor(listen string) []Site {
	var out []Site
	for _, s := range w.Sites {
		if listen != "" && s.Backend == listen {
			out = append(out, s)
		}
	}
	return out
}

// ApacheSites returns the Apache virtual hosts (mod_php serves them all).
func (w WebMap) ApacheSites() []Site {
	var out []Site
	for _, s := range w.Sites {
		if s.Server == "apache" {
			out = append(out, s)
		}
	}
	return out
}

// Roots returns the distinct document roots of sites.
func Roots(sites []Site) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range sites {
		if s.Root != "" && !seen[s.Root] {
			seen[s.Root] = true
			out = append(out, s.Root)
		}
	}
	sort.Strings(out)
	return out
}

// AnyHTTPS reports whether one of sites is served over HTTPS.
func AnyHTTPS(sites []Site) bool {
	for _, s := range sites {
		if s.HTTPS {
			return true
		}
	}
	return false
}

const maxIncludes = 500

// ReadWebMap reads the nginx and Apache configuration (following includes)
// and records, per server block or virtual host, its root, whether it
// serves HTTPS and the FPM address its PHP requests go to.
func ReadWebMap(env Env) WebMap {
	var w WebMap
	if env.Exists("/etc/nginx/nginx.conf") {
		w.Nginx = true
		lines := expand(env, "/etc/nginx/nginx.conf", "/etc/nginx", nginxIncludeRe, map[string]bool{}, 0)
		w.Sites = append(w.Sites, nginxSites(lines)...)
	}
	for _, main := range []string{"/etc/apache2/apache2.conf", "/etc/httpd/conf/httpd.conf"} {
		if env.Exists(main) {
			w.Apache = true
			root := path.Dir(main)
			if strings.HasPrefix(main, "/etc/httpd") {
				root = "/etc/httpd"
			}
			lines := expand(env, main, root, apacheIncludeRe, map[string]bool{}, 0)
			w.Sites = append(w.Sites, apacheSites(lines)...)
			break
		}
	}
	return w
}

var (
	nginxIncludeRe  = regexp.MustCompile(`^\s*include\s+([^;\s]+)\s*;`)
	apacheIncludeRe = regexp.MustCompile(`(?i)^\s*Include(?:Optional)?\s+"?([^"\s]+)"?`)
)

// expand returns file's lines with every include replaced by the files it
// names, at most maxIncludes files.
func expand(env Env, file, root string, inc *regexp.Regexp, seen map[string]bool, depth int) []string {
	if seen[file] || len(seen) >= maxIncludes || depth > 8 {
		return nil
	}
	seen[file] = true
	c, ok := readSmall(env, file)
	if !ok {
		return nil
	}
	var out []string
	for _, l := range strings.Split(c, "\n") {
		if t := strings.TrimSpace(l); strings.HasPrefix(t, "#") {
			continue
		}
		if m := inc.FindStringSubmatch(l); m != nil {
			pat := m[1]
			if !strings.HasPrefix(pat, "/") {
				pat = path.Join(root, pat)
			}
			if strings.HasSuffix(pat, "/") || (!strings.ContainsAny(pat, "*?[") && !strings.Contains(path.Base(pat), ".")) {
				pat = strings.TrimSuffix(pat, "/") + "/*"
			}
			for _, f := range env.Glob(pat) {
				out = append(out, expand(env, f, root, inc, seen, depth+1)...)
			}
			continue
		}
		out = append(out, l)
	}
	return out
}

var (
	ngServerRe   = regexp.MustCompile(`^\s*server\s*\{`)
	ngUpstreamRe = regexp.MustCompile(`^\s*upstream\s+(\S+)\s*\{`)
	ngUpServerRe = regexp.MustCompile(`^\s*server\s+([^;\s]+)`)
	ngRootRe     = regexp.MustCompile(`(?:^|[{;])\s*root\s+"?([^;"\s]+)"?\s*;`)
	ngListenRe   = regexp.MustCompile(`(?:^|[{;])\s*listen\s+([^;]+);`)
	ngNameRe     = regexp.MustCompile(`(?:^|[{;])\s*server_name\s+([^;]+);`)
	ngPassRe     = regexp.MustCompile(`(?:^|[{;])\s*fastcgi_pass\s+([^;\s]+)\s*;`)
)

func nginxSites(lines []string) []Site {
	upstreams := map[string]string{}
	var sites []Site
	depth, start := 0, -1
	upstream, upDepth := "", -1
	var cur *Site
	for _, l := range lines {
		if i := strings.IndexByte(l, '#'); i >= 0 {
			l = l[:i]
		}
		if m := ngUpstreamRe.FindStringSubmatch(l); m != nil {
			upstream, upDepth = m[1], depth
			// "upstream php { server unix:/x.sock; }" on one line.
			if m := ngUpServerRe.FindStringSubmatch(l[strings.IndexByte(l, '{')+1:]); m != nil {
				upstreams[upstream] = normListen(m[1])
			}
		} else if upstream != "" {
			if m := ngUpServerRe.FindStringSubmatch(l); m != nil {
				if _, ok := upstreams[upstream]; !ok {
					upstreams[upstream] = normListen(m[1])
				}
			}
		} else if ngServerRe.MatchString(l) && cur == nil {
			sites = append(sites, Site{Server: "nginx"})
			cur, start = &sites[len(sites)-1], depth
		} else if cur != nil {
			if m := ngRootRe.FindStringSubmatch(l); m != nil && cur.Root == "" {
				cur.Root = path.Clean(m[1])
			}
			if m := ngListenRe.FindStringSubmatch(l); m != nil {
				f := " " + m[1] + " "
				if strings.Contains(f, " ssl ") || strings.Contains(f, ":443 ") || strings.Contains(f, " 443 ") || strings.Contains(f, " quic ") {
					cur.HTTPS = true
				}
			}
			if m := ngNameRe.FindStringSubmatch(l); m != nil {
				cur.Names = append(cur.Names, strings.Fields(m[1])...)
			}
			if m := ngPassRe.FindStringSubmatch(l); m != nil && cur.Backend == "" {
				cur.Backend = m[1]
			}
		}
		depth += strings.Count(l, "{") - strings.Count(l, "}")
		if upstream != "" && depth <= upDepth {
			upstream = ""
		}
		if cur != nil && depth <= start {
			cur = nil
		}
	}
	for i := range sites {
		b := sites[i].Backend
		if b == "" {
			continue
		}
		if u, ok := upstreams[b]; ok {
			sites[i].Backend = u
		} else {
			sites[i].Backend = normListen(b)
		}
	}
	return sites
}

var (
	apVhostRe   = regexp.MustCompile(`(?i)^\s*<VirtualHost\s+([^>]+)>`)
	apVhostEnd  = regexp.MustCompile(`(?i)^\s*</VirtualHost>`)
	apRootRe    = regexp.MustCompile(`(?i)^\s*DocumentRoot\s+"?([^"\s]+)"?`)
	apNameRe    = regexp.MustCompile(`(?i)^\s*Server(?:Name|Alias)\s+(.+)$`)
	apSSLRe     = regexp.MustCompile(`(?i)^\s*SSLEngine\s+on`)
	apHandlerRe = regexp.MustCompile(`(?i)(?:SetHandler|ProxyPassMatch)\s+.*?"?proxy:(unix:[^|"\s]+|fcgi://[^/"\s]+)`)
	apFcgiRe    = regexp.MustCompile(`(?i)ProxyPassMatch\s+\S+\s+"?fcgi://([^/"\s]+)`)
)

func apacheSites(lines []string) []Site {
	var sites []Site
	global := ""
	var cur *Site
	backend := func(l string) string {
		if m := apHandlerRe.FindStringSubmatch(l); m != nil {
			v := m[1]
			if strings.HasPrefix(strings.ToLower(v), "fcgi://") {
				v = v[len("fcgi://"):]
			}
			return normListen(v)
		}
		if m := apFcgiRe.FindStringSubmatch(l); m != nil {
			return normListen(m[1])
		}
		return ""
	}
	for _, l := range lines {
		if m := apVhostRe.FindStringSubmatch(l); m != nil {
			sites = append(sites, Site{Server: "apache", HTTPS: strings.Contains(m[1], ":443")})
			cur = &sites[len(sites)-1]
			continue
		}
		if apVhostEnd.MatchString(l) {
			cur = nil
			continue
		}
		b := backend(l)
		if cur == nil {
			if b != "" && global == "" {
				global = b
			}
			continue
		}
		if m := apRootRe.FindStringSubmatch(l); m != nil {
			cur.Root = path.Clean(m[1])
		}
		if m := apNameRe.FindStringSubmatch(l); m != nil {
			cur.Names = append(cur.Names, strings.Fields(m[1])...)
		}
		if apSSLRe.MatchString(l) {
			cur.HTTPS = true
		}
		if b != "" && cur.Backend == "" {
			cur.Backend = b
		}
	}
	// A handler set outside any virtual host (Debian's php-fpm conf, RHEL's
	// php.conf) serves every one that doesn't set its own.
	for i := range sites {
		if sites[i].Backend == "" {
			sites[i].Backend = global
		}
	}
	return sites
}
