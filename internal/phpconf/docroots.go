package phpconf

import (
	"path"
	"regexp"
	"strings"
)

// DocRoot is one document root a web server configuration names.
type DocRoot struct {
	Root   string
	Names  []string // ServerName / server_name / vhDomain, when known
	Server string   // apache, nginx, litespeed, plesk
}

// Bounds of the document root discovery: configuration files read (each at
// most maxFileSize) and roots returned.
const (
	docRootMaxFiles = 5000
	docRootMax      = 2000
)

var (
	// Main configuration files and the server root their relative
	// includes resolve against.
	apacheMains = []struct{ file, root string }{
		{"/etc/apache2/apache2.conf", "/etc/apache2"},    // Debian, Ubuntu
		{"/etc/httpd/conf/httpd.conf", "/etc/httpd"},     // RHEL family
		{"/etc/apache2/conf/httpd.conf", "/etc/apache2"}, // cPanel EA4 (LiteSpeed on cPanel reads it too)
		{"/usr/local/apache/conf/httpd.conf", "/usr/local/apache"},
	}
	// Read even when no main file includes them (a hand-written layout).
	apacheExtra = []string{
		"/etc/apache2/sites-enabled/*",
		"/etc/apache2/conf.d/*.conf",
		"/etc/httpd/conf.d/*.conf",
		"/var/www/vhosts/system/*/conf/httpd.conf", // Plesk
	}
	nginxExtra = []string{
		"/etc/nginx/sites-enabled/*",
		"/etc/nginx/conf.d/*.conf",
		"/var/www/vhosts/system/*/conf/nginx.conf", // Plesk
	}
	lswsMains = []string{
		"/usr/local/lsws/conf/httpd_config.conf", // OpenLiteSpeed, CyberPanel
		"/usr/local/lsws/conf/httpd_config.xml",  // LiteSpeed Enterprise (own configuration)
	}
	lswsExtra = []string{
		"/usr/local/lsws/conf/vhosts/*/vhconf.conf",
		"/usr/local/lsws/conf/vhosts/*/vhost.conf",
		"/usr/local/lsws/conf/vhosts/*/vhconf.xml",
	}

	ngRootAllRe = regexp.MustCompile(`(?:^|[{;])\s*root\s+("[^"]+"|'[^']+'|[^;\s]+)\s*;`)

	lsVhostRe    = regexp.MustCompile(`^\s*virtualhost\s+(\S+)\s*\{`)
	lsKeyRe      = regexp.MustCompile(`^\s*(vhRoot|configFile|docRoot|vhDomain|vhAliases)\s+(.+?)\s*$`)
	lsXMLVhostRe = regexp.MustCompile(`(?i)<virtualHost>`)
	lsXMLEndRe   = regexp.MustCompile(`(?i)</virtualHost>`)
	lsXMLKeyRe   = regexp.MustCompile(`<(name|vhRoot|configFile|docRoot|vhDomain)>\s*([^<]+?)\s*</`)
)

// DocRoots lists the document roots of every enabled site: Apache
// (DocumentRoot inside or outside a virtual host, following Include and
// IncludeOptional), nginx (every root directive), OpenLiteSpeed and
// LiteSpeed (virtual host docRoot) and Plesk's vhost directories. Read
// only and bounded: at most docRootMaxFiles configuration files and
// docRootMax roots. Roots that use a variable the configuration does not
// define are left out; nothing is checked for existence.
func DocRoots(env Env) []DocRoot {
	var out []DocRoot
	seen := map[string]bool{}
	add := func(r DocRoot) {
		r.Root = strings.Trim(strings.TrimSpace(r.Root), `"'`)
		if r.Root == "" || !strings.HasPrefix(r.Root, "/") || strings.ContainsAny(r.Root, "$%{}*?[") || len(out) >= docRootMax {
			return
		}
		r.Root = path.Clean(r.Root)
		if seen[r.Root] {
			return
		}
		seen[r.Root] = true
		out = append(out, r)
	}

	files := map[string]bool{}
	// Apache.
	var lines []string
	for _, m := range apacheMains {
		if env.Exists(m.file) {
			lines = append(lines, expandLimit(env, m.file, m.root, apacheIncludeRe, files, 0, docRootMaxFiles)...)
		}
	}
	for _, g := range apacheExtra {
		for _, f := range env.Glob(g) {
			lines = append(lines, expandLimit(env, f, "/etc/apache2", apacheIncludeRe, files, 0, docRootMaxFiles)...)
		}
	}
	for _, r := range apacheDocRoots(lines) {
		add(r)
	}

	// nginx.
	lines = nil
	if env.Exists("/etc/nginx/nginx.conf") {
		lines = expandLimit(env, "/etc/nginx/nginx.conf", "/etc/nginx", nginxIncludeRe, files, 0, docRootMaxFiles)
	}
	for _, g := range nginxExtra {
		for _, f := range env.Glob(g) {
			lines = append(lines, expandLimit(env, f, "/etc/nginx", nginxIncludeRe, files, 0, docRootMaxFiles)...)
		}
	}
	for _, r := range nginxDocRoots(lines) {
		add(r)
	}

	// OpenLiteSpeed / LiteSpeed's own configuration (on cPanel LiteSpeed
	// reads Apache's, covered above).
	for _, r := range liteSpeedDocRoots(env, files) {
		add(r)
	}

	// Plesk: /var/www/vhosts/<domain>/httpdocs, old subdomains/<sub>/httpdocs,
	// and the directories of additional domains and subdomains
	// (/var/www/vhosts/<domain>/<sub.domain>).
	if env.Exists("/var/www/vhosts") {
		for _, d := range env.Glob("/var/www/vhosts/*/httpdocs") {
			add(DocRoot{Root: d, Names: []string{path.Base(path.Dir(d))}, Server: "plesk"})
		}
		for _, d := range env.Glob("/var/www/vhosts/*/subdomains/*/httpdocs") {
			sub := path.Base(path.Dir(d))
			dom := path.Base(path.Dir(path.Dir(path.Dir(d))))
			add(DocRoot{Root: d, Names: []string{sub + "." + dom}, Server: "plesk"})
		}
		for _, d := range env.Glob("/var/www/vhosts/*/*.*") {
			dom := path.Base(path.Dir(d))
			if dom == "system" || dom == "default" || !strings.Contains(path.Base(d), ".") {
				continue
			}
			if env.Exists(d+"/index.php") || env.Exists(d+"/index.html") || env.Exists(d+"/wp-config.php") {
				add(DocRoot{Root: d, Names: []string{path.Base(d)}, Server: "plesk"})
			}
		}
	}
	return out
}

func apacheDocRoots(lines []string) []DocRoot {
	var out []DocRoot
	var cur *DocRoot // the virtual host being read
	var names []string
	root := ""
	flush := func() {
		if root != "" {
			out = append(out, DocRoot{Root: root, Names: names, Server: "apache"})
		}
		root, names = "", nil
	}
	for _, l := range lines {
		if apVhostRe.MatchString(l) {
			cur = &DocRoot{}
			root, names = "", nil
			continue
		}
		if apVhostEnd.MatchString(l) {
			flush()
			cur = nil
			continue
		}
		if m := apRootRe.FindStringSubmatch(l); m != nil {
			if cur == nil {
				// The server's own DocumentRoot (RHEL's /var/www/html).
				out = append(out, DocRoot{Root: m[1], Server: "apache"})
			} else {
				root = m[1]
			}
		}
		if m := apNameRe.FindStringSubmatch(l); m != nil && cur != nil {
			names = append(names, strings.Fields(m[1])...)
		}
	}
	return out
}

func nginxDocRoots(lines []string) []DocRoot {
	var out []DocRoot
	depth, start := 0, -1
	var names []string
	var roots []string
	inServer := false
	for _, l := range lines {
		if i := strings.IndexByte(l, '#'); i >= 0 {
			l = l[:i]
		}
		if !inServer && ngServerRe.MatchString(l) {
			inServer, start, names, roots = true, depth, nil, nil
		}
		for _, m := range ngRootAllRe.FindAllStringSubmatch(l, -1) {
			if inServer {
				roots = append(roots, m[1])
			} else {
				out = append(out, DocRoot{Root: m[1], Server: "nginx"})
			}
		}
		if inServer {
			if m := ngNameRe.FindStringSubmatch(l); m != nil {
				names = append(names, strings.Fields(m[1])...)
			}
		}
		depth += strings.Count(l, "{") - strings.Count(l, "}")
		if inServer && depth <= start {
			for _, r := range roots {
				out = append(out, DocRoot{Root: r, Names: names, Server: "nginx"})
			}
			inServer = false
		}
	}
	return out
}

// lsVhost is one LiteSpeed virtual host as its configuration says.
type lsVhost struct {
	name, vhRoot, configFile, docRoot string
	names                             []string
}

// lsSubst replaces LiteSpeed's variables; ok is false when one is left.
func lsSubst(v string, h lsVhost) (string, bool) {
	v = strings.Trim(strings.TrimSpace(v), `"'`)
	v = strings.ReplaceAll(v, "$SERVER_ROOT", "/usr/local/lsws")
	v = strings.ReplaceAll(v, "$VH_NAME", h.name)
	if strings.Contains(v, "$VH_ROOT") {
		if h.vhRoot == "" {
			return "", false
		}
		vh := strings.TrimSuffix(h.vhRoot, "/")
		if !strings.HasPrefix(vh, "/") && !strings.HasPrefix(vh, "$") {
			vh = "/usr/local/lsws/" + vh // relative to the server root
		}
		vh, ok := lsSubst(vh, lsVhost{name: h.name})
		if !ok {
			return "", false
		}
		v = strings.ReplaceAll(v, "$VH_ROOT", vh)
	}
	if strings.Contains(v, "$") {
		return "", false
	}
	return v, true
}

func liteSpeedDocRoots(env Env, files map[string]bool) []DocRoot {
	var hosts []lsVhost
	read := func(f string) (string, bool) {
		if files[f] || len(files) >= docRootMaxFiles {
			return "", false
		}
		files[f] = true
		return readSmall(env, f)
	}
	for _, main := range lswsMains {
		c, ok := read(main)
		if !ok {
			continue
		}
		if strings.HasSuffix(main, ".xml") {
			var cur *lsVhost
			for _, l := range strings.Split(c, "\n") {
				if lsXMLVhostRe.MatchString(l) {
					hosts = append(hosts, lsVhost{})
					cur = &hosts[len(hosts)-1]
				}
				if cur != nil {
					for _, m := range lsXMLKeyRe.FindAllStringSubmatch(l, -1) {
						lsSet(cur, m[1], m[2])
					}
				}
				if lsXMLEndRe.MatchString(l) {
					cur = nil
				}
			}
			continue
		}
		depth, start := 0, -1
		var cur *lsVhost
		for _, l := range strings.Split(c, "\n") {
			if i := strings.IndexByte(l, '#'); i >= 0 {
				l = l[:i]
			}
			if m := lsVhostRe.FindStringSubmatch(l); m != nil && cur == nil {
				hosts = append(hosts, lsVhost{name: m[1]})
				cur, start = &hosts[len(hosts)-1], depth
			} else if cur != nil && depth == start+1 {
				if m := lsKeyRe.FindStringSubmatch(l); m != nil {
					lsSet(cur, m[1], m[2])
				}
			}
			depth += strings.Count(l, "{") - strings.Count(l, "}")
			if cur != nil && depth <= start {
				cur = nil
			}
		}
	}
	// Virtual host files nothing above pointed to: their directory is the
	// virtual host's name.
	known := map[string]bool{}
	for _, h := range hosts {
		if f, ok := lsSubst(h.configFile, h); ok {
			known[path.Clean(f)] = true
		}
	}
	for _, g := range lswsExtra {
		for _, f := range env.Glob(g) {
			if !known[f] {
				hosts = append(hosts, lsVhost{name: path.Base(path.Dir(f)), configFile: f, vhRoot: "/usr/local/lsws/" + path.Base(path.Dir(f))})
				known[f] = true
			}
		}
	}

	var out []DocRoot
	for _, h := range hosts {
		if h.configFile != "" {
			if f, ok := lsSubst(h.configFile, h); ok {
				if c, ok := read(path.Clean(f)); ok {
					for _, l := range strings.Split(c, "\n") {
						if i := strings.IndexByte(l, '#'); i >= 0 {
							l = l[:i]
						}
						if m := lsXMLKeyRe.FindStringSubmatch(l); m != nil && m[1] == "docRoot" && h.docRoot == "" {
							h.docRoot = m[2]
						} else if m := lsKeyRe.FindStringSubmatch(l); m != nil && m[1] == "docRoot" && h.docRoot == "" {
							h.docRoot = m[2]
						} else if m != nil && (m[1] == "vhDomain" || m[1] == "vhAliases") {
							lsSet(&h, m[1], m[2])
						}
					}
				}
			}
		}
		if h.docRoot == "" {
			continue
		}
		if r, ok := lsSubst(h.docRoot, h); ok {
			names := h.names
			if len(names) == 0 && strings.Contains(h.name, ".") {
				names = []string{h.name}
			}
			out = append(out, DocRoot{Root: r, Names: names, Server: "litespeed"})
		}
	}
	return out
}

func lsSet(h *lsVhost, key, val string) {
	val = strings.Trim(strings.TrimSpace(val), `"'`)
	switch key {
	case "name":
		h.name = val
	case "vhRoot":
		h.vhRoot = val
	case "configFile":
		h.configFile = val
	case "docRoot":
		h.docRoot = val
	case "vhDomain", "vhAliases":
		for _, n := range strings.FieldsFunc(val, func(r rune) bool { return r == ',' || r == ' ' }) {
			if n != "*" && n != "" {
				h.names = append(h.names, n)
			}
		}
	}
}
