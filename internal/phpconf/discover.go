package phpconf

import (
	"path"
	"regexp"
	"sort"
	"strings"
)

// Runtime is one PHP installation as one SAPI uses it: the files it loads
// and, for PHP-FPM, its pools.
type Runtime struct {
	// ID is stable across PHP updates: "debian-8.2-fpm", "rhel-system-fpm",
	// "remi-php82-fpm", "ea-php82-fpm", "plesk-8.2-fpm", "alt-php82-cgi".
	ID      string
	Family  string // debian, rhel, remi, cpanel, plesk, cloudlinux
	Version string // "8.2" when the layout says it
	SAPI    string // fpm, apache2handler, cgi
	Ini     string // the php.ini it loads
	ScanDir string // the directory of extra .ini files it scans after php.ini
	// CLI is a php binary of the same installation, used to confirm the
	// effective value of a setting ("" if there is none).
	CLI     string
	FPM     string // php-fpm binary
	FPMConf string // php-fpm.conf
	// PoolGlob is php-fpm.conf's include= pattern for the pool files.
	PoolGlob string
	// Service is the unit reloaded after a change ("" = the web server's).
	Service string
	// Panel names the hosting panel that manages this runtime ("" = none):
	// its files are reported, never changed.
	Panel    string
	Settings []Directive // php.ini, then the scan directory in PHP's order
	Pools    []Pool
	Files    []string // every file read, for the watcher
}

// Pool is one PHP-FPM pool.
type Pool struct {
	Name   string
	File   string   // the first file that defines it
	Files  []string // every file with a section for it
	Listen string   // normalized: a socket path or host:port
	User   string
	// Overrides are its php_value/php_flag/php_admin_value/php_admin_flag
	// settings, in file order.
	Overrides []Directive
}

// SiteOverride is a per-site file a hosting panel writes (Plesk's
// /var/www/vhosts/system/<domain>/etc/php.ini, cPanel's .user.ini).
type SiteOverride struct {
	Site     string
	File     string
	Panel    string
	Settings []Directive
}

// Host is everything discovery found.
type Host struct {
	Runtimes []Runtime
	Sites    []SiteOverride
	Web      WebMap
}

// Get returns the effective value of key for the runtime itself.
func (rt Runtime) Get(key string) Directive { return lookup(rt.Settings, key) }

// GetPool returns the effective value of key in pool p: its override
// when it has one PHP honours, else the runtime's.
func (rt Runtime) GetPool(p Pool, key string) Directive {
	for i := len(p.Overrides) - 1; i >= 0; i-- {
		d := p.Overrides[i]
		if d.Key == key && (d.Admin || !systemOnly[key]) {
			return d
		}
	}
	return rt.Get(key)
}

// WithoutFile is the runtime as it would be without file (a drop-in of
// ours), settings and pool overrides alike.
func (rt Runtime) WithoutFile(file string) Runtime {
	out := rt
	out.Settings = nil
	for _, d := range rt.Settings {
		if d.File != file {
			out.Settings = append(out.Settings, d)
		}
	}
	out.Pools = nil
	for _, p := range rt.Pools {
		q := p
		q.Overrides = nil
		for _, d := range p.Overrides {
			if d.File != file {
				q.Overrides = append(q.Overrides, d)
			}
		}
		out.Pools = append(out.Pools, q)
	}
	return out
}

// Pool returns the pool called name.
func (rt Runtime) Pool(name string) (Pool, bool) {
	for _, p := range rt.Pools {
		if p.Name == name {
			return p, true
		}
	}
	return Pool{}, false
}

// Find returns the runtime with id.
func (h Host) Find(id string) (Runtime, bool) {
	for _, rt := range h.Runtimes {
		if rt.ID == id {
			return rt, true
		}
	}
	return Runtime{}, false
}

// Files lists every configuration file discovery read.
func (h Host) Files() []string {
	seen := map[string]bool{}
	var out []string
	add := func(f string) {
		if f != "" && !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	for _, rt := range h.Runtimes {
		for _, f := range rt.Files {
			add(f)
		}
	}
	for _, s := range h.Sites {
		add(s.File)
	}
	sort.Strings(out)
	return out
}

const (
	panelCPanel = "cPanel (EA4 MultiPHP)"
	panelPlesk  = "Plesk"
	panelAlt    = "CloudLinux PHP Selector"
)

var (
	verDirRe = regexp.MustCompile(`^\d+\.\d+$`)
	verTagRe = regexp.MustCompile(`^(?:ea-|alt-)?php(\d)(\d+)$`)
	modPHPRe = regexp.MustCompile(`(?m)^\s*LoadModule\s+php\S*_module`)
)

// Discover finds every PHP runtime, its configuration and the sites.
func Discover(env Env) Host {
	var h Host
	h.Runtimes = append(h.Runtimes, debianRuntimes(env)...)
	h.Runtimes = append(h.Runtimes, rhelRuntimes(env)...)
	h.Runtimes = append(h.Runtimes, sclRuntimes(env)...)
	h.Web = ReadWebMap(env)
	h.Sites = siteOverrides(env)
	return h
}

// debianRuntimes: Debian/Ubuntu packages and ondrej's, /etc/php/X.Y/<sapi>.
func debianRuntimes(env Env) []Runtime {
	var out []Runtime
	for _, dir := range env.Glob("/etc/php/*") {
		v := path.Base(dir)
		if !verDirRe.MatchString(v) {
			continue
		}
		cli := ""
		if env.Exists("/usr/bin/php" + v) {
			cli = "/usr/bin/php" + v
		}
		for _, sapi := range []string{"fpm", "apache2", "cgi"} {
			ini := dir + "/" + sapi + "/php.ini"
			if !env.Exists(ini) {
				continue
			}
			rt := Runtime{
				ID: "debian-" + v + "-" + sapi, Family: "debian", Version: v, SAPI: sapi,
				Ini: ini, ScanDir: dir + "/" + sapi + "/conf.d", CLI: cli,
			}
			switch sapi {
			case "fpm":
				rt.FPM = "/usr/sbin/php-fpm" + v
				rt.FPMConf = dir + "/fpm/php-fpm.conf"
				rt.Service = "php" + v + "-fpm"
			case "apache2":
				rt.SAPI = "apache2handler"
			}
			out = append(out, load(env, rt))
		}
	}
	return out
}

// rhelRuntimes: the distribution's PHP (and remi's modular one), /etc/php.ini.
func rhelRuntimes(env Env) []Runtime {
	if !env.Exists("/etc/php.ini") {
		return nil
	}
	base := Runtime{Family: "rhel", Ini: "/etc/php.ini", ScanDir: "/etc/php.d"}
	if env.Exists("/usr/bin/php") {
		base.CLI = "/usr/bin/php"
	}
	var out []Runtime
	if env.Exists("/usr/sbin/php-fpm") {
		rt := base
		rt.ID, rt.SAPI = "rhel-system-fpm", "fpm"
		rt.FPM, rt.FPMConf, rt.Service = "/usr/sbin/php-fpm", "/etc/php-fpm.conf", "php-fpm"
		out = append(out, load(env, rt))
	}
	for _, f := range env.Glob("/etc/httpd/conf.modules.d/*php*.conf") {
		if c, ok := readSmall(env, f); ok && modPHPRe.MatchString(c) {
			rt := base
			rt.ID, rt.SAPI = "rhel-system-apache2handler", "apache2handler"
			out = append(out, load(env, rt))
			break
		}
	}
	return out
}

// sclRuntimes: remi's parallel versions, cPanel EA4, Plesk and CloudLinux
// alt-php, each under its own prefix.
func sclRuntimes(env Env) []Runtime {
	var out []Runtime
	for _, ini := range env.Glob("/etc/opt/remi/php*/php.ini") {
		dir := path.Dir(ini)
		tag := path.Base(dir) // php82
		v := tagVersion(tag)
		if v == "" {
			continue
		}
		rt := Runtime{Family: "remi", Version: v, Ini: ini, ScanDir: dir + "/php.d"}
		rt.CLI = existing(env, "/opt/remi/"+tag+"/root/usr/bin/php")
		if fpm := existing(env, "/opt/remi/"+tag+"/root/usr/sbin/php-fpm"); fpm != "" {
			rt.ID, rt.SAPI = "remi-"+tag+"-fpm", "fpm"
			rt.FPM, rt.FPMConf, rt.Service = fpm, dir+"/php-fpm.conf", tag+"-php-fpm"
		} else {
			rt.ID, rt.SAPI = "remi-"+tag+"-cgi", "cgi"
		}
		out = append(out, load(env, rt))
	}
	for _, ini := range env.Glob("/opt/cpanel/ea-php*/root/etc/php.ini") {
		prefix := strings.TrimSuffix(ini, "/root/etc/php.ini")
		tag := path.Base(prefix) // ea-php82
		v := tagVersion(tag)
		if v == "" {
			continue
		}
		rt := Runtime{Family: "cpanel", Version: v, Ini: ini, ScanDir: prefix + "/root/etc/php.d", Panel: panelCPanel}
		rt.CLI = existing(env, prefix+"/root/usr/bin/php")
		if fpm := existing(env, prefix+"/root/usr/sbin/php-fpm"); fpm != "" {
			rt.ID, rt.SAPI = tag+"-fpm", "fpm"
			rt.FPM, rt.FPMConf, rt.Service = fpm, prefix+"/root/etc/php-fpm.conf", tag+"-php-fpm"
		} else {
			rt.ID, rt.SAPI = tag+"-cgi", "cgi"
		}
		out = append(out, load(env, rt))
	}
	for _, ini := range env.Glob("/opt/plesk/php/*/etc/php.ini") {
		prefix := strings.TrimSuffix(ini, "/etc/php.ini")
		v := path.Base(prefix)
		if !verDirRe.MatchString(v) {
			continue
		}
		rt := Runtime{Family: "plesk", Version: v, Ini: ini, ScanDir: prefix + "/etc/php.d", Panel: panelPlesk}
		rt.CLI = existing(env, prefix+"/bin/php")
		if fpm := existing(env, prefix+"/sbin/php-fpm"); fpm != "" {
			rt.ID, rt.SAPI = "plesk-"+v+"-fpm", "fpm"
			rt.FPM, rt.FPMConf = fpm, prefix+"/etc/php-fpm.conf"
			rt.Service = "plesk-php" + strings.ReplaceAll(v, ".", "") + "-fpm"
		} else {
			rt.ID, rt.SAPI = "plesk-"+v+"-cgi", "cgi"
		}
		out = append(out, load(env, rt))
	}
	for _, ini := range env.Glob("/opt/alt/php*/etc/php.ini") {
		prefix := strings.TrimSuffix(ini, "/etc/php.ini")
		tag := "alt-" + path.Base(prefix) // alt-php82
		v := tagVersion(tag)
		if v == "" {
			continue
		}
		rt := Runtime{ID: tag + "-cgi", Family: "cloudlinux", Version: v, SAPI: "cgi", Ini: ini, Panel: panelAlt}
		rt.CLI = existing(env, prefix+"/usr/bin/php")
		rt.ScanDir = prefix + "/etc/php.d"
		if !env.Exists(rt.ScanDir) && rt.CLI != "" {
			rt.ScanDir = scanDirFromCLI(env, rt.CLI)
		}
		out = append(out, load(env, rt))
	}
	return out
}

func tagVersion(tag string) string {
	m := verTagRe.FindStringSubmatch(tag)
	if m == nil {
		return ""
	}
	return m[1] + "." + m[2]
}

func existing(env Env, p string) string {
	if env.Exists(p) {
		return p
	}
	return ""
}

// scanDirFromCLI asks a php binary which directory it scans (php --ini).
func scanDirFromCLI(env Env, cli string) string {
	out, err := env.Run(cli, "--ini")
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(l, ":"); ok && strings.HasPrefix(strings.TrimSpace(k), "Scan for additional .ini files in") {
			if v = strings.TrimSpace(v); strings.HasPrefix(v, "/") {
				return v
			}
		}
	}
	return ""
}

// load reads the runtime's php.ini, its scan directory (alphabetical, as
// PHP reads it) and its pools.
func load(env Env, rt Runtime) Runtime {
	if c, ok := readSmall(env, rt.Ini); ok {
		rt.Settings = append(rt.Settings, parseINI(rt.Ini, c)...)
		rt.Files = append(rt.Files, rt.Ini)
	}
	if rt.ScanDir != "" {
		for _, f := range env.Glob(rt.ScanDir + "/*.ini") {
			if c, ok := readSmall(env, f); ok {
				rt.Settings = append(rt.Settings, parseINI(f, c)...)
				rt.Files = append(rt.Files, f)
			}
		}
	}
	if rt.SAPI == "fpm" && rt.FPMConf != "" {
		rt.Pools, rt.PoolGlob, rt.Files = loadPools(env, rt.FPMConf, rt.Files)
	}
	return rt
}

var poolKeyRe = regexp.MustCompile(`^php_(admin_)?(value|flag)\[([^\]]+)\]$`)

// loadPools reads php-fpm.conf and the files its include= lines name. A
// pool defined in several files (FPM merges same-named sections) is one
// pool, with the overrides in load order.
func loadPools(env Env, conf string, files []string) ([]Pool, string, []string) {
	var pools []Pool
	index := map[string]int{}
	glob := ""
	var parse func(file string, depth int)
	parse = func(file string, depth int) {
		c, ok := readSmall(env, file)
		if !ok || depth > 3 {
			return
		}
		files = append(files, file)
		cur := -1
		for i, raw := range strings.Split(c, "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || line[0] == ';' || line[0] == '#' {
				continue
			}
			if line[0] == '[' {
				name := strings.Trim(line, "[] \t")
				cur = -1
				if !strings.EqualFold(name, "global") {
					if j, ok := index[name]; ok {
						cur = j
						if p := &pools[j]; p.Files[len(p.Files)-1] != file {
							p.Files = append(p.Files, file)
						}
					} else {
						index[name] = len(pools)
						cur = len(pools)
						pools = append(pools, Pool{Name: name, File: file, Files: []string{file}})
					}
				}
				continue
			}
			k, v, ok := splitKV(line)
			if !ok {
				continue
			}
			if cur < 0 {
				if k == "include" {
					pat := v
					if !strings.HasPrefix(pat, "/") {
						pat = path.Join(path.Dir(conf), pat)
					}
					if glob == "" {
						glob = pat
					}
					for _, f := range env.Glob(pat) {
						parse(f, depth+1)
					}
				}
				continue
			}
			p := &pools[cur]
			switch {
			case k == "listen":
				p.Listen = normListen(v)
			case k == "user":
				p.User = v
			default:
				if m := poolKeyRe.FindStringSubmatch(k); m != nil {
					p.Overrides = append(p.Overrides, Directive{
						Key: strings.ToLower(m[3]), Value: v, File: file, Line: i + 1, Admin: m[1] != "",
					})
				}
			}
		}
	}
	parse(conf, 0)
	return pools, glob, files
}

// normListen turns "9000", "localhost:9000", "unix:/run/x.sock" and
// "/run/x.sock" into one comparable form.
func normListen(v string) string {
	v = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(v), "unix:"))
	if strings.HasPrefix(v, "/") {
		return path.Clean(v)
	}
	if !strings.Contains(v, ":") {
		return "127.0.0.1:" + v
	}
	host, port, _ := strings.Cut(v, ":")
	if host == "localhost" || host == "" || host == "*" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	return host + ":" + port
}

// siteOverrides reads the per-site files the panels manage, read only.
func siteOverrides(env Env) []SiteOverride {
	var out []SiteOverride
	for _, f := range limit(env.Glob("/var/www/vhosts/system/*/etc/php.ini"), 2000) {
		if c, ok := readSmall(env, f); ok {
			site := path.Base(path.Dir(path.Dir(f)))
			out = append(out, SiteOverride{Site: site, File: f, Panel: panelPlesk, Settings: parseINI(f, c)})
		}
	}
	if env.Exists("/usr/local/cpanel") {
		for _, f := range limit(env.Glob("/home/*/public_html/.user.ini"), 2000) {
			if c, ok := readSmall(env, f); ok {
				site := path.Base(path.Dir(path.Dir(f)))
				out = append(out, SiteOverride{Site: site, File: f, Panel: panelCPanel, Settings: parseINI(f, c)})
			}
		}
	}
	return out
}

func limit(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
