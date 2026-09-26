package preflight

import (
	"regexp"
	"strings"
)

// Panel is the hosting control panel or server management platform that
// manages this server. It decides whether InfraFence may edit the web
// server configuration (a panel may rewrite it) and is shown in the
// dashboard.
type Panel struct {
	ID      string // stable id, e.g. "cpanel" (used for per-panel logic)
	Name    string // display name, e.g. "cPanel / WHM"
	Version string // when the panel records it in a file we can read
}

// Found reports whether a panel was detected.
func (p Panel) Found() bool { return p.ID != "" }

type panelDef struct {
	id, name string
	markers  []string // any existing path means the panel is installed
	version  func(env Env) string
}

// Markers come from each panel's documentation or install script. Order
// matters where one product contains another (Virtualmin before Webmin).
var panelDefs = []panelDef{
	{"cpanel", "cPanel / WHM", []string{"/usr/local/cpanel"}, firstLine("/usr/local/cpanel/version")},
	{"plesk", "Plesk", []string{"/usr/local/psa"}, firstField("/usr/local/psa/version")},
	{"directadmin", "DirectAdmin", []string{"/usr/local/directadmin"}, directAdminVersion},
	{"cyberpanel", "CyberPanel", []string{"/usr/local/CyberCP"}, nil},
	{"hestiacp", "HestiaCP", []string{"/usr/local/hestia"}, shellConfValue("/usr/local/hestia/conf/hestia.conf", "VERSION")},
	{"vestacp", "VestaCP", []string{"/usr/local/vesta"}, nil},
	{"ispconfig", "ISPConfig", []string{"/usr/local/ispconfig"}, nil},
	{"cloudpanel", "CloudPanel", []string{"/home/clp"}, nil},
	{"cwp", "CentOS Web Panel (CWP)", []string{"/usr/local/cwpsrv"}, nil},
	{"aapanel", "aaPanel", []string{"/www/server/panel"}, nil},
	{"keyhelp", "KeyHelp", []string{"/home/keyhelp/www/keyhelp"}, nil},
	{"froxlor", "Froxlor", []string{"/var/www/html/froxlor/lib/userdata.inc.php", "/var/www/froxlor/lib/userdata.inc.php"}, nil},
	{"enhance", "Enhance", []string{"/var/local/enhance"}, nil},
	{"virtualmin", "Virtualmin", []string{"/etc/webmin/virtual-server"}, firstLine("/etc/webmin/version")},
	{"webmin", "Webmin", []string{"/etc/webmin/miniserv.conf"}, firstLine("/etc/webmin/version")},
	{"coolify", "Coolify", []string{"/data/coolify"}, nil},
	{"dokploy", "Dokploy", []string{"/etc/dokploy"}, nil},
	{"easypanel", "Easypanel", []string{"/etc/easypanel"}, nil},
	{"caprover", "CapRover", []string{"/captain"}, nil},
	{"runcloud", "RunCloud", []string{"/etc/runcloud"}, nil},
	{"gridpane", "GridPane", []string{"/etc/gridpane"}, nil},
	{"forge", "Laravel Forge", []string{"/home/forge"}, nil},
	{"ploi", "Ploi", []string{"/home/ploi/.ploi"}, nil},
	{"bitnami", "Bitnami", []string{"/opt/bitnami"}, nil},
}

// DetectPanel inspects the current host.
func DetectPanel() Panel { return detectPanel(hostEnv{}) }

func detectPanel(env Env) Panel {
	for _, d := range panelDefs {
		for _, m := range d.markers {
			if !env.Exists(m) {
				continue
			}
			p := Panel{ID: d.id, Name: d.name}
			if d.version != nil {
				p.Version = d.version(env)
			}
			return p
		}
	}
	return Panel{}
}

var versionLike = regexp.MustCompile(`^v?[0-9][0-9A-Za-z.\-+_]{0,40}$`)

func clean(v string) string {
	v = strings.TrimSpace(v)
	if !versionLike.MatchString(v) {
		return ""
	}
	return strings.TrimPrefix(v, "v")
}

func firstLine(path string) func(Env) string {
	return func(env Env) string {
		s, err := env.ReadFile(path)
		if err != nil {
			return ""
		}
		line, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
		return clean(line)
	}
}

// Plesk's version file is "18.0.65 Ubuntu 22.04 1800241015.10".
func firstField(path string) func(Env) string {
	return func(env Env) string {
		s, err := env.ReadFile(path)
		if err != nil {
			return ""
		}
		if f := strings.Fields(s); len(f) > 0 {
			return clean(f[0])
		}
		return ""
	}
}

// shellConfValue reads KEY='value' from a shell-style config file.
func shellConfValue(path, key string) func(Env) string {
	return func(env Env) string {
		s, err := env.ReadFile(path)
		if err != nil {
			return ""
		}
		for _, line := range strings.Split(s, "\n") {
			k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
			if ok && k == key {
				return clean(strings.Trim(v, `'"`))
			}
		}
		return ""
	}
}

// "DirectAdmin v.1.662 ..." from `directadmin v`.
func directAdminVersion(env Env) string {
	out, err := env.Run("/usr/local/directadmin/directadmin", "v")
	if err != nil {
		return ""
	}
	for _, f := range strings.Fields(out) {
		if v := clean(strings.TrimPrefix(f, "v.")); v != "" && strings.ContainsAny(v, ".") {
			return v
		}
	}
	return ""
}
