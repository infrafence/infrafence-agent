package phpconf

import (
	"fmt"
	"strings"
)

// Check IDs. A finding's CheckID is one of these, "@", and its target:
// "<runtime>" or "<runtime>/<pool>" (e.g. "PHP_DISPLAY_ERRORS@debian-8.2-fpm/www"),
// or "site:<site>" for a panel's per-site file.
const (
	CheckAllowURLInclude  = "PHP_ALLOW_URL_INCLUDE"
	CheckDisplayErrors    = "PHP_DISPLAY_ERRORS"
	CheckExposePHP        = "PHP_EXPOSE_PHP"
	CheckFixPathinfo      = "PHP_CGI_FIX_PATHINFO"
	CheckDisableFunctions = "PHP_DISABLE_FUNCTIONS"
	CheckOpenBasedir      = "PHP_OPEN_BASEDIR"
	CheckCookieHTTPOnly   = "PHP_SESSION_COOKIE_HTTPONLY"
	CheckCookieSecure     = "PHP_SESSION_COOKIE_SECURE"
	CheckAllowURLFopen    = "PHP_ALLOW_URL_FOPEN"
)

// How a check's fix may be applied.
const (
	FixAuto     = "auto"     // AutoMode may apply it without asking
	FixApproval = "approval" // only after a person approves it
	FixNone     = "none"     // no automatic fix
)

// FixClass says how the fix of a check (base ID) may be applied.
func FixClass(base string) string {
	switch base {
	case CheckAllowURLInclude, CheckDisplayErrors, CheckExposePHP:
		return FixAuto
	case CheckFixPathinfo, CheckDisableFunctions, CheckOpenBasedir:
		return FixApproval
	}
	return FixNone
}

// Dangerous are the functions a web pool should not let scripts call.
var Dangerous = []string{"exec", "system", "passthru", "shell_exec", "proc_open", "popen"}

// Finding is one check result (converted to scanner.Finding by the scanner).
type Finding struct {
	CheckID        string
	Severity       string
	Title          string
	Description    string
	Recommendation string
	Details        map[string]string
	Passed         bool
}

// ID builds a check ID for a target.
func ID(base, runtime, pool string) string {
	if pool != "" {
		return base + "@" + runtime + "/" + pool
	}
	return base + "@" + runtime
}

// ParseID splits a check ID into its base, runtime and pool, or site.
func ParseID(id string) (base, runtime, pool, site string, ok bool) {
	base, target, ok := strings.Cut(id, "@")
	if !ok || !strings.HasPrefix(base, "PHP_") || target == "" {
		return "", "", "", "", false
	}
	if s, isSite := strings.CutPrefix(target, "site:"); isSite {
		return base, "", "", s, s != ""
	}
	runtime, pool, _ = strings.Cut(target, "/")
	return base, runtime, pool, "", runtime != ""
}

// target is what one set of checks runs against: a runtime without pools,
// or one of its pools.
type target struct {
	rt    Runtime
	pool  *Pool
	sites []Site
}

func (t target) get(key string) Directive {
	if t.pool != nil {
		return t.rt.GetPool(*t.pool, key)
	}
	return t.rt.Get(key)
}

// overrides reports whether the pool's own files set key.
func (t target) overrides(key string) bool {
	for _, d := range t.pool.Overrides {
		if d.Key == key && (d.Admin || !systemOnly[key]) {
			return true
		}
	}
	return false
}

func (t target) label() string {
	if t.pool != nil {
		return fmt.Sprintf("PHP %s %s pool %q", t.rt.Version, t.rt.SAPI, t.pool.Name)
	}
	if t.rt.Version != "" {
		return fmt.Sprintf("PHP %s (%s)", t.rt.Version, t.rt.SAPI)
	}
	return fmt.Sprintf("PHP (%s, %s)", t.rt.ID, t.rt.SAPI)
}

func (t target) id(base string) string {
	if t.pool != nil {
		return ID(base, t.rt.ID, t.pool.Name)
	}
	return ID(base, t.rt.ID, "")
}

// Targets lists what the checks run against: every pool of an FPM
// runtime, every other web runtime as a whole.
func targets(h Host) []target {
	var out []target
	for _, rt := range h.Runtimes {
		if rt.SAPI == "cli" {
			continue
		}
		if rt.SAPI == "fpm" {
			for i := range rt.Pools {
				p := &rt.Pools[i]
				out = append(out, target{rt: rt, pool: p, sites: h.Web.SitesFor(p.Listen)})
			}
			continue
		}
		var sites []Site
		if rt.SAPI == "apache2handler" {
			sites = h.Web.ApacheSites()
		}
		out = append(out, target{rt: rt, sites: sites})
	}
	return out
}

// Options tune the checks.
type Options struct {
	// Usage, when set, lists the files under roots that call any of funcs
	// (the disable_functions approval text). Nil skips the search.
	Usage func(roots []string, funcs []string) []string
}

// Check runs every PHP configuration check.
func Check(h Host, o Options) []Finding {
	if o.Usage != nil {
		// Pools share roots: search each set once per run.
		search, memo := o.Usage, map[string][]string{}
		o.Usage = func(roots, funcs []string) []string {
			k := strings.Join(roots, "\x00") + "\x01" + strings.Join(funcs, ",")
			if r, ok := memo[k]; ok {
				return r
			}
			memo[k] = search(roots, funcs)
			return memo[k]
		}
	}
	var out []Finding
	for _, t := range targets(h) {
		out = append(out, checkTarget(h, t, o)...)
	}
	for _, s := range h.Sites {
		out = append(out, checkSite(s)...)
	}
	return out
}

func checkTarget(h Host, t target, o Options) []Finding {
	var out []Finding
	add := func(base, sev, title string, d Directive, passed bool, desc, rec string) {
		f := finding(t, base, sev, title, d, passed, desc, rec)
		out = append(out, f)
	}

	d := t.get("allow_url_include")
	add(CheckAllowURLInclude, "critical", "PHP allow_url_include", d, !IsOn(d.Value),
		"allow_url_include is on: include() and require() can load code from a URL, turning a file inclusion bug into remote code execution.",
		"Set allow_url_include = Off.")

	d = t.get("display_errors")
	add(CheckDisplayErrors, "high", "PHP display_errors", d, !displaysErrors(d.Value),
		"display_errors is on: error messages, with paths, queries and sometimes credentials, are shown to visitors.",
		"Set display_errors = Off and log_errors = On; errors then go to the log.")

	d = t.get("expose_php")
	add(CheckExposePHP, "low", "PHP expose_php", d, !IsOn(d.Value),
		"expose_php is on: every response carries an X-Powered-By header with the exact PHP version.",
		"Set expose_php = Off.")

	if t.rt.SAPI == "fpm" && h.Web.Nginx {
		d = t.get("cgi.fix_pathinfo")
		add(CheckFixPathinfo, "medium", "PHP cgi.fix_pathinfo with nginx", d, !IsOn(d.Value),
			"cgi.fix_pathinfo is 1 behind nginx: a request like /upload/image.jpg/x.php can make PHP-FPM run an uploaded file as PHP when the nginx location doesn't check the file exists.",
			"Set cgi.fix_pathinfo = 0 (needs approval: applications that rely on PATH_INFO through this mechanism stop working), or add try_files $fastcgi_script_name =404; to the nginx PHP location.")
	}

	d = t.get("disable_functions")
	missing := MissingFunctions(d.Value)
	f := finding(t, CheckDisableFunctions, "medium", "PHP disable_functions", d, len(missing) == 0,
		"Web scripts can run system commands: disable_functions does not cover "+strings.Join(missing, ", ")+". A webshell or an injection bug then gets a shell on the server.",
		"Add "+strings.Join(missing, ", ")+" to disable_functions (advisory, needs approval: check the listed files first).")
	f.Details["advisory"] = "true"
	f.Details["missing_functions"] = strings.Join(missing, ",")
	if len(missing) > 0 && o.Usage != nil {
		roots := Roots(t.sites)
		if used := o.Usage(roots, missing); len(used) > 0 {
			f.Details["approval_note"] = "Site code calls these functions; disabling them can break: " + strings.Join(used, ", ")
		} else if len(roots) > 0 {
			f.Details["approval_note"] = "No call to these functions found under " + strings.Join(roots, ", ")
		}
	}
	if len(missing) == 0 {
		f.Description = "disable_functions covers " + strings.Join(Dangerous, ", ") + "."
	}
	out = append(out, f)

	if roots := Roots(t.sites); len(roots) > 1 {
		d = t.get("open_basedir")
		f := finding(t, CheckOpenBasedir, "medium", "PHP open_basedir on a shared pool", d, strings.TrimSpace(d.Value) != "",
			fmt.Sprintf("open_basedir is not set and %d sites share these PHP processes (%s): a compromised site can read the files of the others and of the system.", len(roots), strings.Join(roots, ", ")),
			"Give each site its own pool and user; at least set open_basedir to the sites' roots and the temp directories (advisory, needs approval).")
		f.Details["advisory"] = "true"
		f.Details["roots"] = strings.Join(roots, ":")
		out = append(out, f)
	}

	d = t.get("session.cookie_httponly")
	add(CheckCookieHTTPOnly, "low", "PHP session.cookie_httponly", d, IsOn(d.Value),
		"session.cookie_httponly is off: scripts in the page (an XSS) can read the session cookie and take over logged-in sessions.",
		"Set session.cookie_httponly = On.")

	if AnyHTTPS(t.sites) || (t.pool == nil && AnyHTTPS(h.Web.Sites) && len(t.sites) == 0) {
		d = t.get("session.cookie_secure")
		add(CheckCookieSecure, "low", "PHP session.cookie_secure", d, IsOn(d.Value),
			"session.cookie_secure is off on an HTTPS site: the session cookie is also sent over plain HTTP, where it can be intercepted.",
			"Set session.cookie_secure = On once every page of the site is served over HTTPS.")
	}

	d = t.get("allow_url_fopen")
	add(CheckAllowURLFopen, "info", "PHP allow_url_fopen", d, !IsOn(d.Value),
		"allow_url_fopen is on: file functions can open URLs. Many applications need it (updates, APIs); it widens what a file-path bug can reach.",
		"Leave it on if the sites need it; otherwise set allow_url_fopen = Off.")
	return out
}

// finding fills the fields every PHP finding has.
func finding(t target, base, sev, title string, d Directive, passed bool, desc, rec string) Finding {
	det := map[string]string{
		"runtime":   t.rt.ID,
		"version":   t.rt.Version,
		"sapi":      t.rt.SAPI,
		"directive": d.Key,
		"value":     d.Value,
		"fix":       FixClass(base),
	}
	if t.pool != nil {
		det["pool"] = t.pool.Name
	}
	// scope: where the fix goes. "runtime": the runtime's .ini drop-in, so
	// it (and its revert) applies to every pool that doesn't set the
	// directive itself; "pool": this pool's section only.
	det["scope"] = "runtime"
	if t.pool != nil && (base == CheckOpenBasedir || t.overrides(d.Key)) {
		det["scope"] = "pool"
	}
	src := ""
	if d.Default {
		det["file"] = t.rt.Ini
		det["default"] = "true"
		src = fmt.Sprintf("not set in %s or its scan directory: PHP's built-in default %q applies", t.rt.Ini, d.Value)
	} else {
		det["file"] = d.File
		det["line"] = fmt.Sprint(d.Line)
		src = fmt.Sprintf("%s = %q in %s:%d", d.Key, d.Value, d.File, d.Line)
	}
	det["automode_safe"] = fmt.Sprint(FixClass(base) == FixAuto && t.rt.Panel == "")
	if sites := Roots(t.sites); len(sites) > 0 {
		det["sites"] = strings.Join(sites, ",")
	}
	if !passed {
		desc = fmt.Sprintf("%s: %s (%s).", t.label(), strings.TrimSuffix(desc, "."), src)
	} else {
		desc = fmt.Sprintf("%s: %s (%s).", t.label(), d.Key+" is safe", src)
		rec = ""
	}
	if t.rt.Panel != "" {
		det["panel"] = t.rt.Panel
		desc += " " + t.rt.Panel + " manages this PHP configuration: InfraFence reports it and does not change it; change it in the panel."
	}
	return Finding{
		CheckID: t.id(base), Severity: sev, Title: title + " (" + t.rt.ID + poolSuffix(t) + ")",
		Description: desc, Recommendation: rec, Details: det, Passed: passed,
	}
}

func poolSuffix(t target) string {
	if t.pool != nil {
		return "/" + t.pool.Name
	}
	return ""
}

// checkSite reports the risky values a panel's per-site file sets.
func checkSite(s SiteOverride) []Finding {
	var out []Finding
	for _, c := range []struct {
		base, key, sev, what string
		bad                  func(string) bool
	}{
		{CheckAllowURLInclude, "allow_url_include", "critical", "allow_url_include is on", IsOn},
		{CheckDisplayErrors, "display_errors", "high", "display_errors is on", displaysErrors},
	} {
		d := lookup(s.Settings, c.key)
		if d.Default {
			continue
		}
		out = append(out, Finding{
			CheckID:  c.base + "@site:" + s.Site,
			Severity: c.sev,
			Title:    "PHP " + c.key + " (site " + s.Site + ")",
			Description: fmt.Sprintf("Site %s: %s = %q in %s:%d. %s manages this file: InfraFence reports it and does not change it.",
				s.Site, d.Key, d.Value, d.File, d.Line, s.Panel),
			Recommendation: "Change it in the panel's PHP settings for this site.",
			Details: map[string]string{
				"site": s.Site, "file": d.File, "line": fmt.Sprint(d.Line), "directive": d.Key, "value": d.Value,
				"panel": s.Panel, "fix": FixNone, "automode_safe": "false",
			},
			Passed: !c.bad(d.Value),
		})
	}
	return out
}

// missingFunctions returns the Dangerous functions disable_functions lacks.
func MissingFunctions(v string) []string {
	have := map[string]bool{}
	for _, f := range strings.FieldsFunc(strings.ToLower(v), func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		have[f] = true
	}
	var out []string
	for _, f := range Dangerous {
		if !have[f] {
			out = append(out, f)
		}
	}
	return out
}

// MergeFunctions returns v with add appended, without duplicates.
func MergeFunctions(v string, add []string) string {
	var list []string
	seen := map[string]bool{}
	for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		if !seen[strings.ToLower(f)] {
			seen[strings.ToLower(f)] = true
			list = append(list, f)
		}
	}
	for _, f := range add {
		if !seen[f] {
			seen[f] = true
			list = append(list, f)
		}
	}
	return strings.Join(list, ",")
}
