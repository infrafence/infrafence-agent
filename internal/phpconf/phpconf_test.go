package phpconf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeTree creates files (path -> content) under a temporary root.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for p, c := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// debianHost is Debian 12 with PHP 8.2-FPM behind nginx, two sites on the
// www pool (one over HTTPS) and a second pool for one site.
func debianHost() map[string]string {
	return map[string]string{
		"/etc/php/8.2/fpm/php.ini": "[PHP]\nexpose_php = On\ndisplay_errors = Off\nallow_url_include = Off\n" +
			"; a comment\ndisable_functions = pcntl_fork,exec\n[PATH=/var/www/b]\nallow_url_include = On\n",
		"/etc/php/8.2/fpm/conf.d/10-opcache.ini": "zend_extension=opcache.so\n",
		"/etc/php/8.2/fpm/conf.d/50-custom.ini":  "display_errors = \"On\" ; for debugging\n",
		"/etc/php/8.2/fpm/php-fpm.conf":          "[global]\npid = /run/php/php8.2-fpm.pid\ninclude=/etc/php/8.2/fpm/pool.d/*.conf\n",
		"/etc/php/8.2/fpm/pool.d/www.conf":       "[www]\nuser = www-data\nlisten = /run/php/php8.2-fpm.sock\n",
		"/etc/php/8.2/fpm/pool.d/shop.conf": "[shop]\nuser = shop\nlisten = 127.0.0.1:9001\n" +
			"php_admin_flag[display_errors] = off\nphp_value[allow_url_include] = On\nphp_admin_value[expose_php] = Off\n",
		"/etc/php/8.2/cli/php.ini": "display_errors = On\n",
		"/usr/bin/php8.2":          "",
		"/etc/nginx/nginx.conf":    "http {\n  include /etc/nginx/sites-enabled/*;\n}\n",
		"/etc/nginx/sites-enabled/a": "server {\n  listen 80;\n  listen 443 ssl;\n  server_name a.example;\n  root /var/www/a;\n" +
			"  location ~ \\.php$ {\n    include snippets/fastcgi-php.conf;\n    fastcgi_pass unix:/run/php/php8.2-fpm.sock;\n  }\n}\n",
		"/etc/nginx/sites-enabled/b": "upstream php { server unix:/run/php/php8.2-fpm.sock; }\n" +
			"server {\n  listen 80;\n  server_name b.example;\n  root /var/www/b;\n  location ~ \\.php$ { fastcgi_pass php; }\n}\n",
		"/etc/nginx/sites-enabled/shop": "server {\n  listen 80;\n  server_name shop.example;\n  root /var/www/shop;\n" +
			"  location ~ \\.php$ { fastcgi_pass localhost:9001; }\n}\n",
	}
}

func TestDiscoverDebian(t *testing.T) {
	h := Discover(RootedEnv(writeTree(t, debianHost())))
	if len(h.Runtimes) != 1 {
		t.Fatalf("runtimes = %+v", h.Runtimes)
	}
	rt := h.Runtimes[0]
	if rt.ID != "debian-8.2-fpm" || rt.Service != "php8.2-fpm" || rt.CLI != "/usr/bin/php8.2" || rt.PoolGlob != "/etc/php/8.2/fpm/pool.d/*.conf" {
		t.Fatalf("runtime = %+v", rt)
	}
	// The scan directory wins over php.ini; the [PATH=] section is ignored.
	if d := rt.Get("display_errors"); d.Value != "On" || d.File != "/etc/php/8.2/fpm/conf.d/50-custom.ini" || d.Line != 1 {
		t.Errorf("display_errors = %+v", d)
	}
	if d := rt.Get("allow_url_include"); d.Value != "Off" || d.Line != 4 {
		t.Errorf("allow_url_include = %+v", d)
	}
	if d := rt.Get("cgi.fix_pathinfo"); !d.Default || d.Value != "1" {
		t.Errorf("cgi.fix_pathinfo = %+v", d)
	}
	shop, ok := rt.Pool("shop")
	if !ok || shop.Listen != "127.0.0.1:9001" {
		t.Fatalf("pools = %+v", rt.Pools)
	}
	// php_admin_flag overrides; php_value can't set a system-only directive.
	if d := rt.GetPool(shop, "display_errors"); d.Value != "off" || !d.Admin {
		t.Errorf("shop display_errors = %+v", d)
	}
	if d := rt.GetPool(shop, "allow_url_include"); d.Value != "Off" {
		t.Errorf("shop allow_url_include = %+v", d)
	}
	if got := Roots(h.Web.SitesFor("/run/php/php8.2-fpm.sock")); strings.Join(got, ",") != "/var/www/a,/var/www/b" {
		t.Errorf("www sites = %v", got)
	}
	if got := Roots(h.Web.SitesFor("127.0.0.1:9001")); strings.Join(got, ",") != "/var/www/shop" {
		t.Errorf("shop sites = %v (%+v)", got, h.Web.Sites)
	}
}

func byID(fs []Finding) map[string]Finding {
	m := map[string]Finding{}
	for _, f := range fs {
		m[f.CheckID] = f
	}
	return m
}

func TestChecks(t *testing.T) {
	files := debianHost()
	files["/etc/php/8.2/fpm/conf.d/60-bad.ini"] = "allow_url_include=1\nsession.cookie_httponly = 1\n"
	h := Discover(RootedEnv(writeTree(t, files)))
	var asked []string
	got := byID(Check(h, Options{Usage: func(roots, funcs []string) []string {
		asked = roots
		return []string{"/var/www/a/x.php:3"}
	}}))

	cases := []struct {
		id, sev string
		passed  bool
	}{
		{"PHP_ALLOW_URL_INCLUDE@debian-8.2-fpm/www", "critical", false},
		{"PHP_ALLOW_URL_INCLUDE@debian-8.2-fpm/shop", "critical", false}, // php_value can't override it
		{"PHP_DISPLAY_ERRORS@debian-8.2-fpm/www", "high", false},
		{"PHP_DISPLAY_ERRORS@debian-8.2-fpm/shop", "high", true},
		{"PHP_EXPOSE_PHP@debian-8.2-fpm/www", "low", false},
		{"PHP_EXPOSE_PHP@debian-8.2-fpm/shop", "low", true},
		{"PHP_CGI_FIX_PATHINFO@debian-8.2-fpm/www", "medium", false},
		{"PHP_DISABLE_FUNCTIONS@debian-8.2-fpm/www", "medium", false},
		{"PHP_OPEN_BASEDIR@debian-8.2-fpm/www", "medium", false},
		{"PHP_SESSION_COOKIE_HTTPONLY@debian-8.2-fpm/www", "low", true},
		{"PHP_SESSION_COOKIE_SECURE@debian-8.2-fpm/www", "low", false},
		{"PHP_ALLOW_URL_FOPEN@debian-8.2-fpm/www", "info", false},
	}
	for _, c := range cases {
		f, ok := got[c.id]
		if !ok {
			t.Errorf("%s missing", c.id)
			continue
		}
		if f.Severity != c.sev || f.Passed != c.passed {
			t.Errorf("%s: severity %s passed %v, want %s %v (%s)", c.id, f.Severity, f.Passed, c.sev, c.passed, f.Description)
		}
	}
	// One site per pool: no open_basedir finding; HTTP only: no cookie_secure.
	for _, id := range []string{"PHP_OPEN_BASEDIR@debian-8.2-fpm/shop", "PHP_SESSION_COOKIE_SECURE@debian-8.2-fpm/shop"} {
		if _, ok := got[id]; ok {
			t.Errorf("%s should not be reported", id)
		}
	}
	f := got["PHP_ALLOW_URL_INCLUDE@debian-8.2-fpm/www"]
	if f.Details["file"] != "/etc/php/8.2/fpm/conf.d/60-bad.ini" || f.Details["line"] != "1" || f.Details["automode_safe"] != "true" ||
		!strings.Contains(f.Description, "60-bad.ini:1") {
		t.Errorf("allow_url_include finding = %+v", f)
	}
	f = got["PHP_CGI_FIX_PATHINFO@debian-8.2-fpm/www"]
	if f.Details["default"] != "true" || f.Details["fix"] != FixApproval || f.Details["automode_safe"] != "false" {
		t.Errorf("fix_pathinfo finding = %+v", f.Details)
	}
	f = got["PHP_DISABLE_FUNCTIONS@debian-8.2-fpm/www"]
	if f.Details["missing_functions"] != "system,passthru,shell_exec,proc_open,popen" ||
		!strings.Contains(f.Details["approval_note"], "/var/www/a/x.php:3") || strings.Join(asked, ",") != "/var/www/a,/var/www/b" {
		t.Errorf("disable_functions finding = %+v (asked %v)", f.Details, asked)
	}
}

func TestPanelRuntimesReportOnly(t *testing.T) {
	root := writeTree(t, map[string]string{
		"/opt/cpanel/ea-php74/root/etc/php.ini":           "allow_url_include = On\n",
		"/opt/cpanel/ea-php74/root/usr/bin/php":           "",
		"/opt/plesk/php/8.1/etc/php.ini":                  "expose_php = Off\n",
		"/opt/plesk/php/8.1/etc/php.d/zz.ini":             "display_errors = On\n",
		"/var/www/vhosts/system/shop.example/etc/php.ini": "display_errors = on\n",
	})
	h := Discover(RootedEnv(root))
	got := byID(Check(h, Options{}))
	f, ok := got["PHP_ALLOW_URL_INCLUDE@ea-php74-cgi"]
	if !ok || f.Passed || f.Details["panel"] != panelCPanel || f.Details["automode_safe"] != "false" || !strings.Contains(f.Description, "does not change it") {
		t.Errorf("cPanel finding = %+v", f)
	}
	if f := got["PHP_DISPLAY_ERRORS@plesk-8.1-cgi"]; f.Passed || f.Details["panel"] != panelPlesk {
		t.Errorf("Plesk finding = %+v", f)
	}
	if f := got["PHP_DISPLAY_ERRORS@site:shop.example"]; f.Passed || f.Details["fix"] != FixNone {
		t.Errorf("Plesk site finding = %+v", f)
	}
}

func TestParseID(t *testing.T) {
	b, rt, pool, site, ok := ParseID("PHP_DISPLAY_ERRORS@debian-8.2-fpm/www")
	if !ok || b != CheckDisplayErrors || rt != "debian-8.2-fpm" || pool != "www" || site != "" {
		t.Errorf("got %q %q %q %q %v", b, rt, pool, site, ok)
	}
	if _, _, _, site, ok := ParseID("PHP_DISPLAY_ERRORS@site:a.example"); !ok || site != "a.example" {
		t.Errorf("site id: %q %v", site, ok)
	}
	for _, bad := range []string{"VER_PHP", "SSH_ROOT_LOGIN@x", "PHP_X@"} {
		if _, _, _, _, ok := ParseID(bad); ok {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestWatcherReportsOncePerChange(t *testing.T) {
	root := writeTree(t, debianHost())
	var risks []Risk
	changes := make(chan Host, 4)
	w := &Watcher{Env: RootedEnv(root), Debounce: 10 * time.Millisecond,
		OnRisk: func(r Risk) { risks = append(risks, r) }, OnChange: func(h Host) { changes <- h }}
	ini := root + "/etc/php/8.2/fpm/conf.d/60-bad.ini"

	if w.Poll() || len(risks) != 0 {
		t.Fatalf("baseline: risks %v", risks)
	}
	if w.Poll() {
		t.Fatal("no change reported as a change")
	}
	os.WriteFile(ini, []byte("allow_url_include = On\n"), 0o644)
	if !w.Poll() {
		t.Fatal("change not seen")
	}
	// www gets it; shop's php_value can't override a system directive, so it has it too.
	if len(risks) != 2 || risks[0].Directive != "allow_url_include" || risks[0].Severity != "critical" ||
		risks[0].File != "/etc/php/8.2/fpm/conf.d/60-bad.ini" || risks[0].Line != 1 {
		t.Fatalf("risks = %+v", risks)
	}
	select {
	case <-changes:
	case <-time.After(2 * time.Second):
		t.Fatal("OnChange not called")
	}
	// Same value, file touched again (a comment): no new event.
	os.WriteFile(ini, []byte("allow_url_include = On\n; again\n"), 0o644)
	w.Poll()
	if len(risks) != 2 {
		t.Fatalf("re-reported: %+v", risks)
	}
	// Fixed, then re-enabled: reported again.
	os.WriteFile(ini, []byte("allow_url_include = Off\n"), 0o644)
	w.Poll()
	os.WriteFile(ini, []byte("allow_url_include = On\n"), 0o644)
	w.Poll()
	if len(risks) != 4 {
		t.Fatalf("re-enable not reported: %+v", risks)
	}
}

func TestApacheGlobalHandler(t *testing.T) {
	root := writeTree(t, map[string]string{
		"/etc/httpd/conf/httpd.conf": "IncludeOptional conf.d/*.conf\n",
		"/etc/httpd/conf.d/php.conf": "<FilesMatch \\.(php|phar)$>\n  SetHandler \"proxy:unix:/run/php-fpm/www.sock|fcgi://localhost\"\n</FilesMatch>\n",
		"/etc/httpd/conf.d/a.conf":   "<VirtualHost *:443>\n  ServerName a.example\n  DocumentRoot \"/srv/a\"\n  SSLEngine on\n</VirtualHost>\n",
	})
	w := ReadWebMap(RootedEnv(root))
	s := w.SitesFor("/run/php-fpm/www.sock")
	if len(s) != 1 || s[0].Root != "/srv/a" || !s[0].HTTPS {
		t.Fatalf("sites = %+v", w.Sites)
	}
}

func TestFindUsage(t *testing.T) {
	root := writeTree(t, map[string]string{
		"/a/run.php":  "<?php\n// exec('x');\n$o->exec('y');\n$r = shell_exec('id');\n",
		"/a/safe.php": "<?php\nfunction system() {}\n$db->system();\n",
	})
	got := FindUsage([]string{root + "/a"}, Dangerous)
	if len(got) != 1 || got[0] != root+"/a/run.php:4" {
		t.Fatalf("usage = %v", got)
	}
}

// A pool that sets a directive in its own file gets a manual fix, never an
// automatic one: InfraFence writes nothing in PHP-FPM's pool configuration.
func TestPoolSettingIsManualFix(t *testing.T) {
	files := debianHost()
	files["/etc/php/8.2/fpm/pool.d/shop.conf"] = "[shop]\nuser = shop\nlisten = 127.0.0.1:9001\nphp_admin_flag[display_errors] = on\n"
	got := byID(Check(Discover(RootedEnv(writeTree(t, files))), Options{}))

	f := got["PHP_DISPLAY_ERRORS@debian-8.2-fpm/shop"]
	if f.Passed || f.Details["fix"] != FixNone || f.Details["scope"] != "pool" || f.Details["automode_safe"] != "false" {
		t.Fatalf("details = %+v", f.Details)
	}
	for _, want := range []string{"shop.conf:4", "[shop]", "php_admin_flag[display_errors] = Off and php_admin_flag[log_errors] = On", "reload php8.2-fpm"} {
		if !strings.Contains(f.Details["manual_fix"], want) || f.Recommendation != f.Details["manual_fix"] {
			t.Errorf("manual_fix %q lacks %q", f.Details["manual_fix"], want)
		}
	}
	// The www pool inherits php.ini: its fix stays automatic.
	if f := got["PHP_DISPLAY_ERRORS@debian-8.2-fpm/www"]; f.Details["fix"] != FixAuto || f.Details["manual_fix"] != "" {
		t.Errorf("www details = %+v", f.Details)
	}
	f = got["PHP_OPEN_BASEDIR@debian-8.2-fpm/www"]
	if f.Details["fix"] != FixNone || !strings.Contains(f.Details["manual_fix"], "php_admin_value[open_basedir] = /var/www/a:/var/www/b:/tmp") ||
		!strings.Contains(f.Details["manual_fix"], "/etc/php/8.2/fpm/pool.d/www.conf") {
		t.Errorf("open_basedir details = %+v", f.Details)
	}
}
