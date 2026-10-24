package remediation

import (
	"errors"
	"path"
	"sort"
	"strings"
	"testing"
)

// Glob lets discovery list the fake host's files.
func (h *fakeHost) Glob(pattern string) []string {
	seen := map[string]bool{}
	var out []string
	for p := range h.files {
		for q := p; q != "/" && q != "."; q = path.Dir(q) {
			if ok, _ := path.Match(pattern, q); ok && !seen[q] {
				seen[q] = true
				out = append(out, q)
			}
		}
	}
	sort.Strings(out)
	return out
}

const (
	debIni     = "/etc/php/8.2/fpm/conf.d/" + PHPIniDropIn
	debRuntime = "debian-8.2-fpm"
)

// phpHost is Debian with PHP 8.2-FPM: the www pool inherits php.ini, the
// shop pool overrides display_errors in its own file. php -r answers with
// what the drop-in says, as PHP would.
func phpHost(t *testing.T) *fakeHost {
	t.Helper()
	PHPStatePath = t.TempDir() + "/php-dropins.json"
	phpSettle = 0
	h := newHost()
	h.files["/etc/php/8.2/fpm/php.ini"] = "[PHP]\nallow_url_include = On\ndisplay_errors = On\n"
	h.files["/etc/php/8.2/fpm/conf.d/10-opcache.ini"] = "zend_extension=opcache.so\n"
	h.files["/etc/php/8.2/fpm/php-fpm.conf"] = "[global]\ninclude=/etc/php/8.2/fpm/pool.d/*.conf\n"
	h.files["/etc/php/8.2/fpm/pool.d/www.conf"] = "[www]\nlisten = /run/php/php8.2-fpm.sock\n"
	h.files["/etc/php/8.2/fpm/pool.d/shop.conf"] = "[shop]\nlisten = 127.0.0.1:9001\nphp_admin_flag[display_errors] = on\n"
	h.files["/usr/bin/php8.2"] = ""
	h.files["/usr/sbin/php-fpm8.2"] = ""
	h.bins["systemctl"] = true
	h.run = func(name string, args ...string) (string, error) {
		if name == "env" { // env PHP_INI_SCAN_DIR=... php -c ini -r "echo ini_get('k');"
			code := args[len(args)-1]
			_, key, _ := strings.Cut(code, "ini_get('")
			key, _, _ = strings.Cut(key, "'")
			for _, l := range strings.Split(h.files[debIni], "\n") {
				if k, v, ok := strings.Cut(l, " = "); ok && k == key {
					if v == "Off" {
						return "PHP Warning: x\n@@@@", nil
					}
					return "@@" + v + "@@", nil
				}
			}
			return "@@1@@", nil
		}
		if name == "systemctl" && args[0] == "is-active" {
			return "active\n", nil
		}
		return "", nil
	}
	return h
}

func ran(h *fakeHost, cmd string) bool {
	for _, c := range h.calls {
		if c == cmd {
			return true
		}
	}
	return false
}

func TestPHPApplyAndRevertIniDropIn(t *testing.T) {
	h := phpHost(t)
	id := "PHP_ALLOW_URL_INCLUDE@" + debRuntime + "/www"
	if ok, why := phpAvailability(h, id, safe); !ok {
		t.Fatalf("not available: %s", why)
	}
	msg, err := Apply(h, id, safe)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.files[debIni], "allow_url_include = Off\n") || !strings.HasPrefix(h.files[debIni], "; Managed by InfraFence") {
		t.Fatalf("drop-in = %q", h.files[debIni])
	}
	if h.files["/etc/php/8.2/fpm/php.ini"] != "[PHP]\nallow_url_include = On\ndisplay_errors = On\n" {
		t.Fatal("php.ini was edited")
	}
	for _, c := range []string{"/usr/sbin/php-fpm8.2 -t -y /etc/php/8.2/fpm/php-fpm.conf", "systemctl reload php8.2-fpm"} {
		if !ran(h, c) {
			t.Errorf("%q not run: %v", c, h.calls)
		}
	}
	if ran(h, "systemctl restart php8.2-fpm") {
		t.Error("php-fpm restarted")
	}
	if !strings.Contains(msg, debIni) || !strings.Contains(msg, "reloaded") {
		t.Errorf("message %q", msg)
	}
	if _, err := Revert(h, id); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.files[debIni]; ok {
		t.Fatalf("drop-in left after revert: %q", h.files[debIni])
	}
}

// onlyPoolFiles fails if anything but the fixture's own pool files is in
// the pool directory: InfraFence never writes PHP-FPM pool configuration.
func onlyPoolFiles(t *testing.T, h *fakeHost, want ...string) {
	t.Helper()
	var got []string
	for p := range h.files {
		if path.Dir(p) == "/etc/php/8.2/fpm/pool.d" {
			got = append(got, path.Base(p))
		}
	}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("pool directory = %v, want %v", got, want)
	}
}

func TestPHPPoolSetsItIsManualOnly(t *testing.T) {
	h := phpHost(t)
	// The shop pool sets display_errors itself: no .ini file can win, and
	// InfraFence doesn't touch the pool's configuration.
	id := "PHP_DISPLAY_ERRORS@" + debRuntime + "/shop"
	if ok, why := phpAvailability(h, id, safe); ok || why != ReasonManualOnly {
		t.Fatalf("availability = %v %q", ok, why)
	}
	_, err := Apply(h, id, safe)
	if !errors.Is(err, ErrNotFixable) || !strings.Contains(err.Error(), "shop.conf:3") {
		t.Fatalf("err = %v", err)
	}
	if _, ok := h.files[debIni]; ok || len(h.calls) != 0 {
		t.Fatalf("changed something: %q %v", h.files[debIni], h.calls)
	}
	onlyPoolFiles(t, h, "www.conf", "shop.conf")

	// The second setting of a fix counts too: log_errors set off by the pool.
	h.files["/etc/php/8.2/fpm/pool.d/www.conf"] += "php_admin_flag[log_errors] = off\n"
	phpCacheHost = nil
	if ok, why := phpAvailability(h, "PHP_DISPLAY_ERRORS@"+debRuntime+"/www", safe); ok || why != ReasonManualOnly {
		t.Fatalf("log_errors in the pool: %v %q", ok, why)
	}
}

// Whatever happens to the pools afterwards, a fix leaves only the .ini
// drop-in, which can't stop PHP-FPM from starting; the revert still works
// once the pool it was asked for is gone.
func TestPHPFixesNeverWritePoolConfig(t *testing.T) {
	h := phpHost(t)
	for _, base := range []string{"PHP_ALLOW_URL_INCLUDE", "PHP_DISPLAY_ERRORS", "PHP_EXPOSE_PHP", "PHP_CGI_FIX_PATHINFO", "PHP_DISABLE_FUNCTIONS", "PHP_OPEN_BASEDIR"} {
		for _, pool := range []string{"www", "shop"} {
			_, _ = Apply(h, base+"@"+debRuntime+"/"+pool, safe)
		}
	}
	onlyPoolFiles(t, h, "www.conf", "shop.conf")
	if !strings.Contains(h.files[debIni], "allow_url_include = Off") {
		t.Fatalf("drop-in = %q", h.files[debIni])
	}
	delete(h.files, "/etc/php/8.2/fpm/pool.d/www.conf")
	if _, err := Revert(h, "PHP_ALLOW_URL_INCLUDE@"+debRuntime+"/www"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(h.files[debIni], "allow_url_include") {
		t.Fatalf("not reverted: %q", h.files[debIni])
	}
}

func TestPHPOverriddenElsewhereIsUndone(t *testing.T) {
	h := phpHost(t)
	// Sorts after ours: our value can't win.
	h.files["/etc/php/8.2/fpm/conf.d/zzz-custom.ini"] = "expose_php = On\n"
	_, err := Apply(h, "PHP_EXPOSE_PHP@"+debRuntime+"/www", safe)
	if err == nil || !strings.Contains(err.Error(), "zzz-custom.ini:1") || !strings.Contains(err.Error(), "change undone") {
		t.Fatalf("err = %v", err)
	}
	if _, ok := h.files[debIni]; ok || ran(h, "systemctl reload php8.2-fpm") {
		t.Fatal("change kept or reloaded")
	}
}

func TestPHPConfigTestFailureRestores(t *testing.T) {
	h := phpHost(t)
	h.files[debIni] = phpHeader + "expose_php = Off\n"
	before := h.files[debIni]
	run := h.run
	h.run = func(name string, args ...string) (string, error) {
		if strings.HasPrefix(name, "/usr/sbin/php-fpm") {
			return "ERROR: bad", errors.New("exit 78")
		}
		return run(name, args...)
	}
	if _, err := Apply(h, "PHP_ALLOW_URL_INCLUDE@"+debRuntime+"/www", safe); err == nil || !strings.Contains(err.Error(), "config test failed") {
		t.Fatalf("err = %v", err)
	}
	if h.files[debIni] != before {
		t.Fatalf("drop-in not restored: %q", h.files[debIni])
	}
}

func TestPHPReloadFailureRestores(t *testing.T) {
	h := phpHost(t)
	run := h.run
	h.run = func(name string, args ...string) (string, error) {
		if name == "systemctl" && args[0] == "is-active" {
			return "failed\n", errors.New("exit 3")
		}
		return run(name, args...)
	}
	if _, err := Apply(h, "PHP_ALLOW_URL_INCLUDE@"+debRuntime+"/www", safe); err == nil || !strings.Contains(err.Error(), "not running") {
		t.Fatalf("err = %v", err)
	}
	if _, ok := h.files[debIni]; ok {
		t.Fatal("drop-in kept after a failed reload")
	}
	if !ran(h, "systemctl start php8.2-fpm") {
		t.Errorf("php-fpm not brought back: %v", h.calls)
	}
}

func TestPHPAvailability(t *testing.T) {
	h := phpHost(t)
	h.files["/opt/cpanel/ea-php82/root/etc/php.ini"] = "allow_url_include = On\n"
	cases := map[string]string{
		"PHP_ALLOW_URL_INCLUDE@ea-php82-cgi":               ReasonManaged,
		"PHP_DISPLAY_ERRORS@site:a.example":                ReasonManaged,
		"PHP_SESSION_COOKIE_SECURE@" + debRuntime + "/www": ReasonSiteRisk,
		"PHP_ALLOW_URL_INCLUDE@nope-8.0-fpm":               ReasonUnsupported,
		"PHP_OPEN_BASEDIR@" + debRuntime + "/www":          ReasonNoAutomation, // manual: per pool only
		"PHP_EXPOSE_PHP@" + debRuntime + "/shop":           "",
		"PHP_DISABLE_FUNCTIONS@" + debRuntime + "/www":     "",
		"PHP_CGI_FIX_PATHINFO@" + debRuntime + "/www":      "",
	}
	for id, want := range cases {
		ok, why := phpAvailability(h, id, safe)
		if why != want || ok != (want == "") {
			t.Errorf("%s: %v %q, want %q", id, ok, why, want)
		}
	}
	if ok, why := phpAvailability(h, "PHP_EXPOSE_PHP@"+debRuntime+"/www", Policy{}); ok || why != ReasonManaged {
		t.Errorf("unsafe policy: %v %q", ok, why)
	}
	if !AutoModeSafe("PHP_DISPLAY_ERRORS@x/www") || AutoModeSafe("PHP_DISABLE_FUNCTIONS@x/www") || AutoModeSafe("SSH_ROOT_LOGIN") {
		t.Error("AutoModeSafe")
	}
}

func TestPHPDisableFunctionsMerges(t *testing.T) {
	h := phpHost(t)
	h.files["/etc/php/8.2/fpm/php.ini"] += "disable_functions = pcntl_exec,exec\n"
	run := h.run
	h.run = func(name string, args ...string) (string, error) {
		if name == "env" {
			return "@@pcntl_exec,exec,system,passthru,shell_exec,proc_open,popen@@", nil
		}
		return run(name, args...)
	}
	if _, err := Apply(h, "PHP_DISABLE_FUNCTIONS@"+debRuntime+"/www", safe); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.files[debIni], "disable_functions = pcntl_exec,exec,system,passthru,shell_exec,proc_open,popen\n") {
		t.Fatalf("drop-in = %q", h.files[debIni])
	}
}

func TestPHPDropInChanged(t *testing.T) {
	h := phpHost(t)
	if _, err := Apply(h, "PHP_DISPLAY_ERRORS@"+debRuntime+"/www", safe); err != nil {
		t.Fatal(err)
	}
	if got := CheckPHPDropIns(h); len(got) != 0 {
		t.Fatalf("unchanged reported: %+v", got)
	}
	h.files[debIni] += "allow_url_include = On\n"
	got := CheckPHPDropIns(h)
	if len(got) != 1 || got[0].File != debIni || got[0].Change != "modified" || got[0].Runtime != debRuntime {
		t.Fatalf("changes = %+v", got)
	}
	if got := CheckPHPDropIns(h); len(got) != 0 {
		t.Fatalf("reported twice: %+v", got)
	}
	delete(h.files, debIni)
	if got := CheckPHPDropIns(h); len(got) != 1 || got[0].Change != "removed" {
		t.Fatalf("removal = %+v", got)
	}
}

func TestPHPNoChangeMessage(t *testing.T) {
	h := phpHost(t)
	id := "PHP_EXPOSE_PHP@" + debRuntime + "/www"
	if _, err := Apply(h, id, safe); err != nil {
		t.Fatal(err)
	}
	msg, err := Apply(h, id, safe)
	if err != nil || !strings.HasPrefix(msg, PHPNoChange) {
		t.Fatalf("second apply: %q %v", msg, err)
	}
}

func TestPHPRemoveAll(t *testing.T) {
	h := phpHost(t)
	if _, err := Apply(h, "PHP_DISPLAY_ERRORS@"+debRuntime+"/www", safe); err != nil {
		t.Fatal(err)
	}
	done, err := RemoveAll(h)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(done, ",") != debIni {
		t.Fatalf("removed %v", done)
	}
	if _, ok := h.files[debIni]; ok {
		t.Fatal("ini drop-in left")
	}
}

// A pool's php_admin_value of a system directive blocks the fix; its
// php_value doesn't (PHP ignores it), so the .ini fix still applies.
func TestPHPPoolSetsSystemDirectives(t *testing.T) {
	h := phpHost(t)
	h.files["/etc/php/8.2/fpm/pool.d/shop.conf"] += "php_admin_value[disable_functions] = exec\nphp_value[allow_url_include] = On\n"
	if ok, why := phpAvailability(h, "PHP_DISABLE_FUNCTIONS@"+debRuntime+"/shop", safe); ok || why != ReasonManualOnly {
		t.Errorf("php_admin_value: %v %q", ok, why)
	}
	if ok, why := phpAvailability(h, "PHP_ALLOW_URL_INCLUDE@"+debRuntime+"/shop", safe); !ok {
		t.Errorf("php_value of a system directive blocked the fix: %q", why)
	}
}

// The current disable_functions list is copied into our file only when it
// is plain function names: a \r would start a new directive there.
func TestPHPDisableFunctionsRefusesOddValue(t *testing.T) {
	h := phpHost(t)
	h.files["/etc/php/8.2/fpm/php.ini"] += "disable_functions = \"exec\rextension=evil.so\"\n"
	if _, err := Apply(h, "PHP_DISABLE_FUNCTIONS@"+debRuntime+"/www", safe); err == nil || !strings.Contains(err.Error(), "other than function names") {
		t.Fatalf("err = %v, drop-in %q", err, h.files[debIni])
	}
	if _, ok := h.files[debIni]; ok {
		t.Fatalf("drop-in written: %q", h.files[debIni])
	}
}
