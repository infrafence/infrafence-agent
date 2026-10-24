package remediation

// PHP hardening fixes. Like the other fixes, nothing edits a main
// configuration file: each PHP runtime gets one drop-in of its own,
//
//   - <scan dir>/zz-infrafence-hardening.ini, read after php.ini and the
//     other files of the directory it scans, and
//   - <pool dir>/zz-infrafence-hardening.conf, only for a pool whose own
//     file overrides the directive (a pool setting beats any .ini file),
//
// so undoing a fix removes a line, and the file once it is empty. After the
// change PHP-FPM's config test must pass and the new value must be the
// effective one (read back with the runtime's own php binary when it has
// one), then PHP-FPM is reloaded, never restarted. The caller then checks
// that the sites still answer and reverts on failure. Runtimes a hosting
// panel manages are only reported.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/infrafence/infrafence-agent/internal/phpconf"
)

// Names of the PHP drop-ins InfraFence owns (in each runtime's scan
// directory and pool directory) and the record of their contents.
const (
	PHPIniDropIn  = "zz-infrafence-hardening.ini"
	PHPPoolDropIn = "zz-infrafence-hardening.conf"
)

// PHPStatePath records what InfraFence wrote in each PHP drop-in, so a
// change by someone else (a panel, a package, a person) is detected.
var PHPStatePath = "/var/lib/infrafence/php-dropins.json"

const phpHeader = "; Managed by InfraFence (PHP hardening fixes applied from the dashboard).\n; Delete this file and reload PHP to undo them.\n"

// phpSetting is one value a fix sets.
type phpSetting struct{ key, value string }

// phpSettings are the values each fix sets; disable_functions and
// open_basedir are computed from the host.
var phpSettings = map[string][]phpSetting{
	phpconf.CheckAllowURLInclude:  {{"allow_url_include", "Off"}},
	phpconf.CheckDisplayErrors:    {{"display_errors", "Off"}, {"log_errors", "On"}},
	phpconf.CheckExposePHP:        {{"expose_php", "Off"}},
	phpconf.CheckFixPathinfo:      {{"cgi.fix_pathinfo", "0"}},
	phpconf.CheckDisableFunctions: {{"disable_functions", ""}},
	phpconf.CheckOpenBasedir:      {{"open_basedir", ""}},
}

var phpBool = map[string]bool{"allow_url_include": true, "display_errors": true, "log_errors": true, "expose_php": true}

// phpEnv lets discovery read the host through Host.
type phpEnv struct{ h Host }

func (e phpEnv) ReadFile(p string) ([]byte, error) {
	if _, real := e.h.(osHost); real {
		return phpconf.System.ReadFile(p) // regular files only, bounded
	}
	return e.h.ReadFile(p)
}
func (e phpEnv) Exists(p string) bool { return exists(e.h, p) }
func (e phpEnv) Run(n string, a ...string) (string, error) {
	return e.h.Run(n, a...)
}
func (e phpEnv) Glob(p string) []string {
	if g, ok := e.h.(interface{ Glob(string) []string }); ok {
		return g.Glob(p)
	}
	m, _ := filepath.Glob(p)
	sort.Strings(m)
	return m
}

// discoverPHP reads the host's PHP configuration; Availability is asked
// once per finding, so the result is kept for a few seconds.
var (
	phpCacheMu   sync.Mutex
	phpCacheHost Host
	phpCache     phpconf.Host
	phpCacheAt   time.Time
)

func discoverPHP(h Host, fresh bool) phpconf.Host {
	phpCacheMu.Lock()
	defer phpCacheMu.Unlock()
	if !fresh && phpCacheHost == h && time.Since(phpCacheAt) < 10*time.Second {
		return phpCache
	}
	phpCache, phpCacheHost, phpCacheAt = phpconf.Discover(phpEnv{h}), h, time.Now()
	return phpCache
}

// phpAvailability is Availability for PHP check IDs.
func phpAvailability(h Host, checkID string, p Policy) (bool, string) {
	base, rtID, poolName, site, _ := phpconf.ParseID(checkID)
	if site != "" {
		return false, ReasonManaged
	}
	if phpconf.FixClass(base) == phpconf.FixNone {
		if base == phpconf.CheckAllowURLFopen || base == phpconf.CheckCookieSecure || base == phpconf.CheckCookieHTTPOnly {
			return false, ReasonSiteRisk
		}
		return false, ReasonNoAutomation
	}
	rt, ok := discoverPHP(h, false).Find(rtID)
	if !ok {
		return false, ReasonUnsupported
	}
	if rt.Panel != "" || !p.ConfigChangesSafe {
		return false, ReasonManaged
	}
	if _, _, err := phpPlan(discoverPHP(h, false), rt, poolName, base, true); err != nil {
		return false, ReasonUnsupported
	}
	return true, ""
}

// IsPHPCheck reports whether checkID is a PHP configuration check.
func IsPHPCheck(checkID string) bool {
	_, _, _, _, ok := phpconf.ParseID(checkID)
	return ok
}

// AutoModeSafe reports whether AutoMode may apply checkID's fix without a
// person approving it.
func AutoModeSafe(checkID string) bool {
	if base, _, _, site, ok := phpconf.ParseID(checkID); ok {
		return site == "" && phpconf.FixClass(base) == phpconf.FixAuto
	}
	return false
}

// phpPlan says where each setting of a fix goes: the runtime's .ini
// drop-in, or the pool drop-in when the pool's own file overrides it.
// set=false (revert) gives the keys with "" (remove).
func phpPlan(host phpconf.Host, rt phpconf.Runtime, poolName, base string, set bool) (ini, pool map[string]string, err error) {
	ini, pool = map[string]string{}, map[string]string{}
	var pl *phpconf.Pool
	if poolName != "" {
		p, ok := rt.Pool(poolName)
		if !ok {
			return nil, nil, fmt.Errorf("%w: pool %s not found", ErrUnsupported, poolName)
		}
		pl = &p
	}
	if set && rt.SAPI == "fpm" && rt.FPM == "" {
		return nil, nil, fmt.Errorf("%w: no php-fpm binary to test the configuration with", ErrUnsupported)
	}
	iniFile, poolFile := phpDropIns(rt)
	clean := rt.WithoutFile(iniFile).WithoutFile(poolFile)
	for _, s := range phpSettings[base] {
		v := ""
		if set {
			v = s.value
			switch s.key {
			case "disable_functions":
				cur := clean.Get(s.key).Value
				if pl != nil {
					cur = clean.GetPool(mustPool(clean, poolName), s.key).Value
				}
				v = phpconf.MergeFunctions(cur, phpconf.MissingFunctions(cur))
			case "open_basedir":
				if pl == nil {
					return nil, nil, fmt.Errorf("%w: open_basedir is only set per pool", ErrUnsupported)
				}
				v = openBasedir(clean, *pl, host)
				if v == "" {
					return nil, nil, fmt.Errorf("%w: the pool's sites are not known", ErrUnsupported)
				}
			}
		}
		overridden := false
		if pl != nil {
			for _, d := range pl.Overrides {
				if d.Key == s.key && d.File != poolFile && (d.Admin || !phpSystemOnly(s.key)) {
					overridden = true
				}
			}
		}
		if s.key == "open_basedir" {
			overridden = true
		}
		if overridden {
			if poolFile == "" {
				return nil, nil, fmt.Errorf("%w: php-fpm.conf does not include a pool directory", ErrUnsupported)
			}
			pool[s.key] = v
		} else {
			if iniFile == "" {
				return nil, nil, fmt.Errorf("%w: this PHP has no scan directory", ErrUnsupported)
			}
			ini[s.key] = v
		}
	}
	return ini, pool, nil
}

func mustPool(rt phpconf.Runtime, name string) phpconf.Pool {
	p, _ := rt.Pool(name)
	return p
}

func phpSystemOnly(key string) bool {
	switch key {
	case "allow_url_include", "expose_php", "cgi.fix_pathinfo", "disable_functions":
		return true
	}
	return false
}

// openBasedir is the pool's site roots plus the directories PHP itself
// needs (temp, uploads, sessions, PEAR).
func openBasedir(rt phpconf.Runtime, p phpconf.Pool, host phpconf.Host) string {
	var dirs []string
	for _, r := range phpconf.Roots(host.Web.SitesFor(p.Listen)) {
		// A root with a variable or a separator can't be expressed safely.
		if strings.ContainsAny(r, "$;:*\"\n") || r == "/" {
			return ""
		}
		// Frameworks serve public/ (or web/) but load code from its parent.
		if b := path.Base(r); b == "public" || b == "web" || b == "pub" || b == "webroot" {
			r = path.Dir(r)
		}
		dirs = append(dirs, r)
	}
	if len(dirs) == 0 {
		return ""
	}
	for _, k := range []string{"session.save_path", "upload_tmp_dir", "sys_temp_dir"} {
		v := rt.GetPool(p, k).Value
		if i := strings.LastIndexByte(v, ';'); i >= 0 { // "N;MODE;/path"
			v = v[i+1:]
		}
		if strings.HasPrefix(v, "/") {
			dirs = append(dirs, v)
		}
	}
	dirs = append(dirs, "/tmp", "/var/tmp", "/usr/share/php", "/usr/share/pear")
	seen := map[string]bool{}
	var out []string
	for _, d := range dirs {
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return strings.Join(out, ":")
}

// phpDropIns returns the runtime's two drop-in paths ("" when it has no
// scan directory, or no pool directory whose include= pattern takes it).
func phpDropIns(rt phpconf.Runtime) (ini, pool string) {
	if rt.ScanDir != "" {
		ini = rt.ScanDir + "/" + PHPIniDropIn
	}
	if rt.SAPI == "fpm" && rt.PoolGlob != "" {
		cand := path.Dir(rt.PoolGlob) + "/" + PHPPoolDropIn
		if ok, _ := path.Match(rt.PoolGlob, cand); ok {
			pool = cand
		}
	}
	return ini, pool
}

// applyPHP sets (or, set=false, removes) the settings of one PHP fix.
func applyPHP(h Host, checkID string, p Policy, set bool) (string, error) {
	base, rtID, poolName, _, ok := phpconf.ParseID(checkID)
	if !ok {
		return "", ErrNotFixable
	}
	host := discoverPHP(h, true)
	rt, ok := host.Find(rtID)
	if !ok {
		return "", fmt.Errorf("%w: PHP runtime %s not found", ErrUnsupported, rtID)
	}
	if set && (rt.Panel != "" || !p.ConfigChangesSafe) {
		return "", ErrNotFixable
	}
	iniSet, poolSet, err := phpPlan(host, rt, poolName, base, set)
	if err != nil {
		if set {
			return "", err
		}
		// Revert where the plan can't tell (the pool is gone): out of both.
		iniSet, poolSet = map[string]string{}, map[string]string{}
		for _, s := range phpSettings[base] {
			iniSet[s.key], poolSet[s.key] = "", ""
		}
	}
	iniFile, poolFile := phpDropIns(rt)
	if poolName == "" {
		poolSet = nil
	}

	type saved struct {
		file, old string
		had       bool
	}
	var undo []saved
	restore := func() error {
		var errs []error
		for _, s := range undo {
			if s.had {
				errs = append(errs, writePHPFile(h, s.file, s.old))
			} else {
				errs = append(errs, restoreFile(h, s.file, "", false, 0o644))
			}
		}
		return errors.Join(errs...)
	}
	write := func(file, next string) error {
		old, had := readOptional(h, file)
		if next == old || (next == "" && !had) {
			return nil
		}
		undo = append(undo, saved{file, old, had})
		return writePHPFile(h, file, next)
	}
	if iniFile != "" && len(iniSet) > 0 {
		old, _ := readOptional(h, iniFile)
		if err := write(iniFile, setINI(old, iniSet)); err != nil {
			return "", fmt.Errorf("write %s, %s: %w", iniFile, undone(restore()), err)
		}
	}
	if poolFile != "" && len(poolSet) > 0 {
		old, _ := readOptional(h, poolFile)
		if err := write(poolFile, setPoolINI(old, poolName, poolSet)); err != nil {
			return "", fmt.Errorf("write %s, %s: %w", poolFile, undone(restore()), err)
		}
	}
	if len(undo) == 0 {
		if set {
			return PHPNoChange + describe(iniSet, poolSet) + " already in InfraFence's drop-in for " + rtID, nil
		}
		return PHPNoChange + "nothing to remove", nil
	}

	if rt.SAPI == "fpm" && rt.FPM != "" {
		if !exists(h, rt.FPM) {
			return "", fmt.Errorf("%w: %s not found to test the configuration, %s", ErrUnsupported, rt.FPM, undone(restore()))
		}
		args := []string{"-t"}
		if rt.FPMConf != "" {
			args = append(args, "-y", rt.FPMConf)
		}
		if out, err := h.Run(rt.FPM, args...); err != nil {
			return "", fmt.Errorf("php-fpm config test failed, %s: %s", undone(restore()), strings.TrimSpace(out))
		}
	}
	if set {
		if err := phpEffective(h, rtID, poolName, iniSet, poolSet); err != nil {
			return "", fmt.Errorf("%v, %s", err, undone(restore()))
		}
	}
	reloaded, err := reloadPHP(h, rt)
	if err != nil {
		rb := undone(restore())
		// With the old files back, PHP must be running again whatever the
		// failed reload left behind.
		if _, err2 := reloadPHP(h, rt); err2 != nil {
			rb += fmt.Sprintf("; %s is still not running after the rollback (%v), check it by hand", reloaded, err2)
		}
		return "", fmt.Errorf("could not reload %s, %s: %v", reloaded, rb, err)
	}
	recordPHPDropIns(h)

	var files []string
	for _, s := range undo {
		files = append(files, s.file)
	}
	if !set {
		return fmt.Sprintf("removed %s from %s; %s", keys(iniSet), strings.Join(files, ", "), reloaded), nil
	}
	return fmt.Sprintf("set %s in %s; %s", describe(iniSet, poolSet), strings.Join(files, ", "), reloaded), nil
}

// phpEffective re-reads the configuration and checks the new values are
// the ones in effect, through the runtime's own php binary when there is
// one (it reads the same php.ini and scan directory).
func phpEffective(h Host, rtID, poolName string, iniSet, poolSet map[string]string) error {
	rt, ok := discoverPHP(h, true).Find(rtID)
	if !ok {
		return fmt.Errorf("PHP runtime %s disappeared", rtID)
	}
	same := func(key, got, want string) bool {
		if phpBool[key] {
			return phpconf.IsOn(got) == phpconf.IsOn(want)
		}
		return strings.TrimSpace(got) == strings.TrimSpace(want)
	}
	var pl *phpconf.Pool
	if poolName != "" {
		if p, ok := rt.Pool(poolName); ok {
			pl = &p
		}
	}
	for _, m := range []map[string]string{iniSet, poolSet} {
		for k, want := range m {
			d := rt.Get(k)
			if pl != nil {
				d = rt.GetPool(*pl, k)
			}
			if !same(k, d.Value, want) {
				return fmt.Errorf("another setting overrides %s (%s = %q in %s:%d)", k, k, d.Value, d.File, d.Line)
			}
		}
	}
	if rt.CLI == "" || !exists(h, rt.CLI) || rt.ScanDir == "" {
		return nil
	}
	for k, want := range iniSet {
		if pl != nil && rt.GetPool(*pl, k).File != rt.ScanDir+"/"+PHPIniDropIn {
			continue // a pool setting decides, php -r can't see it
		}
		out, err := h.Run("env", "PHP_INI_SCAN_DIR="+rt.ScanDir, rt.CLI, "-c", rt.Ini, "-d", "auto_prepend_file=", "-d", "auto_append_file=", "-r", "echo '@@', ini_get('"+k+"'), '@@';")
		// Between markers: startup warnings may share the output.
		_, rest, ok1 := strings.Cut(out, "@@")
		got, _, ok2 := strings.Cut(rest, "@@")
		if err != nil || !ok1 || !ok2 {
			return fmt.Errorf("could not read %s back with %s: %v %s", k, rt.CLI, err, strings.TrimSpace(out))
		}
		got = strings.TrimSpace(got)
		if phpBool[k] && got == "" {
			got = "0"
		}
		if !same(k, got, want) {
			return fmt.Errorf("%s is %q for %s, not %q: another setting overrides it", k, got, rt.CLI, want)
		}
	}
	return nil
}

// reloadPHP makes the runtime read its configuration again: PHP-FPM is
// reloaded (its workers finish their requests), mod_php and CGI through a
// graceful Apache reload. It returns what it reloaded.
func reloadPHP(h Host, rt phpconf.Runtime) (string, error) {
	switch {
	case rt.SAPI == "fpm" && rt.Service != "":
		if findBinary(h, "systemctl") == "" {
			if _, err := h.Run("service", rt.Service, "reload"); err != nil {
				return rt.Service, err
			}
			return rt.Service + " reloaded (requests in progress finish)", nil
		}
		reloadErr := func() error { _, err := h.Run("systemctl", "reload", rt.Service); return err }()
		// PHP-FPM re-executes itself on reload and exits if it can't: watch
		// it for a moment, and never leave it stopped (start it again, which
		// is all that is left to do for a stopped service).
		for i := 0; i < 3 && reloadErr == nil; i++ {
			time.Sleep(phpSettle)
			if !phpActive(h, rt.Service) {
				break
			}
			if i == 2 {
				return rt.Service + " reloaded (requests in progress finish)", nil
			}
		}
		if !phpActive(h, rt.Service) {
			_, _ = h.Run("systemctl", "start", rt.Service)
			if !phpActive(h, rt.Service) {
				return rt.Service, fmt.Errorf("%s is not running after the reload", rt.Service)
			}
			if reloadErr == nil {
				return rt.Service, fmt.Errorf("%s stopped after the reload (started again)", rt.Service)
			}
		}
		if reloadErr != nil {
			return rt.Service, reloadErr
		}
		return rt.Service + " reloaded (requests in progress finish)", nil
	case rt.SAPI == "apache2handler" || rt.SAPI == "cgi":
		ctl := apachectl(h)
		if ctl == "" {
			return "PHP reads it when its processes next start", nil
		}
		if out, err := h.Run(ctl, "configtest"); err != nil {
			return "Apache", fmt.Errorf("apachectl configtest: %s", strings.TrimSpace(out))
		}
		if _, err := h.Run(ctl, "graceful"); err != nil {
			return "Apache", err
		}
		return "Apache reloaded (graceful)", nil
	}
	return "nothing to reload", nil
}

// phpSettle is how long PHP-FPM is given after a reload between checks
// (replaced in tests).
var phpSettle = time.Second

func phpActive(h Host, unit string) bool {
	out, err := h.Run("systemctl", "is-active", unit)
	return err == nil || strings.TrimSpace(out) == "active"
}

// PHPNoChange starts the message of a fix that changed nothing (the caller
// then has nothing to verify or roll back).
const PHPNoChange = "no change: "

// writePHPFile replaces p atomically: a temporary file the include
// patterns don't match (a leading dot, a .tmp suffix), then a rename, so a
// crash never leaves PHP a half-written drop-in. A symlink in place of
// our file is refused. content "" removes it.
func writePHPFile(h Host, p, content string) error {
	if isSymlink(h, p) {
		return fmt.Errorf("%s is a symlink, not InfraFence's file", p)
	}
	if content == "" {
		return writeOrRemove(h, p, "", 0o644)
	}
	r, ok := h.(interface{ Rename(string, string) error })
	if !ok {
		return h.WriteFile(p, []byte(content), 0o644)
	}
	tmp := path.Join(path.Dir(p), "."+path.Base(p)+".tmp")
	if err := h.WriteFile(tmp, []byte(content), 0o644); err != nil {
		return err
	}
	if err := r.Rename(tmp, p); err != nil {
		_ = h.Remove(tmp)
		return err
	}
	return nil
}

func isSymlink(h Host, p string) bool {
	if lh, ok := h.(interface {
		Lstat(string) (os.FileInfo, error)
	}); ok {
		if fi, err := lh.Lstat(p); err == nil {
			return fi.Mode()&os.ModeSymlink != 0
		}
	}
	return false
}

// setINI returns the .ini drop-in with each key set (value "" removes it).
func setINI(content string, set map[string]string) string {
	kv := map[string]string{}
	for _, l := range strings.Split(content, "\n") {
		t := strings.TrimSpace(l)
		if t == "" || t[0] == ';' {
			continue
		}
		if k, v, ok := strings.Cut(t, "="); ok {
			kv[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	for k, v := range set {
		if v == "" {
			delete(kv, k)
		} else {
			kv[k] = v
		}
	}
	if len(kv) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(phpHeader)
	for _, k := range sortedKeys(kv) {
		b.WriteString(k + " = " + kv[k] + "\n")
	}
	return b.String()
}

// setPoolINI returns the pool drop-in with the keys set for one pool
// section (php_admin_*: scripts can't change them back).
func setPoolINI(content, section string, set map[string]string) string {
	pools := parsePoolDropIn(content)
	if pools[section] == nil {
		pools[section] = map[string]string{}
	}
	for k, v := range set {
		if v == "" {
			delete(pools[section], k)
		} else {
			pools[section][k] = v
		}
	}
	return renderPoolDropIn(pools)
}

func parsePoolDropIn(content string) map[string]map[string]string {
	pools := map[string]map[string]string{}
	cur := ""
	for _, l := range strings.Split(content, "\n") {
		t := strings.TrimSpace(l)
		if t == "" || t[0] == ';' {
			continue
		}
		if t[0] == '[' {
			cur = strings.Trim(t, "[] ")
			if pools[cur] == nil {
				pools[cur] = map[string]string{}
			}
			continue
		}
		k, v, ok := strings.Cut(t, "=")
		if !ok || cur == "" {
			continue
		}
		k = strings.TrimSpace(k)
		if i, j := strings.IndexByte(k, '['), strings.IndexByte(k, ']'); i > 0 && j > i {
			pools[cur][k[i+1:j]] = strings.TrimSpace(v)
		}
	}
	return pools
}

func renderPoolDropIn(pools map[string]map[string]string) string {
	var b strings.Builder
	for _, name := range sortedKeys(pools) {
		kv := pools[name]
		if len(kv) == 0 {
			continue
		}
		b.WriteString("\n[" + name + "]\n")
		for _, k := range sortedKeys(kv) {
			kind := "php_admin_value"
			if phpBool[k] {
				kind = "php_admin_flag"
			}
			b.WriteString(kind + "[" + k + "] = " + kv[k] + "\n")
		}
	}
	if b.Len() == 0 {
		return ""
	}
	return phpHeader + b.String()
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func describe(ini, pool map[string]string) string {
	var parts []string
	for _, m := range []map[string]string{ini, pool} {
		for _, k := range sortedKeys(m) {
			parts = append(parts, k+" = "+m[k])
		}
	}
	return strings.Join(parts, ", ")
}

func keys(m map[string]string) string { return strings.Join(sortedKeys(m), ", ") }

// ── drop-ins changed by someone else ────────────────────────────────────────

// PHPDropInChange is a drop-in of ours that someone else changed or removed.
type PHPDropInChange struct {
	Runtime string
	File    string
	Change  string // modified or removed
}

func loadPHPState(h Host) map[string]string {
	st := map[string]string{}
	if b, err := h.ReadFile(PHPStatePath); err == nil {
		_ = json.Unmarshal(b, &st)
	}
	return st
}

// recordPHPDropIns stores the hash of every PHP drop-in of ours.
func recordPHPDropIns(h Host) {
	st := map[string]string{}
	for _, rt := range discoverPHP(h, true).Runtimes {
		ini, pool := phpDropIns(rt)
		for _, f := range []string{ini, pool} {
			if b, err := h.ReadFile(f); f != "" && err == nil {
				sum := sha256.Sum256(b)
				st[f] = hex.EncodeToString(sum[:])
			}
		}
	}
	b, _ := json.Marshal(st)
	_ = h.MkdirAll(filepath.Dir(PHPStatePath), 0o700)
	_ = h.WriteFile(PHPStatePath, b, 0o600)
}

// CheckPHPDropIns reports the drop-ins whose content is no longer what
// InfraFence wrote (once per change), and drops pool sections whose pool
// no longer exists, which would otherwise stop PHP-FPM at its next reload.
func CheckPHPDropIns(h Host) []PHPDropInChange {
	st := loadPHPState(h)
	host := discoverPHP(h, true)
	var out []PHPDropInChange
	owner := map[string]string{}
	for _, rt := range host.Runtimes {
		ini, pool := phpDropIns(rt)
		owner[ini], owner[pool] = rt.ID, rt.ID
		if pool != "" {
			prunePoolDropIn(h, rt, pool)
		}
	}
	for _, f := range sortedKeys(st) {
		b, err := h.ReadFile(f)
		switch {
		case err != nil:
			out = append(out, PHPDropInChange{owner[f], f, "removed"})
		default:
			sum := sha256.Sum256(b)
			if hex.EncodeToString(sum[:]) != st[f] {
				out = append(out, PHPDropInChange{owner[f], f, "modified"})
			}
		}
	}
	if len(out) > 0 || len(st) > 0 {
		recordPHPDropIns(h)
	}
	return out
}

// prunePoolDropIn removes the sections of pools only our drop-in defines
// (their own file was deleted): such a section is a pool without a listen
// address, which PHP-FPM refuses.
func prunePoolDropIn(h Host, rt phpconf.Runtime, file string) {
	old, had := readOptional(h, file)
	if !had {
		return
	}
	pools := parsePoolDropIn(old)
	changed := false
	for name := range pools {
		p, ok := rt.Pool(name)
		if !ok || !definedElsewhere(p, file) {
			delete(pools, name)
			changed = true
		}
	}
	if changed {
		_ = writeOrRemove(h, file, renderPoolDropIn(pools), 0o644)
		recordPHPDropIns(h)
	}
}

// definedElsewhere reports whether pool p is defined by a file other than ours.
func definedElsewhere(p phpconf.Pool, ours string) bool {
	for _, f := range p.Files {
		if f != ours {
			return true
		}
	}
	return false
}

// removePHPDropIns deletes every PHP drop-in of ours and reloads the
// runtimes that used one (uninstall).
func removePHPDropIns(h Host) ([]string, []error) {
	var done []string
	var errs []error
	for _, rt := range discoverPHP(h, true).Runtimes {
		ini, pool := phpDropIns(rt)
		removed := false
		for _, f := range []string{ini, pool} {
			if f != "" && exists(h, f) {
				if err := h.Remove(f); err == nil {
					done = append(done, f)
					removed = true
				}
			}
		}
		if removed {
			if what, err := reloadPHP(h, rt); err != nil {
				errs = append(errs, fmt.Errorf("reload %s: %w", what, err))
			}
		}
	}
	if exists(h, PHPStatePath) {
		_ = h.Remove(PHPStatePath)
	}
	return done, errs
}
