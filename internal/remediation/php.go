package remediation

// PHP hardening fixes. Like the other fixes, nothing edits a main
// configuration file: each PHP runtime gets one drop-in of its own,
// <scan dir>/zz-infrafence-hardening.ini, read after php.ini and the other
// files of the directory it scans, so undoing a fix removes a line, and the
// file once it is empty. An .ini file can never stop PHP from starting (a
// bad line is a warning), so whatever happens to the rest of the
// configuration this file can't take the sites down.
//
// Nothing is ever written in PHP-FPM's pool configuration: PHP-FPM merges
// sections by name, so a section of ours left behind after someone deletes
// the pool's file would be a pool without a listen address, and PHP-FPM
// would refuse to start. A pool that sets a directive in its own file
// (which beats any .ini file) is reported with a manual fix instead.
//
// After the
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
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/infrafence/infrafence-agent/internal/phpconf"
)

// PHPIniDropIn is the name of the drop-in InfraFence owns in each PHP
// runtime's scan directory.
const PHPIniDropIn = "zz-infrafence-hardening.ini"

// PHPStatePath records what InfraFence wrote in each PHP drop-in, so a
// change by someone else (a panel, a package, a person) is detected.
var PHPStatePath = "/var/lib/infrafence/php-dropins.json"

const phpHeader = "; Managed by InfraFence (PHP hardening fixes applied from the dashboard).\n; Delete this file and reload PHP to undo them.\n"

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
	reason, _ := phpFixable(h, checkID, p)
	return reason == "", reason
}

// phpFixable returns why checkID's fix can't be applied ("" when it can),
// and for a pool that sets the directive itself, the error that says so.
func phpFixable(h Host, checkID string, p Policy) (string, error) {
	base, rtID, poolName, site, _ := phpconf.ParseID(checkID)
	if site != "" {
		return ReasonManaged, nil
	}
	if phpconf.FixClass(base) == phpconf.FixNone {
		if base == phpconf.CheckAllowURLFopen || base == phpconf.CheckCookieSecure || base == phpconf.CheckCookieHTTPOnly {
			return ReasonSiteRisk, nil
		}
		return ReasonNoAutomation, nil
	}
	host := discoverPHP(h, false)
	rt, ok := host.Find(rtID)
	if !ok {
		return ReasonUnsupported, nil
	}
	if rt.Panel != "" || !p.ConfigChangesSafe {
		return ReasonManaged, nil
	}
	if _, err := phpPlan(rt, poolName, base, true); err != nil {
		if errors.Is(err, errPoolSets) {
			return ReasonManualOnly, err
		}
		return ReasonUnsupported, err
	}
	return "", nil
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

// errPoolSets: the pool sets the directive in its own file, which only a
// person changes.
var errPoolSets = errors.New("the pool sets it in its own file")

// phpPlan gives the settings of a fix for the runtime's .ini drop-in.
// set=false (revert) gives the keys with "" (remove).
func phpPlan(rt phpconf.Runtime, poolName, base string, set bool) (map[string]string, error) {
	var pl *phpconf.Pool
	if poolName != "" {
		p, ok := rt.Pool(poolName)
		if !ok {
			return nil, fmt.Errorf("%w: pool %s not found", ErrUnsupported, poolName)
		}
		pl = &p
	}
	if set && rt.SAPI == "fpm" && rt.FPM == "" {
		return nil, fmt.Errorf("%w: no php-fpm binary to test the configuration with", ErrUnsupported)
	}
	iniFile := phpDropIn(rt)
	if iniFile == "" {
		return nil, fmt.Errorf("%w: this PHP has no scan directory", ErrUnsupported)
	}
	if set && pl != nil {
		if d, ok := phpconf.PoolSets(rt, pl, base); ok {
			return nil, fmt.Errorf("%w (%s in %s:%d): InfraFence does not change PHP-FPM's pool files, change it there by hand", errPoolSets, d.Key, d.File, d.Line)
		}
	}
	cur := rt.WithoutFile(iniFile).Get("disable_functions").Value
	ini := map[string]string{}
	for _, s := range phpconf.FixSettings(base, cur) {
		ini[s.Key] = ""
		if set {
			// The current list is copied into our file: only plain function
			// names, so nothing in it (a \r is a line break to PHP) can
			// become a directive of its own there.
			if s.Key == "disable_functions" && !phpFuncList.MatchString(s.Value) {
				return nil, fmt.Errorf("%w: the current disable_functions value has characters other than function names", ErrUnsupported)
			}
			ini[s.Key] = s.Value
		}
	}
	if len(ini) == 0 {
		return nil, ErrNotFixable
	}
	return ini, nil
}

var phpFuncList = regexp.MustCompile(`^[A-Za-z0-9_\\]+(,[A-Za-z0-9_\\]+)*$`)

// phpDropIn returns the runtime's drop-in path ("" when it has no scan
// directory).
func phpDropIn(rt phpconf.Runtime) string {
	if rt.ScanDir == "" {
		return ""
	}
	return rt.ScanDir + "/" + PHPIniDropIn
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
	iniSet, err := phpPlan(rt, poolName, base, set)
	if err != nil {
		if set {
			return "", err
		}
		// Revert where the plan can't tell (the pool is gone): the keys
		// come out of the drop-in all the same.
		iniSet = map[string]string{}
		for _, s := range phpconf.FixSettings(base, "") {
			iniSet[s.Key] = ""
		}
	}
	iniFile := phpDropIn(rt)

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
	if len(undo) == 0 {
		if set {
			return PHPNoChange + describe(iniSet) + " already in InfraFence's drop-in for " + rtID, nil
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
		if err := phpEffective(h, rtID, poolName, iniSet); err != nil {
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
	return fmt.Sprintf("set %s in %s; %s", describe(iniSet), strings.Join(files, ", "), reloaded), nil
}

// phpEffective re-reads the configuration and checks the new values are
// the ones in effect, through the runtime's own php binary when there is
// one (it reads the same php.ini and scan directory).
func phpEffective(h Host, rtID, poolName string, iniSet map[string]string) error {
	rt, ok := discoverPHP(h, true).Find(rtID)
	if !ok {
		return fmt.Errorf("PHP runtime %s disappeared", rtID)
	}
	same := func(key, got, want string) bool {
		if phpconf.IsBool(key) {
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
	for k, want := range iniSet {
		d := rt.Get(k)
		if pl != nil {
			d = rt.GetPool(*pl, k)
		}
		if !same(k, d.Value, want) {
			return fmt.Errorf("another setting overrides %s (%s = %q in %s:%d)", k, k, d.Value, d.File, d.Line)
		}
	}
	if rt.CLI == "" || !exists(h, rt.CLI) || rt.ScanDir == "" {
		return nil
	}
	for k, want := range iniSet {
		out, err := h.Run("env", "PHP_INI_SCAN_DIR="+rt.ScanDir, rt.CLI, "-c", rt.Ini, "-d", "auto_prepend_file=", "-d", "auto_append_file=", "-r", "echo '@@', ini_get('"+k+"'), '@@';")
		// Between markers: startup warnings may share the output.
		_, rest, ok1 := strings.Cut(out, "@@")
		got, _, ok2 := strings.Cut(rest, "@@")
		if err != nil || !ok1 || !ok2 {
			return fmt.Errorf("could not read %s back with %s: %v %s", k, rt.CLI, err, strings.TrimSpace(out))
		}
		got = strings.TrimSpace(got)
		if phpconf.IsBool(k) && got == "" {
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

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func describe(ini map[string]string) string {
	var parts []string
	for _, k := range sortedKeys(ini) {
		parts = append(parts, k+" = "+ini[k])
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
		if f := phpDropIn(rt); f != "" {
			if b, err := h.ReadFile(f); err == nil {
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
// InfraFence wrote (once per change).
func CheckPHPDropIns(h Host) []PHPDropInChange {
	st := loadPHPState(h)
	host := discoverPHP(h, true)
	var out []PHPDropInChange
	owner := map[string]string{}
	for _, rt := range host.Runtimes {
		owner[phpDropIn(rt)] = rt.ID
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

// removePHPDropIns deletes every PHP drop-in of ours and reloads the
// runtimes that used one (uninstall).
func removePHPDropIns(h Host) ([]string, []error) {
	var done []string
	var errs []error
	for _, rt := range discoverPHP(h, true).Runtimes {
		f := phpDropIn(rt)
		if f == "" || !exists(h, f) {
			continue
		}
		if err := h.Remove(f); err != nil {
			errs = append(errs, err)
			continue
		}
		done = append(done, f)
		if what, err := reloadPHP(h, rt); err != nil {
			errs = append(errs, fmt.Errorf("reload %s: %w", what, err))
		}
	}
	if exists(h, PHPStatePath) {
		_ = h.Remove(PHPStatePath)
	}
	return done, errs
}
