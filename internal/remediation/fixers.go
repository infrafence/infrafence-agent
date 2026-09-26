// Package remediation applies the hardening fixes an admin asks for from the
// dashboard. Every fix is written so it can't take a production server down:
//
//   - nothing edits a main configuration file: each change lives in a file
//     of its own (sshd_config.d, nginx conf.d, Apache conf-enabled/conf.d),
//     so undoing it means deleting that file;
//   - the service's own config test must pass (sshd -t, nginx -t,
//     apachectl configtest) and the new value must actually be in effect,
//     otherwise the change is rolled back before any reload;
//   - services are reloaded, never restarted, so open sessions and
//     connections survive;
//   - changes that could lock people out (root login, password login, the
//     SSH port) or break sites (directory listing, security headers) are
//     never automatic: the dashboard shows how to do them by hand.
package remediation

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Why a finding can't be fixed automatically. The dashboard translates these
// codes.
const (
	ReasonLockoutRisk  = "lockout_risk"  // could lock people out of SSH
	ReasonSiteRisk     = "site_risk"     // could change how websites behave
	ReasonManaged      = "managed"       // a hosting panel or config management owns the files
	ReasonUnsupported  = "unsupported"   // this host's layout isn't one we can change safely
	ReasonNoAutomation = "no_automation" // there is no automatic fix for this check
)

// Host is what the fixes need from the system; tests replace it.
type Host interface {
	Run(name string, args ...string) (string, error)
	LookPath(name string) (string, error)
	ReadFile(path string) ([]byte, error)
	WriteFile(path string, data []byte, perm os.FileMode) error
	Remove(path string) error
	Stat(path string) (os.FileInfo, error)
	Chmod(path string, mode os.FileMode) error
	Symlink(oldname, newname string) error
	MkdirAll(path string, perm os.FileMode) error
}

type osHost struct{}

func (osHost) Run(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}
func (osHost) LookPath(name string) (string, error)              { return exec.LookPath(name) }
func (osHost) ReadFile(path string) ([]byte, error)              { return os.ReadFile(path) }
func (osHost) Remove(path string) error                          { return os.Remove(path) }
func (osHost) Stat(path string) (os.FileInfo, error)             { return os.Stat(path) }
func (osHost) Chmod(path string, mode os.FileMode) error         { return os.Chmod(path, mode) }
func (osHost) Symlink(oldname, newname string) error             { return os.Symlink(oldname, newname) }
func (osHost) MkdirAll(path string, perm os.FileMode) error      { return os.MkdirAll(path, perm) }
func (osHost) WriteFile(p string, d []byte, m os.FileMode) error { return os.WriteFile(p, d, m) }

// System is the real host.
var System Host = osHost{}

// Files InfraFence owns. Uninstall deletes them.
const (
	SSHDropIn      = "/etc/ssh/sshd_config.d/00-infrafence-hardening.conf"
	NginxDropIn    = "/etc/nginx/conf.d/zz-infrafence-hardening.conf"
	ApacheDebAvail = "/etc/apache2/conf-available/zz-infrafence-hardening.conf"
	ApacheDebLink  = "/etc/apache2/conf-enabled/zz-infrafence-hardening.conf"
	ApacheRHEL     = "/etc/httpd/conf.d/zz-infrafence-hardening.conf"
)

type fixKind int

const (
	kindSSH fixKind = iota
	kindPerm
	kindNginx
	kindApache
)

type fix struct {
	kind  fixKind
	key   string      // directive (ssh, nginx, apache)
	value string      // value to set
	path  string      // file (permissions)
	mode  os.FileMode // strictest allowed mode (permissions)
}

var fixes = map[string]fix{
	"SSH_X11_FORWARDING":      {kind: kindSSH, key: "X11Forwarding", value: "no"},
	"SSH_MAX_AUTH_TRIES":      {kind: kindSSH, key: "MaxAuthTries", value: "4"},
	"PERM_SHADOW":             {kind: kindPerm, path: "/etc/shadow", mode: 0o640},
	"PERM_PASSWD":             {kind: kindPerm, path: "/etc/passwd", mode: 0o644},
	"PERM_SSHD_CONFIG":        {kind: kindPerm, path: "/etc/ssh/sshd_config", mode: 0o600},
	"PERM_AUTH_KEYS":          {kind: kindPerm, path: "/root/.ssh/authorized_keys", mode: 0o600},
	"WS_SERVER_TOKENS":        {kind: kindNginx, key: "server_tokens", value: "off"},
	"WS_SERVER_TOKENS_APACHE": {kind: kindApache, key: "ServerTokens", value: "Prod"},
	"WS_SERVER_SIGNATURE":     {kind: kindApache, key: "ServerSignature", value: "Off"},
	"WS_TRACE_METHOD":         {kind: kindApache, key: "TraceEnable", value: "Off"},
}

var manual = map[string]string{
	"SSH_ROOT_LOGIN":       ReasonLockoutRisk,
	"SSH_PASSWORD_AUTH":    ReasonLockoutRisk,
	"SSH_DEFAULT_PORT":     ReasonLockoutRisk,
	"WS_DIRECTORY_LISTING": ReasonSiteRisk,
	"WS_SSL_PROTOCOLS":     ReasonSiteRisk,
	"WS_HSTS":              ReasonSiteRisk,
	"WS_XCTO":              ReasonSiteRisk,
	"WS_XFO":               ReasonSiteRisk,
	"WS_CSP":               ReasonSiteRisk,
	"WS_PERMISSIONS":       ReasonSiteRisk,
	"WS_REFERRER":          ReasonSiteRisk,
}

// Policy says what the host allows.
type Policy struct {
	// ConfigChangesSafe is false when a hosting panel or configuration
	// management owns the service configuration (preflight decides).
	ConfigChangesSafe bool
}

// Availability reports whether checkID has an automatic fix on this host,
// and if not, why.
func Availability(checkID string, p Policy) (bool, string) {
	if r, ok := manual[checkID]; ok {
		return false, r
	}
	f, ok := fixes[checkID]
	if !ok {
		return false, ReasonNoAutomation
	}
	if f.kind != kindPerm && !p.ConfigChangesSafe {
		return false, ReasonManaged
	}
	return true, ""
}

// ErrNotFixable is returned for checks without an automatic fix.
var ErrNotFixable = errors.New("no automatic fix for this check on this server")

// Apply fixes one check. The returned message says what was changed.
func Apply(h Host, checkID string, p Policy) (string, error) {
	if ok, _ := Availability(checkID, p); !ok {
		return "", ErrNotFixable
	}
	f := fixes[checkID]
	switch f.kind {
	case kindSSH:
		return setSSH(h, f.key, f.value)
	case kindPerm:
		return tightenPerm(h, f.path, f.mode)
	case kindNginx:
		return setNginx(h, f.key, f.value)
	case kindApache:
		return setApache(h, f.key, f.value)
	}
	return "", ErrNotFixable
}

// Revert undoes a fix applied by Apply (permissions stay as they are: a
// stricter mode never breaks anything and loosening it again would reopen
// the problem).
func Revert(h Host, checkID string) (string, error) {
	f, ok := fixes[checkID]
	if !ok {
		return "", ErrNotFixable
	}
	switch f.kind {
	case kindSSH:
		return setSSH(h, f.key, "")
	case kindNginx:
		return setNginx(h, f.key, "")
	case kindApache:
		return setApache(h, f.key, "")
	}
	return "permissions left as they are", nil
}

// RemoveAll deletes every file InfraFence added and reloads the services
// that used them. Used by uninstall.
func RemoveAll(h Host) []string {
	var done []string
	if exists(h, SSHDropIn) {
		if err := h.Remove(SSHDropIn); err == nil {
			reloadSSH(h)
			done = append(done, SSHDropIn)
		}
	}
	if exists(h, NginxDropIn) {
		if err := h.Remove(NginxDropIn); err == nil {
			if _, err := h.Run("nginx", "-t"); err == nil {
				reloadNginx(h)
			}
			done = append(done, NginxDropIn)
		}
	}
	apacheChanged := false
	for _, p := range []string{ApacheDebLink, ApacheDebAvail, ApacheRHEL} {
		if exists(h, p) || isLink(h, p) {
			if err := h.Remove(p); err == nil {
				done = append(done, p)
				apacheChanged = true
			}
		}
	}
	if apacheChanged {
		if ctl := apachectl(h); ctl != "" {
			if _, err := h.Run(ctl, "configtest"); err == nil {
				h.Run(ctl, "graceful")
			}
		}
	}
	return done
}

// ── SSH ─────────────────────────────────────────────────────────────────────

var sshIncludeRe = regexp.MustCompile(`(?im)^\s*Include\s+\S*sshd_config\.d/\*\.conf`)

// setSSH sets key to value in InfraFence's sshd drop-in (value "" removes
// it), validates with `sshd -t`, checks the value is in effect with
// `sshd -T`, then reloads sshd. Any failure puts the old file back.
func setSSH(h Host, key, value string) (string, error) {
	sshd := findBinary(h, "sshd", "/usr/sbin/sshd")
	if sshd == "" {
		return "", fmt.Errorf("%w: sshd not found", ErrUnsupported)
	}
	main, err := h.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		return "", fmt.Errorf("read sshd_config: %w", err)
	}
	if !sshIncludeRe.Match(main) {
		return "", fmt.Errorf("%w: sshd_config does not include sshd_config.d", ErrUnsupported)
	}

	old, hadOld := readOptional(h, SSHDropIn)
	next := setDirective(old, key, value, " ")
	if err := writeOrRemove(h, SSHDropIn, next, 0o600); err != nil {
		return "", err
	}
	restore := func() { restoreFile(h, SSHDropIn, old, hadOld, 0o600) }

	if out, err := h.Run(sshd, "-t"); err != nil {
		restore()
		return "", fmt.Errorf("sshd -t failed, change undone: %s", strings.TrimSpace(out))
	}
	if value != "" {
		out, err := h.Run(sshd, "-T")
		if err != nil || !hasEffective(out, key, value) {
			restore()
			return "", fmt.Errorf("another setting overrides %s, change undone", key)
		}
	}
	if err := reloadSSH(h); err != nil {
		restore()
		return "", fmt.Errorf("could not reload sshd, change undone: %v", err)
	}
	if value == "" {
		return fmt.Sprintf("removed %s from %s; sshd reloaded", key, SSHDropIn), nil
	}
	return fmt.Sprintf("set %s %s in %s; sshd reloaded (open sessions unaffected)", key, value, SSHDropIn), nil
}

func reloadSSH(h Host) error {
	var last error
	for _, unit := range []string{"ssh", "sshd"} {
		if _, err := h.Run("systemctl", "reload", unit); err == nil {
			return nil
		} else {
			last = err
		}
	}
	for _, svc := range []string{"ssh", "sshd"} {
		if _, err := h.Run("service", svc, "reload"); err == nil {
			return nil
		}
	}
	return last
}

// hasEffective reports whether `sshd -T` output has key set to value.
func hasEffective(dump, key, value string) bool {
	want := strings.ToLower(key) + " " + strings.ToLower(value)
	for _, line := range strings.Split(dump, "\n") {
		if strings.ToLower(strings.TrimSpace(line)) == want {
			return true
		}
	}
	return false
}

// ── Permissions ─────────────────────────────────────────────────────────────

// tightenPerm removes the permission bits beyond max; it never adds any.
func tightenPerm(h Host, path string, max os.FileMode) (string, error) {
	info, err := h.Stat(path)
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	cur := info.Mode().Perm()
	next := cur & max
	if next == cur {
		return fmt.Sprintf("%s already %04o", path, cur), nil
	}
	if err := h.Chmod(path, next); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s: %04o → %04o", path, cur, next), nil
}

// ── nginx ───────────────────────────────────────────────────────────────────

func setNginx(h Host, key, value string) (string, error) {
	if findBinary(h, "nginx", "/usr/sbin/nginx") == "" {
		return "", fmt.Errorf("%w: nginx not found", ErrUnsupported)
	}
	if !exists(h, filepath.Dir(NginxDropIn)) {
		return "", fmt.Errorf("%w: no /etc/nginx/conf.d", ErrUnsupported)
	}
	old, hadOld := readOptional(h, NginxDropIn)
	next := setDirective(old, key, value+";", " ")
	if value == "" {
		next = setDirective(old, key, "", " ")
	}
	if err := writeOrRemove(h, NginxDropIn, next, 0o644); err != nil {
		return "", err
	}
	restore := func() { restoreFile(h, NginxDropIn, old, hadOld, 0o644) }

	if value != "" {
		// The file must actually be loaded, inside the http block.
		dump, err := h.Run("nginx", "-T")
		if err != nil || !strings.Contains(dump, "# configuration file "+NginxDropIn) {
			restore()
			if err != nil && strings.Contains(dump, "duplicate") {
				return "", fmt.Errorf("%s is already set elsewhere in the nginx configuration, change undone", key)
			}
			return "", fmt.Errorf("%w: nginx does not load conf.d, change undone", ErrUnsupported)
		}
	}
	if out, err := h.Run("nginx", "-t"); err != nil {
		restore()
		if strings.Contains(out, "duplicate") {
			return "", fmt.Errorf("%s is already set elsewhere in the nginx configuration, change undone", key)
		}
		return "", fmt.Errorf("nginx -t failed, change undone: %s", strings.TrimSpace(out))
	}
	if err := reloadNginx(h); err != nil {
		restore()
		return "", fmt.Errorf("could not reload nginx, change undone: %v", err)
	}
	if value == "" {
		return fmt.Sprintf("removed %s from %s; nginx reloaded", key, NginxDropIn), nil
	}
	return fmt.Sprintf("set %s %s in %s; nginx reloaded", key, value, NginxDropIn), nil
}

func reloadNginx(h Host) error {
	if _, err := h.Run("systemctl", "reload", "nginx"); err == nil {
		return nil
	}
	_, err := h.Run("nginx", "-s", "reload")
	return err
}

// ── Apache ──────────────────────────────────────────────────────────────────

func setApache(h Host, key, value string) (string, error) {
	ctl := apachectl(h)
	if ctl == "" {
		return "", fmt.Errorf("%w: apachectl not found", ErrUnsupported)
	}
	var file, link string
	switch {
	case exists(h, "/etc/apache2/conf-available") && exists(h, "/etc/apache2/conf-enabled"):
		file, link = ApacheDebAvail, ApacheDebLink
	case exists(h, "/etc/httpd/conf.d"):
		file = ApacheRHEL
	default:
		return "", fmt.Errorf("%w: unknown Apache layout", ErrUnsupported)
	}

	old, hadOld := readOptional(h, file)
	hadLink := link != "" && (exists(h, link) || isLink(h, link))
	next := setDirective(old, key, value, " ")
	if err := writeOrRemove(h, file, next, 0o644); err != nil {
		return "", err
	}
	if link != "" {
		if next != "" && !hadLink {
			if err := h.Symlink("../conf-available/"+filepath.Base(file), link); err != nil {
				restoreFile(h, file, old, hadOld, 0o644)
				return "", err
			}
		}
		if next == "" && hadLink {
			h.Remove(link)
		}
	}
	restore := func() {
		restoreFile(h, file, old, hadOld, 0o644)
		if link != "" {
			if hadLink && !isLink(h, link) {
				h.Symlink("../conf-available/"+filepath.Base(file), link)
			}
			if !hadLink {
				h.Remove(link)
			}
		}
	}

	if out, err := h.Run(ctl, "configtest"); err != nil {
		restore()
		return "", fmt.Errorf("apachectl configtest failed, change undone: %s", strings.TrimSpace(out))
	}
	if _, err := h.Run(ctl, "graceful"); err != nil {
		restore()
		return "", fmt.Errorf("could not reload Apache, change undone: %v", err)
	}
	if value == "" {
		return fmt.Sprintf("removed %s from %s; Apache reloaded", key, file), nil
	}
	return fmt.Sprintf("set %s %s in %s; Apache reloaded (graceful)", key, value, file), nil
}

func apachectl(h Host) string {
	return findBinary(h, "apache2ctl", "apachectl", "/usr/sbin/apache2ctl", "/usr/sbin/apachectl")
}

// ── helpers ─────────────────────────────────────────────────────────────────

// ErrUnsupported marks hosts whose layout we don't change.
var ErrUnsupported = errors.New(ReasonUnsupported)

const header = "# Managed by InfraFence (hardening fixes applied from the dashboard).\n# Delete this file to undo them.\n"

// setDirective returns the drop-in content with key set to value (value ""
// removes it). Returns "" when no directive is left.
func setDirective(content, key, value, sep string) string {
	kv := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		fields := strings.SplitN(t, " ", 2)
		if len(fields) == 2 {
			kv[fields[0]] = strings.TrimSpace(fields[1])
		}
	}
	for k := range kv {
		if strings.EqualFold(k, key) {
			delete(kv, k)
		}
	}
	if value != "" {
		kv[key] = value
	}
	if len(kv) == 0 {
		return ""
	}
	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(header)
	for _, k := range keys {
		b.WriteString(k + sep + kv[k] + "\n")
	}
	return b.String()
}

func findBinary(h Host, names ...string) string {
	for _, n := range names {
		if p, err := h.LookPath(n); err == nil {
			return p
		}
	}
	return ""
}

func exists(h Host, p string) bool {
	_, err := h.Stat(p)
	return err == nil
}

func isLink(h Host, p string) bool {
	if lh, ok := h.(interface {
		Lstat(string) (os.FileInfo, error)
	}); ok {
		_, err := lh.Lstat(p)
		return err == nil
	}
	return false
}

func (osHost) Lstat(p string) (os.FileInfo, error) { return os.Lstat(p) }

func readOptional(h Host, p string) (string, bool) {
	b, err := h.ReadFile(p)
	if err != nil {
		return "", false
	}
	return string(b), true
}

func writeOrRemove(h Host, p, content string, mode os.FileMode) error {
	if content == "" {
		if err := h.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	return h.WriteFile(p, []byte(content), mode)
}

func restoreFile(h Host, p, old string, hadOld bool, mode os.FileMode) {
	if hadOld {
		h.WriteFile(p, []byte(old), mode)
		return
	}
	h.Remove(p)
}
