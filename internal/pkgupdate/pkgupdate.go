// Package pkgupdate installs the security updates an admin asks for from the
// dashboard: the packages with a known vulnerability that has a fix.
//
// Written for production servers:
//   - only packages already installed are touched, and only upgraded
//     (apt-get --only-upgrade / dnf upgrade <names>): nothing new is
//     installed, nothing is removed;
//   - existing configuration files are kept (dpkg --force-confold);
//   - it refuses to start while another package operation is running;
//   - the server is never rebooted and InfraFence restarts no service itself
//     (needrestart in list mode): the result says which services and whether
//     the kernel need a restart. A package's own upgrade script may still
//     restart its service (e.g. nginx, openssh) — the dashboard says so
//     before asking for confirmation.
package pkgupdate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Host is what an update needs from the system; tests replace it.
type Host interface {
	Run(timeout time.Duration, env []string, name string, args ...string) (string, error)
	LookPath(name string) bool
	Exists(path string) bool
	// Busy lists package operations running right now.
	Busy() []string
}

type osHost struct{ busy func() []string }

func (h osHost) Run(timeout time.Duration, env []string, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return string(out), fmt.Errorf("%s timed out after %s", name, timeout)
	}
	return string(out), err
}
func (osHost) LookPath(name string) bool { _, err := exec.LookPath(name); return err == nil }
func (osHost) Exists(p string) bool      { _, err := os.Stat(p); return err == nil }
func (h osHost) Busy() []string          { return h.busy() }

// NewHost returns the real host; busy reports running package operations.
func NewHost(busy func() []string) Host { return osHost{busy: busy} }

// Result of an update.
type Result struct {
	Manager           string   // apt, dnf or yum
	Upgraded          []string // "name old → new"
	Unchanged         []string // requested, already at the newest version available
	ServicesToRestart []string
	RebootRequired    bool
	Output            string // last lines of the package manager's output
}

var (
	// ErrBusy: another package operation is running.
	ErrBusy = errors.New("another package operation is running")
	// ErrNothing: none of the requested packages is installed.
	ErrNothing = errors.New("none of the requested packages is installed")
	// ErrUnsupported: no apt, dnf or yum.
	ErrUnsupported = errors.New("no supported package manager (apt, dnf, yum)")

	nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9+._-]{0,127}$`)
	srpmRe = regexp.MustCompile(`^(.+)-[^-]+-[^-]+\.src\.rpm$`)
)

const (
	refreshTimeout = 10 * time.Minute
	upgradeTimeout = 30 * time.Minute
	queryTimeout   = 2 * time.Minute
	outputTail     = 8000
)

var aptEnv = []string{
	"DEBIAN_FRONTEND=noninteractive",
	"APT_LISTCHANGES_FRONTEND=none",
	"NEEDRESTART_MODE=l", // list services needing a restart, never restart them
}

// ValidNames keeps the names that are valid package names (the dashboard
// sends source package names from the vulnerability report).
func ValidNames(names []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, n := range names {
		n = strings.TrimSpace(strings.ToLower(n))
		if nameRe.MatchString(n) && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

func manager(h Host) string {
	switch {
	case h.LookPath("apt-get") && h.LookPath("dpkg-query"):
		return "apt"
	case h.LookPath("dnf"):
		return "dnf"
	case h.LookPath("yum"):
		return "yum"
	}
	return ""
}

// installed maps each installed binary package to its source package and
// version.
type pkg struct{ source, version string }

func installed(h Host, mgr string) (map[string]pkg, error) {
	out := map[string]pkg{}
	if mgr == "apt" {
		o, err := h.Run(queryTimeout, nil, "dpkg-query", "-W",
			"-f=${db:Status-Abbrev}\t${Package}\t${source:Package}\t${Version}\n")
		if err != nil {
			return nil, fmt.Errorf("dpkg-query: %w", err)
		}
		for _, line := range strings.Split(o, "\n") {
			f := strings.Split(line, "\t")
			if len(f) != 4 || strings.TrimSpace(f[0]) != "ii" {
				continue
			}
			src := f[2]
			if src == "" {
				src = f[1]
			}
			out[f[1]] = pkg{source: src, version: f[3]}
		}
		return out, nil
	}
	o, err := h.Run(queryTimeout, nil, "rpm", "-qa", "--queryformat",
		"%{NAME}\t%{SOURCERPM}\t%|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}\n")
	if err != nil {
		return nil, fmt.Errorf("rpm -qa: %w", err)
	}
	for _, line := range strings.Split(o, "\n") {
		f := strings.Split(strings.TrimSpace(line), "\t")
		if len(f) != 3 || f[0] == "gpg-pubkey" {
			continue
		}
		src := f[0]
		if m := srpmRe.FindStringSubmatch(f[1]); m != nil {
			src = m[1]
		}
		out[f[0]] = pkg{source: src, version: f[2]}
	}
	return out, nil
}

// Update upgrades every installed package built from the given source
// packages (or with those names).
func Update(h Host, sources []string) (Result, error) {
	res := Result{}
	sources = ValidNames(sources)
	if len(sources) == 0 {
		return res, ErrNothing
	}
	mgr := manager(h)
	if mgr == "" {
		return res, ErrUnsupported
	}
	res.Manager = mgr
	if busy := h.Busy(); len(busy) > 0 {
		return res, fmt.Errorf("%w (%s); try again when it has finished", ErrBusy, strings.Join(busy, ", "))
	}

	before, err := installed(h, mgr)
	if err != nil {
		return res, err
	}
	want := map[string]bool{}
	for _, s := range sources {
		want[s] = true
	}
	var targets []string
	for name, p := range before {
		if want[p.source] || want[name] {
			targets = append(targets, name)
		}
	}
	sort.Strings(targets)
	if len(targets) == 0 {
		return res, ErrNothing
	}

	var out string
	switch mgr {
	case "apt":
		o, err := h.Run(refreshTimeout, aptEnv, "apt-get", "update", "-q")
		out += o
		if err != nil {
			res.Output = tail(out)
			return res, fmt.Errorf("apt-get update failed: %w", err)
		}
		args := append([]string{"install", "--only-upgrade", "-y", "-q",
			"-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"}, targets...)
		o, err = h.Run(upgradeTimeout, aptEnv, "apt-get", args...)
		out += o
		if err != nil {
			res.Output = tail(out)
			return res, fmt.Errorf("apt-get install failed: %w", err)
		}
	default:
		args := append([]string{"update", "-y"}, targets...) // yum
		if mgr == "dnf" {
			args = append([]string{"upgrade", "-y", "--refresh"}, targets...)
		}
		o, err := h.Run(upgradeTimeout, nil, mgr, args...)
		out += o
		if err != nil {
			res.Output = tail(out)
			return res, fmt.Errorf("%s upgrade failed: %w", mgr, err)
		}
	}
	res.Output = tail(out)

	after, err := installed(h, mgr)
	if err == nil {
		for _, name := range targets {
			b, a := before[name].version, after[name].version
			if a != "" && a != b {
				res.Upgraded = append(res.Upgraded, fmt.Sprintf("%s %s → %s", name, b, a))
			} else {
				res.Unchanged = append(res.Unchanged, name)
			}
		}
	}
	res.RebootRequired, res.ServicesToRestart = restartNeeds(h, mgr)
	return res, nil
}

// restartNeeds reports whether the server needs a reboot and which services
// still run old code, using the distribution's own tools when present.
func restartNeeds(h Host, mgr string) (bool, []string) {
	reboot := false
	var services []string
	if mgr == "apt" {
		reboot = h.Exists("/var/run/reboot-required")
		if h.LookPath("needrestart") {
			o, _ := h.Run(queryTimeout, aptEnv, "needrestart", "-b", "-r", "l")
			for _, line := range strings.Split(o, "\n") {
				if s, ok := strings.CutPrefix(line, "NEEDRESTART-SVC: "); ok {
					services = append(services, strings.TrimSpace(s))
				}
				if strings.HasPrefix(line, "NEEDRESTART-KSTA: ") && strings.TrimSpace(strings.TrimPrefix(line, "NEEDRESTART-KSTA: ")) != "1" {
					reboot = true
				}
			}
		}
		return reboot, services
	}
	if h.LookPath("needs-restarting") {
		if _, err := h.Run(queryTimeout, nil, "needs-restarting", "-r"); err != nil {
			reboot = true // exit status 1: reboot required
		}
		o, _ := h.Run(queryTimeout, nil, "needs-restarting", "-s")
		for _, line := range strings.Split(o, "\n") {
			if s := strings.TrimSpace(line); s != "" && !strings.Contains(s, " ") {
				services = append(services, s)
			}
		}
	}
	return reboot, services
}

func tail(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= outputTail {
		return s
	}
	return "…" + s[len(s)-outputTail:]
}
