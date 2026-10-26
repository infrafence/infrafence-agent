package phpconf

import (
	"crypto/sha256"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Risk is a dangerous value in effect for a runtime or pool.
type Risk struct {
	Runtime   string
	Pool      string
	File      string
	Line      int
	Directive string
	Value     string
	Severity  string // critical or warning
}

// CheckID is the hardening check that reports this value
// (PHP_ALLOW_URL_INCLUDE@<runtime>[/<pool>], PHP_DISPLAY_ERRORS@site:<site>...):
// the same subject in the dashboard. "" for another directive.
func (r Risk) CheckID() string {
	base := ""
	switch strings.ToLower(r.Directive) {
	case "allow_url_include":
		base = CheckAllowURLInclude
	case "display_errors":
		base = CheckDisplayErrors
	default:
		return ""
	}
	return ID(base, r.Runtime, r.Pool)
}

func (r Risk) key() string {
	return r.Runtime + "\x00" + r.Pool + "\x00" + r.Directive + "\x00" + r.Value + "\x00" + r.File + "\x00" + strconv.Itoa(r.Line)
}

// Risks lists the dangerous values in effect: allow_url_include on
// (critical) and display_errors on for a web runtime (warning).
func Risks(h Host) []Risk {
	var out []Risk
	for _, t := range targets(h) {
		pool := ""
		if t.pool != nil {
			pool = t.pool.Name
		}
		if d := t.get("allow_url_include"); IsOn(d.Value) {
			out = append(out, Risk{t.rt.ID, pool, d.File, d.Line, d.Key, d.Value, "critical"})
		}
		if d := t.get("display_errors"); displaysErrors(d.Value) {
			file := d.File
			if d.Default {
				file = t.rt.Ini
			}
			out = append(out, Risk{t.rt.ID, pool, file, d.Line, d.Key, d.Value, "warning"})
		}
	}
	for _, s := range h.Sites {
		if d := lookup(s.Settings, "display_errors"); !d.Default && displaysErrors(d.Value) {
			out = append(out, Risk{"site:" + s.Site, "", d.File, d.Line, d.Key, d.Value, "warning"})
		}
	}
	return out
}

// Watcher polls the PHP configuration files (php.ini, scan directories,
// php-fpm.conf, pools, the panels' per-site files). The agent does not
// depend on an inotify library, so it compares their contents every
// interval. When a dangerous value appears it calls OnRisk once for that
// value and place; after any change it calls OnChange, debounced.
type Watcher struct {
	Env      Env
	Interval time.Duration // 60 s by default
	Debounce time.Duration // 15 s by default
	OnRisk   func(Risk)
	OnChange func(Host)

	mu     sync.Mutex
	sums   map[string][32]byte
	risks  map[string]bool
	timer  *time.Timer
	stopCh chan struct{}
}

// Start takes the baseline (existing values are the hardening check's to
// report, not events) and starts polling.
func (w *Watcher) Start() {
	if w.Interval == 0 {
		w.Interval = 60 * time.Second
	}
	if w.Debounce == 0 {
		w.Debounce = 15 * time.Second
	}
	w.mu.Lock()
	w.stopCh = make(chan struct{})
	stop := w.stopCh
	w.mu.Unlock()
	w.Poll()
	go func() {
		t := time.NewTicker(w.Interval)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				w.Poll()
			}
		}
	}()
}

// Stop stops polling.
func (w *Watcher) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopCh != nil {
		close(w.stopCh)
		w.stopCh = nil
	}
	if w.timer != nil {
		w.timer.Stop()
	}
}

// Poll checks once; the first call only records the baseline. It reports
// whether anything changed.
func (w *Watcher) Poll() bool {
	env := w.Env
	if env == nil {
		env = System
	}
	h := Discover(env)
	sums := map[string][32]byte{}
	for _, f := range h.Files() {
		if c, ok := readSmall(env, f); ok {
			sums[f] = sha256.Sum256([]byte(c))
		}
	}
	risks := map[string]bool{}
	var current []Risk
	for _, r := range Risks(h) {
		if !risks[r.key()] {
			risks[r.key()] = true
			current = append(current, r)
		}
	}

	w.mu.Lock()
	first := w.sums == nil
	changed := !first && !sameSums(w.sums, sums)
	var fresh []Risk
	if changed {
		for _, r := range current {
			if !w.risks[r.key()] {
				fresh = append(fresh, r)
			}
		}
	}
	w.sums, w.risks = sums, risks
	if changed && w.OnChange != nil {
		if w.timer != nil {
			w.timer.Stop()
		}
		w.timer = time.AfterFunc(w.Debounce, func() { w.OnChange(Discover(env)) })
	}
	w.mu.Unlock()

	sort.Slice(fresh, func(i, j int) bool { return fresh[i].key() < fresh[j].key() })
	if w.OnRisk != nil {
		for _, r := range fresh {
			w.OnRisk(r)
		}
	}
	return changed
}

func sameSums(a, b map[string][32]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
