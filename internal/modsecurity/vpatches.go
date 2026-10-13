package modsecurity

import (
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// Virtual patches: narrow ModSecurity rules for actively exploited CVEs,
// applied on request from the dashboard into infrafence-dynamic.conf. The
// catalog is embedded so the rule text only ever comes from the agent; the
// dashboard sends rule ids and nothing else.

//go:embed vpatches.json
var vpatchesJSON []byte

// VirtualPatch is one catalog entry. Rule is SecRule text whose ids are in
// 9920000-9929999.
type VirtualPatch struct {
	RuleID     string   `json:"rule_id"`
	CVE        string   `json:"cve"`
	Title      string   `json:"title"`
	Webservers []string `json:"webservers"`
	Rule       string   `json:"rule"`
}

// Our patches live between these markers in infrafence-dynamic.conf;
// anything else in the file is left exactly as it is.
const (
	vpatchMarker = "# vpatch "
	blockBegin   = "# BEGIN InfraFence virtual patches"
	blockEnd     = "# END InfraFence virtual patches"
)

// probeRule is rendered with the patches: it denies only requests carrying
// the probe header, so a local request tells whether ModSecurity enforces
// the file (rule engine On, file included). nolog/noauditlog: the probe
// leaves no trace in the logs the agent watches.
const (
	probeHeader = "X-InfraFence-Probe"
	probeValue  = "vpatch-check"
	probeRule   = `SecRule REQUEST_HEADERS:` + probeHeader + ` "@streq ` + probeValue + `" "id:9929999,phase:1,deny,status:403,nolog,noauditlog,msg:'InfraFence virtual patch probe'"`
)

var (
	catalogOnce sync.Once
	catalog     []VirtualPatch
	catalogErr  error
)

// VirtualPatches returns the embedded catalog.
func VirtualPatches() ([]VirtualPatch, error) {
	catalogOnce.Do(func() {
		catalogErr = json.Unmarshal(vpatchesJSON, &catalog)
	})
	return catalog, catalogErr
}

// LookupVirtualPatch finds a catalog entry by its rule id.
func LookupVirtualPatch(ruleID string) (VirtualPatch, bool) {
	all, err := VirtualPatches()
	if err != nil {
		return VirtualPatch{}, false
	}
	for _, p := range all {
		if p.RuleID == ruleID {
			return p, true
		}
	}
	return VirtualPatch{}, false
}

// Supports reports whether the patch can be applied on this web server.
func (p VirtualPatch) Supports(webserver string) bool {
	return slices.Contains(p.Webservers, webserver)
}

// ErrNotActive: our rules are not included by Apache (ModSecurity missing,
// web server changes off, or setup failed), so a patch would not take effect.
var ErrNotActive = errors.New("InfraFence ModSecurity rules are not active on this server")

// AppliedVirtualPatches lists the rule ids present in infrafence-dynamic.conf.
func (e *Engine) AppliedVirtualPatches() []string {
	content, err := os.ReadFile(filepath.Join(e.modsecDir, dynamicRules))
	if err != nil {
		return nil
	}
	return parseAppliedPatches(string(content))
}

// parseAppliedPatches reads the rule ids inside our block only.
func parseAppliedPatches(content string) []string {
	var ids []string
	in := false
	for _, line := range strings.Split(content, "\n") {
		switch strings.TrimSpace(line) {
		case blockBegin:
			in = true
			continue
		case blockEnd:
			in = false
			continue
		}
		if !in {
			continue
		}
		if id, ok := strings.CutPrefix(line, vpatchMarker); ok {
			ids = append(ids, strings.TrimSpace(id))
		}
	}
	return ids
}

// renderVirtualPatches returns our block for these rule ids: catalog
// entries only (unknown ids are dropped), sorted, each preceded by its
// marker line so the applied set can be read back after a restart, plus the
// probe rule. No patches renders no block.
func renderVirtualPatches(ruleIDs []string) string {
	ids := slices.Clone(ruleIDs)
	sort.Strings(ids)
	ids = slices.Compact(ids)
	var b strings.Builder
	for _, id := range ids {
		p, ok := LookupVirtualPatch(id)
		if !ok {
			continue
		}
		fmt.Fprintf(&b, "%s%s\n# %s: %s\n%s\n", vpatchMarker, p.RuleID, p.CVE, p.Title, strings.TrimRight(p.Rule, "\n"))
	}
	if b.Len() == 0 {
		return ""
	}
	return blockBegin + "\n" + b.String() + probeRule + "\n" + blockEnd + "\n"
}

// mergeBlock replaces our block in content with block (appending it when
// there is none, removing it when block is empty) and keeps every other
// byte of content.
func mergeBlock(content, block string) string {
	start := strings.Index(content, blockBegin+"\n")
	if start < 0 {
		if block == "" {
			return content
		}
		if content != "" && !strings.HasSuffix(content, "\n") {
			content += "\n"
		}
		return content + block
	}
	end := strings.Index(content[start:], blockEnd)
	if end < 0 {
		// A begin marker without its end: everything after it is ours.
		return content[:start] + block
	}
	end += start + len(blockEnd)
	if end < len(content) && content[end] == '\n' {
		end++
	}
	return content[:start] + block + content[end:]
}

// SetVirtualPatches makes infrafence-dynamic.conf hold exactly these patches:
// write, config test (the old file is put back if it fails), graceful
// reload. The returned undo puts the previous file back the same way, for a
// rollback after a failed verification. changed is false when there was
// nothing to do (undo is then nil). Adding a patch needs Setup to have
// succeeded in this process; removing one only needs ModSecurity, so a rule
// that gets in the way can always be taken out.
func (e *Engine) SetVirtualPatches(ruleIDs []string) (undo func() error, changed bool, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.available || e.apachectl == "" {
		return nil, false, ErrNotActive
	}

	path := filepath.Join(e.modsecDir, dynamicRules)
	old, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, false, err
	}
	if !e.setUp {
		current := parseAppliedPatches(string(old))
		for _, id := range ruleIDs {
			if !slices.Contains(current, id) {
				return nil, false, ErrNotActive
			}
		}
		if err != nil {
			return nil, false, ErrNotActive
		}
	}
	content := mergeBlock(string(old), renderVirtualPatches(ruleIDs))
	if string(old) == content {
		return nil, false, nil
	}
	if err := e.swapDynamicRules(path, []byte(content), old); err != nil {
		return nil, false, err
	}
	undo = func() error {
		e.mu.Lock()
		defer e.mu.Unlock()
		return e.swapDynamicRules(path, old, []byte(content))
	}
	return undo, true, nil
}

// swapDynamicRules writes content, tests the config and reloads gracefully.
// On a failed test or reload, prev is written back (and reloaded when the
// reload was what failed), so Apache never keeps a file it cannot parse.
// Writes go through a temp file and a rename: anything else reloading Apache
// meanwhile never reads a half-written file.
func (e *Engine) swapDynamicRules(path string, content, prev []byte) error {
	if err := writeAtomic(path, content); err != nil {
		return err
	}
	restore := func() error {
		if err := writeAtomic(path, prev); err != nil {
			return fmt.Errorf("restoring %s FAILED (%v), check it by hand", path, err)
		}
		return nil
	}
	if out, err := e.apachectlRun("configtest"); err != nil {
		if rerr := restore(); rerr != nil {
			return fmt.Errorf("config test failed and %v: %s", rerr, out)
		}
		return fmt.Errorf("config test failed, nothing changed: %s", out)
	}
	if out, err := e.apachectlRun("graceful"); err != nil {
		if rerr := restore(); rerr != nil {
			return fmt.Errorf("graceful reload failed and %v: %s", rerr, out)
		}
		_, _ = e.apachectlRun("graceful")
		return fmt.Errorf("graceful reload failed, previous rules restored: %s", out)
	}
	e.lastReload = time.Now()
	log.Printf("[modsec] virtual patches updated, Apache reloaded gracefully")
	return nil
}

func (e *Engine) apachectlRun(arg string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, e.apachectl, arg).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func writeAtomic(path string, content []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(content)
	if err == nil {
		err = tmp.Chmod(0644)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}

// IneffectiveMessage is the result message when ModSecurity would not
// enforce a patch.
const IneffectiveMessage = "ineffective: SecRuleEngine is not On"

// Replaced in tests.
var (
	// vpatchProbe requests the local home page, with or without the probe
	// header, and returns the status, -1 when nothing answered.
	vpatchProbe = probeLocal
	// probeWait bounds how long a graceful reload may take to reach the
	// workers: the probe is repeated until it is blocked or this passes.
	probeWait     = 10 * time.Second
	probeInterval = 500 * time.Millisecond
	dumpIncludes  = func(e *Engine) string { return e.dumpIncludes() }
)

// VirtualPatchesEnforced reports whether ModSecurity actually blocks with
// the rules in infrafence-dynamic.conf: the effective SecRuleEngine is not
// DetectionOnly or Off, and the probe header turns the local home page into
// a 403 (or, when that cannot be told - nothing answers locally, or the page
// is a 403 anyway - the engine reads On). It changes nothing: the rule
// engine is the owner's setting. msg says why when it returns false.
func (e *Engine) VirtualPatchesEnforced() (bool, string) {
	engine := effectiveRuleEngine(parseIncludes(dumpIncludes(e)))
	if engine == "off" || engine == "detectiononly" {
		return false, IneffectiveMessage
	}
	baseline, code := vpatchProbe(false), -1
	if baseline >= 0 && baseline != 403 {
		deadline := time.Now().Add(probeWait)
		for {
			code = vpatchProbe(true)
			if code == 403 || time.Now().After(deadline) {
				break
			}
			time.Sleep(probeInterval)
		}
	}
	switch {
	case code == 403:
		return true, ""
	case code >= 0:
		return false, IneffectiveMessage
	case engine == "on":
		return true, ""
	}
	return false, IneffectiveMessage + " (could not confirm it: no SecRuleEngine found and the local probe was inconclusive)"
}

// dumpIncludes lists the files Apache's configuration includes.
func (e *Engine) dumpIncludes() string {
	for _, bin := range []string{e.apachectl, "httpd", "apache2ctl"} {
		if bin == "" {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		out, err := exec.CommandContext(ctx, bin, "-t", "-D", "DUMP_INCLUDES").CombinedOutput()
		cancel()
		if err == nil && strings.Contains(string(out), "Included configuration files") {
			return string(out)
		}
	}
	return ""
}

// parseIncludes returns the files of `-t -D DUMP_INCLUDES` output, in the
// order Apache reads them ("  (*) /etc/apache2/apache2.conf",
// "    (146) /etc/apache2/mods-enabled/security2.conf").
func parseIncludes(out string) []string {
	var files []string
	for _, line := range strings.Split(out, "\n") {
		l := strings.TrimSpace(line)
		if !strings.HasPrefix(l, "(") {
			continue
		}
		if _, path, ok := strings.Cut(l, ") "); ok && filepath.IsAbs(strings.TrimSpace(path)) {
			files = append(files, strings.TrimSpace(path))
		}
	}
	return files
}

// effectiveRuleEngine returns the last SecRuleEngine value (lowercase: on,
// off, detectiononly) set in files, in order, or "" when none sets it.
func effectiveRuleEngine(files []string) string {
	engine := ""
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && strings.EqualFold(fields[0], "SecRuleEngine") {
				switch v := strings.ToLower(strings.Trim(fields[1], `"'`)); v {
				case "on", "off", "detectiononly":
					engine = v
				}
			}
		}
	}
	return engine
}

// probeLocal requests the home page from 127.0.0.1 over HTTP, then HTTPS,
// with or without the probe header; redirects are not followed.
func probeLocal(withHeader bool) int {
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			// Only the status matters, from this host's own server.
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
			Proxy:             nil,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	for _, u := range []string{"http://127.0.0.1/", "https://127.0.0.1/"} {
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		if withHeader {
			req.Header.Set(probeHeader, probeValue)
		}
		req.Header.Set("User-Agent", "InfraFence-verify")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	return -1
}
