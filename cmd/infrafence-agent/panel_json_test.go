package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/malware"
	"github.com/infrafence/infrafence-agent/internal/panel"
	"github.com/infrafence/infrafence-agent/internal/preflight"
)

// The reference examples of docs/panel-json.md and testdata/panel/*.json:
// a real panel socket served by handlePanel over a known agent state, and
// the CLI run as its own process (this test binary re-executed, entering
// cmdPanel exactly as main does) for every command. "go test -run
// TestPanelJSONReference -update-panel-json" rewrites them; without the
// flag the test fails when the code no longer prints what they show, or
// when the doc misses a field.

var updatePanelJSON = flag.Bool("update-panel-json", false, "rewrite testdata/panel and the examples in docs/panel-json.md")

const panelChildEnv = "INFRAFENCE_PANEL_JSON_CHILD"

func TestMain(m *testing.M) {
	// The CLI side of TestPanelJSONReference.
	if sock := os.Getenv(panelChildEnv); sock != "" {
		panelSocketPath = sock
		panelEuid = func() int { return 0 }
		cmdPanel(os.Args[1:])
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// panelEnv is a host for the read-only detection (preflight.Env).
type panelEnv struct {
	files map[string]string
	runs  map[string]string
}

func (e panelEnv) Run(name string, args ...string) (string, error) {
	if out, ok := e.runs[strings.TrimSpace(name+" "+strings.Join(args, " "))]; ok {
		return out, nil
	}
	return "", errors.New("exit 1")
}
func (e panelEnv) LookPath(n string) bool { return n == "systemctl" }
func (e panelEnv) ReadFile(p string) (string, error) {
	if s, ok := e.files[p]; ok {
		return s, nil
	}
	return "", os.ErrNotExist
}
func (e panelEnv) Exists(p string) bool { _, ok := e.files[p]; return ok }
func (e panelEnv) Glob(pat string) []string {
	var out []string
	for p := range e.files {
		if ok, _ := filepath.Match(pat, p); ok {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}
func (e panelEnv) IsRoot() bool { return true }

// seedPanelReference sets up a cPanel server as the agent sees it after a
// sync: bans of every source, allow lists, events, findings, sites. Paths
// live under base.
func seedPanelReference(t *testing.T, f *fakePanelHost, base string) {
	f.now = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) string { return f.now.Add(d).Format(time.RFC3339) }
	panelLastHeartbeat.Store(f.now.Add(-40 * time.Second).Unix())
	panelSystemDirs = []string{"/etc", "/proc"} // base is under /tmp on Linux

	alice := filepath.Join(base, "home/alice/public_html")
	bob := filepath.Join(base, "home/bob/public_html")
	for _, d := range []string{alice, alice + "/blog", bob} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	env := panelEnv{files: map[string]string{
		"/usr/local/cpanel":                                "",
		"/usr/bin/systemctl":                               "",
		"/etc/csf/csf.conf":                                "TESTING = \"0\"\n",
		"/etc/csf/version.txt":                             "14.20\n",
		"/usr/sbin/lfd":                                    "",
		"/var/cpanel/hulkd":                                "",
		"/var/cpanel/hulkd/enabled":                        "",
		"/usr/bin/imunify360-agent":                        "",
		"/etc/apache2/conf.d/modsec2.conf":                 "",
		"/etc/apache2/conf.d/modsec_vendor_configs/OWASP3": "",
		"/etc/apache2/conf.d/modsec_vendor_configs/imunify360-full-apache": "",
		"/var/cpanel/users/alice":                       "",
		"/var/cpanel/users/bob":                         "",
		"/var/cpanel/userdata/alice/main":               "main_domain: alice.example\nparked_domains:\n  - alice.example.net\nsub_domains:\n  - blog.alice.example\n",
		"/var/cpanel/userdata/alice/alice.example":      "documentroot: " + alice + "\n",
		"/var/cpanel/userdata/alice/blog.alice.example": "documentroot: " + alice + "/blog\n",
		"/var/cpanel/userdata/bob/main":                 "main_domain: bob.example\n",
		"/var/cpanel/userdata/bob/bob.example":          "documentroot: " + bob + "\n",
	}, runs: map[string]string{
		"/usr/bin/systemctl is-active csf":        "active",
		"/usr/bin/systemctl is-active lfd":        "active",
		"/usr/bin/systemctl is-active imunify360": "active",
	}}
	panelCoexistence = func() preflight.Coexistence { return preflight.DetectCoexistenceEnv(env) }
	panelDetectSites = func(id string) []preflight.Site { return preflight.DetectSitesEnv(env, id) }
	f.roots = []malware.WebRoot{{Path: filepath.Join(base, "home/alice")}}
	f.homes["alice"], f.homes["bob"] = filepath.Join(base, "home/alice"), filepath.Join(base, "home/bob")

	f.banned["203.0.113.7"] = true
	panelNoteLocalBan("203.0.113.7", "SSH brute force (8 failed logins in 60s)")
	scanOn := true
	panelNoteSync(&api.SyncResponse{
		Config: api.SyncConfig{Plan: "pro", MalwareScanConfig: &api.MalwareScanConfig{Enabled: scanOn, IntervalHours: 24, Intensity: "medium"}},
		Bans: []api.Ban{
			{ID: 101, IPAddress: "203.0.113.7", ExpiresAt: strp(at(24 * time.Hour))},
			{ID: 0, IPAddress: "192.0.2.50", ExpiresAt: strp(at(36 * time.Hour))},
			{ID: 102, IPAddress: "198.51.100.9"},
			{ID: 103, IPAddress: "198.51.100.23", Source: "automode", Reason: "Under attack: HTTP flood", CreatedAt: at(-2 * time.Hour), ExpiresAt: strp(at(4 * time.Hour))},
		},
		Whitelists: []api.WhitelistEntry{{ID: 1, IPAddress: strp("203.0.113.20")}, {ID: 2, IPRange: strp("10.0.0.0/8")}},
	})
	panelState.Lock()
	panelState.p.Allowed = []panelAllowEntry{{IP: "198.51.100.4", Note: "Office VPN", Actor: "root", AddedAt: f.now.Add(-48 * time.Hour).Unix()}}
	panelState.Unlock()

	panelNoteEvent(api.EventRequest{Type: "ssh_brute_force", Severity: "warning", SourceIP: "203.0.113.7", OccurredAt: at(-3 * time.Hour), Details: map[string]string{"source": "watcher"}})
	panelNoteEvent(api.EventRequest{Type: "sql_injection", Severity: "critical", SourceIP: "198.51.100.23", OccurredAt: at(-2 * time.Hour), Details: map[string]string{"source": "modsecurity"}})
	panelNoteEvent(api.EventRequest{Type: "integrity_change", Severity: "warning", OccurredAt: at(-90 * time.Minute), Details: map[string]string{"file": "/etc/passwd"}})
	panelNoteEvent(api.EventRequest{Type: "malware_realtime", Severity: "critical", OccurredAt: at(-time.Hour),
		Details: map[string]string{"file_path": alice + "/wp-content/uploads/x.php", "name": "PHP webshell (generic)"}})
	panelNoteEvent(api.EventRequest{Type: "quarantine_completed", Severity: "info", OccurredAt: at(-50 * time.Minute),
		Details: map[string]string{"file": alice + "/wp-content/uploads/x.php"}})
	panelNow = func() time.Time { return f.now.Add(-30 * time.Minute) }
	panelNoteScanFindings([]malware.Finding{{FilePath: bob + "/wp-includes/class-wp-cache.php", Name: "Obfuscated eval", Severity: "high"}})
	panelNow = func() time.Time { return f.now }
}

// panelRef is one reference run: the file name and the CLI arguments.
type panelRef struct {
	name string
	args []string
}

var panelRefs = []panelRef{
	{"status", []string{"status", "--json"}},
	{"bans", []string{"bans", "--limit", "50", "--json"}},
	{"allowlist", []string{"allowlist", "--json"}},
	{"findings", []string{"findings", "--limit", "50", "--json"}},
	{"events", []string{"events", "--limit", "50", "--since", "2026-10-16T08:00:00Z", "--json"}},
	{"coexistence", []string{"coexistence", "--json"}},
	{"sites", []string{"sites", "--json"}},
	{"unban", []string{"unban", "198.51.100.9", "--actor", "root", "--json"}},
	{"allow", []string{"allow", "198.51.100.77", "--note", "Office VPN 2", "--actor", "root", "--json"}},
	{"disallow", []string{"disallow", "198.51.100.4", "--actor", "root", "--json"}},
	{"scan", []string{"scan", "{base}/home/alice/public_html", "--actor", "root", "--json"}},
	{"error", []string{"unban", "203.0.113.99", "--actor", "root", "--json"}},
	{"error_invalid_ip", []string{"unban", "203.0.113.0/24", "--actor", "root", "--json"}},
	{"map", []string{"map", "--hours", "24", "--json"}},
	{"map_stale", []string{"map", "--hours", "24", "--json"}},
	{"score", []string{"score", "--json"}},
	{"error_not_connected", []string{"map", "--hours", "168", "--json"}},
}

// refDashboardDown: the dashboard stops answering the map from map_stale
// on. The fakes are installed before the socket serves (no race with it).
var refDashboardDown atomic.Bool

func installRefDashboard() {
	refDashboardDown.Store(false)
	panelFetchMap = func(_ context.Context, hours int) (*api.AttackMap, error) {
		if refDashboardDown.Load() {
			return nil, errors.New("connection refused")
		}
		m := &api.AttackMap{Hours: hours, GeneratedAt: "2026-10-16T11:58:00Z",
			Countries:  []api.MapCountry{{Code: "CN", Attacks: 40}, {Code: "US", Attacks: 12}, {Code: "BR", Attacks: 3}},
			Categories: []api.MapCategory{{Cat: "ssh", Attacks: 30}, {Cat: "web", Attacks: 21}, {Cat: "scans", Attacks: 6}}}
		m.Total.Attacks = 57 // 2 from an unknown country
		return m, nil
	}
	panelFetchScore = func(context.Context) (*api.SecurityScore, error) {
		return &api.SecurityScore{GeneratedAt: "2026-10-16T11:58:00Z", Score: 72, Grade: "C",
			Items: []api.ScoreItem{
				{Key: "exposed_ports", Points: 16, Detail: map[string]any{"ports": []any{3306.0, 6379.0}}},
				{Key: "hardening", Points: 12, Detail: map[string]any{"failed": 22.0, "total": 43.0}}},
			Trend: []api.ScorePoint{{Day: "2026-10-14", Score: 65}, {Day: "2026-10-15", Score: 70}, {Day: "2026-10-16", Score: 72}}}, nil
	}
}

// panelRefSetups prepare the dashboard's side of a reference run.
var panelRefSetups = map[string]func(f *fakePanelHost){
	// The dashboard stops answering; the last request was 5 minutes ago.
	"map_stale": func(f *fakePanelHost) {
		refDashboardDown.Store(true)
		panelInfoCache.Lock()
		panelInfoCache.entries["map:24"].tried = f.now.Add(-panelMapEvery)
		panelInfoCache.Unlock()
	},
}

// Without a running agent (the socket does not exist).
var panelOfflineRefs = []panelRef{
	{"status_agent_not_running", []string{"status", "--json"}},
	{"error_agent_not_running", []string{"bans", "--json"}},
}

func runPanelChild(t *testing.T, sock string, args []string) (string, int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), panelChildEnv+"="+sock)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return out.String(), code
}

func TestPanelJSONReference(t *testing.T) {
	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		t.Skip("the panel socket serves root only")
	}
	f := withFakePanel(t)
	sockDir, err := os.MkdirTemp("/tmp", "ifj")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sockDir)
	base := filepath.Join(sockDir, "srv")
	seedPanelReference(t, f, base)
	resolved, _ := filepath.EvalSymlinks(sockDir)
	// Paths are shown as on the server: the test's directory prefix goes.
	strip := func(s string) string {
		return strings.ReplaceAll(strings.ReplaceAll(s, filepath.Join(resolved, "srv"), ""), base, "")
	}

	sock := filepath.Join(sockDir, "panel.sock")
	srv, err := panel.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	installRefDashboard()
	go srv.Serve(handlePanel)

	got := map[string]string{}
	for _, r := range panelRefs {
		if setup := panelRefSetups[r.name]; setup != nil {
			setup(f)
		}
		args := make([]string, len(r.args))
		for i, a := range r.args {
			args[i] = strings.ReplaceAll(a, "{base}", base)
		}
		out, code := runPanelChild(t, sock, args)
		var resp panel.Response
		if err := json.Unmarshal([]byte(out), &resp); err != nil {
			t.Fatalf("%s: not one JSON object: %q", r.name, out)
		}
		if wantOK := !strings.HasPrefix(r.name, "error"); resp.Succeeded() != wantOK || (code == 0) != wantOK {
			t.Fatalf("%s: exit %d, %s", r.name, code, out)
		}
		got[r.name] = strip(out)
	}
	srv.Close()

	// Offline: the config file gives the agent id (never the token).
	cfg := filepath.Join(sockDir, "config.json")
	os.WriteFile(cfg, []byte(`{"server_url":"https://app.infrafence.com","agent_token":"not-printed","agent_id":42}`), 0o600)
	t.Setenv("INFRAFENCE_CONFIG", cfg)
	for _, r := range panelOfflineRefs {
		out, _ := runPanelChild(t, sock, r.args)
		if strings.Contains(out, "not-printed") {
			t.Fatalf("token printed: %s", out)
		}
		got[r.name] = out
	}

	root := filepath.Join("..", "..")
	docPath := filepath.Join(root, "docs", "panel-json.md")
	doc, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatal(err)
	}
	newDoc := string(doc)
	for name, out := range got {
		file := filepath.Join(root, "testdata", "panel", name+".json")
		if *updatePanelJSON {
			if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(file, []byte(out), 0o644); err != nil {
				t.Fatal(err)
			}
		} else if old, err := os.ReadFile(file); err != nil || string(old) != out {
			t.Errorf("testdata/panel/%s.json differs from what the CLI prints now (run with -update-panel-json):\n%s", name, out)
		}
		var pretty bytes.Buffer
		json.Indent(&pretty, []byte(out), "", "  ")
		block, err := replaceExample(newDoc, name, pretty.String())
		if err != nil {
			t.Fatal(err)
		}
		newDoc = block
		if err := checkFieldsDocumented(newDoc, name, out); err != nil {
			t.Error(err)
		}
	}
	if *updatePanelJSON {
		if err := os.WriteFile(docPath, []byte(newDoc), 0o644); err != nil {
			t.Fatal(err)
		}
	} else if newDoc != string(doc) {
		t.Error("the examples in docs/panel-json.md differ from what the CLI prints now (run with -update-panel-json)")
	}
}

// replaceExample puts body between <!-- example:NAME --> and
// <!-- /example:NAME --> as a json code block.
func replaceExample(doc, name, body string) (string, error) {
	start, end := "<!-- example:"+name+" -->", "<!-- /example:"+name+" -->"
	i, j := strings.Index(doc, start), strings.Index(doc, end)
	if i < 0 || j < i {
		return "", fmt.Errorf("docs/panel-json.md has no %s ... %s", start, end)
	}
	return doc[:i+len(start)] + "\n```json\n" + strings.TrimRight(body, "\n") + "\n```\n" + doc[j:], nil
}

// A field row: | `path` | type | values | always present (yes/no) | ...
// Cells may contain an escaped pipe ("string \\| null").
var fieldRow = regexp.MustCompile("(?m)^\\| `([^`]+)` \\|(?:[^|\\\\]|\\\\.)*\\|(?:[^|\\\\]|\\\\.)*\\| *(yes|no)\\b")

// checkFieldsDocumented: every field of the example is a row of a field
// table in the same section (up to the next heading).
func checkFieldsDocumented(doc, name, out string) error {
	i := strings.Index(doc, "<!-- /example:"+name+" -->")
	section := doc[i:]
	if k := strings.Index(section, "\n## "); k >= 0 {
		section = section[:k]
	}
	if k := strings.Index(section, "\n### "); k >= 0 {
		section = section[:k]
	}
	documented := map[string]bool{} // path -> always present
	for _, m := range fieldRow.FindAllStringSubmatch(section, -1) {
		documented[m[1]] = m[2] == "yes"
	}
	var v any
	json.Unmarshal([]byte(out), &v)
	problems := map[string]string{}
	var walk func(prefix string, v any)
	walk = func(prefix string, v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, c := range x {
				p := k
				if prefix != "" {
					p = prefix + "." + k
				}
				if _, ok := documented[p]; !ok {
					problems[p] = "no table row"
				}
				walk(p, c)
			}
			// Fields documented as always present are in every object.
			for p, always := range documented {
				parent, key := "", p
				if i := strings.LastIndex(p, "."); i >= 0 {
					parent, key = p[:i], p[i+1:]
				}
				if _, ok := x[key]; always && parent == prefix && !ok {
					problems[p] = "documented as always present, missing"
				}
			}
		case []any:
			for _, c := range x {
				walk(prefix+"[]", c)
			}
		}
	}
	walk("", v)
	if len(problems) > 0 {
		return fmt.Errorf("docs/panel-json.md, %s: %v", name, problems)
	}
	return nil
}
