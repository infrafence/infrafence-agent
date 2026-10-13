package main

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/modsecurity"
	"github.com/infrafence/infrafence-agent/internal/verify"
)

type fakeVPEngine struct {
	applied []string
	setErr  error
	sets    int
	undos   int
	// notEnforced is the message VirtualPatchesEnforced returns; "" = enforced.
	notEnforced string
}

func (f *fakeVPEngine) VirtualPatchesEnforced() (bool, string) {
	return f.notEnforced == "", f.notEnforced
}

func (f *fakeVPEngine) AppliedVirtualPatches() []string { return slices.Clone(f.applied) }

func (f *fakeVPEngine) SetVirtualPatches(ids []string) (func() error, bool, error) {
	if f.setErr != nil {
		return nil, false, f.setErr
	}
	old := slices.Clone(f.applied)
	next := slices.Clone(ids)
	slices.Sort(next)
	if slices.Equal(old, next) {
		return nil, false, nil
	}
	f.sets++
	f.applied = next
	return func() error { f.undos++; f.applied = old; return nil }, true, nil
}

func stubVerify(t *testing.T, ok bool, editsOK bool) {
	snap, check, edits := verifySnapshot, verifyCheck, vpatchEditsOK
	t.Cleanup(func() { verifySnapshot, verifyCheck, vpatchEditsOK = snap, check, edits })
	verifySnapshot = func(context.Context, []int, []string) verify.State { return verify.State{} }
	verifyCheck = func(context.Context, verify.State) verify.Result {
		if ok {
			return verify.Result{SSHOK: true, SitesOK: true, Details: "fine"}
		}
		return verify.Result{SSHOK: true, SitesOK: false, Details: "localhost answered 200 before, 503 now"}
	}
	vpatchEditsOK = func() (bool, string) {
		if editsOK {
			return true, ""
		}
		return false, "disabled in dashboard settings"
	}
}

func req(action string) api.VirtualPatchRequest {
	return api.VirtualPatchRequest{ID: 7, RuleID: "vp-cve-2021-41773", Action: action}
}

func TestVirtualPatchApplyAndRemove(t *testing.T) {
	stubVerify(t, true, true)
	eng := &fakeVPEngine{}
	typ, _, d := handleVirtualPatch(eng, "apache", false, req("apply"))
	if typ != "virtual_patch_done" || !slices.Equal(eng.applied, []string{"vp-cve-2021-41773"}) {
		t.Fatalf("apply: %s %v applied=%v", typ, d, eng.applied)
	}
	if !strings.Contains(d["verify"], `"ssh_ok":true`) || d["cve"] != "CVE-2021-41773" || d["patch_id"] != "7" {
		t.Errorf("details: %v", d)
	}
	if typ, _, d := handleVirtualPatch(eng, "apache", false, req("apply")); typ != "virtual_patch_done" || d["message"] != "already applied" || eng.sets != 1 {
		t.Errorf("re-apply: %s %v", typ, d)
	}
	// Removal works in monitor mode and with web server changes off.
	stubVerify(t, true, false)
	if typ, _, d := handleVirtualPatch(eng, "apache", true, req("remove")); typ != "virtual_patch_done" || len(eng.applied) != 0 {
		t.Errorf("remove: %s %v %v", typ, d, eng.applied)
	}
}

func TestVirtualPatchRollback(t *testing.T) {
	stubVerify(t, false, true)
	eng := &fakeVPEngine{applied: []string{"vp-cve-2024-4577"}}
	typ, _, d := handleVirtualPatch(eng, "apache", false, req("apply"))
	if typ != "virtual_patch_rolled_back" || d["reason"] != "verify_failed" || eng.undos != 1 {
		t.Fatalf("got %s %v undos=%d", typ, d, eng.undos)
	}
	if !slices.Equal(eng.applied, []string{"vp-cve-2024-4577"}) || !strings.Contains(d["verify"], `"sites_ok":false`) {
		t.Errorf("not rolled back: %v %v", eng.applied, d)
	}
}

func TestVirtualPatchRefusals(t *testing.T) {
	stubVerify(t, true, true)
	for name, c := range map[string]struct {
		eng     vpatchEngine
		ws      string
		monitor bool
		editsOK bool
		r       api.VirtualPatchRequest
		reason  string
	}{
		"nginx":          {&fakeVPEngine{}, "nginx", false, true, req("apply"), "unsupported_webserver"},
		"no modsecurity": {nil, "apache", false, true, req("apply"), "unsupported_webserver"},
		"litespeed":      {&fakeVPEngine{}, "litespeed", false, true, req("remove"), "unsupported_webserver"},
		"monitor mode":   {&fakeVPEngine{}, "apache", true, true, req("apply"), "monitor_mode"},
		"edits off":      {&fakeVPEngine{}, "apache", false, false, req("apply"), "webserver_changes_off"},
		"unknown rule":   {&fakeVPEngine{}, "apache", false, true, api.VirtualPatchRequest{ID: 1, RuleID: "vp-x", Action: "apply"}, "unknown_rule"},
		"bad action":     {&fakeVPEngine{}, "apache", false, true, api.VirtualPatchRequest{ID: 1, RuleID: "vp-cve-2021-41773", Action: "drop"}, "invalid_action"},
		"not active":     {&fakeVPEngine{setErr: modsecurity.ErrNotActive}, "apache", false, true, req("apply"), "modsecurity_not_active"},
		"configtest":     {&fakeVPEngine{setErr: errors.New("config test failed")}, "apache", false, true, req("apply"), "configtest_failed"},
	} {
		stubVerify(t, true, c.editsOK)
		typ, _, d := handleVirtualPatch(c.eng, c.ws, c.monitor, c.r)
		if typ != "virtual_patch_failed" || d["reason"] != c.reason {
			t.Errorf("%s: got %s %v", name, typ, d)
		}
		if f, ok := c.eng.(*fakeVPEngine); ok && f.sets != 0 {
			t.Errorf("%s: changed the rules", name)
		}
	}
}

func TestVirtualPatchIneffective(t *testing.T) {
	stubVerify(t, true, true)
	eng := &fakeVPEngine{applied: []string{"vp-cve-2024-4577"}, notEnforced: modsecurity.IneffectiveMessage}
	typ, _, d := handleVirtualPatch(eng, "apache", false, req("apply"))
	if typ != "virtual_patch_failed" || d["reason"] != "ineffective" || d["message"] != "ineffective: SecRuleEngine is not On" {
		t.Fatalf("got %s %v", typ, d)
	}
	if eng.undos != 1 || !slices.Equal(eng.applied, []string{"vp-cve-2024-4577"}) {
		t.Errorf("not rolled back: undos=%d applied=%v", eng.undos, eng.applied)
	}

	// A removal is never rolled back because the engine does not enforce.
	eng = &fakeVPEngine{applied: []string{"vp-cve-2021-41773"}, notEnforced: modsecurity.IneffectiveMessage}
	if typ, _, d := handleVirtualPatch(eng, "apache", false, req("remove")); typ != "virtual_patch_done" || len(eng.applied) != 0 || eng.undos != 0 {
		t.Errorf("remove: %s %v applied=%v", typ, d, eng.applied)
	}

	// Already in the file but not enforced: not reported done, left as it is.
	eng = &fakeVPEngine{applied: []string{"vp-cve-2021-41773"}, notEnforced: modsecurity.IneffectiveMessage}
	if typ, _, d := handleVirtualPatch(eng, "apache", false, req("apply")); typ != "virtual_patch_failed" || d["reason"] != "ineffective" || eng.sets != 0 {
		t.Errorf("already applied: %s %v", typ, d)
	}
}
