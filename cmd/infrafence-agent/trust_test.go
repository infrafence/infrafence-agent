package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/trust"
)

const (
	trustTokA = "ifv_0123456789abcdef0123456789abcdef"
	trustTokB = "ifv_fedcba9876543210fedcba9876543210"
)

type trustHarness struct {
	base   string
	sites  []trust.Site
	events []string // "type domain detail"
}

func newTrustHarness(t *testing.T) *trustHarness {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := &trustHarness{base: base}
	savedPath, savedSites, savedReport := trustStatePath, trustSites, trustReport
	trustStatePath = filepath.Join(base, "state", "trust-state.json")
	trustSites = func() []trust.Site { return h.sites }
	trustReport = func(_ *api.Client, typ string, d map[string]string) {
		h.events = append(h.events, strings.TrimSpace(typ+" "+d["domain"]+" "+d["path"]+d["reason"]))
	}
	t.Cleanup(func() { trustStatePath, trustSites, trustReport = savedPath, savedSites, savedReport })
	return h
}

func (h *trustHarness) root(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join(h.base, name)
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func (h *trustHarness) take() []string {
	ev := h.events
	h.events = nil
	return ev
}

func tokens(pairs ...string) []api.TrustToken {
	var out []api.TrustToken
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, api.TrustToken{Domain: pairs[i], Token: pairs[i+1]})
	}
	return out
}

func readTrustFile(t *testing.T, root string) string {
	t.Helper()
	data, err := os.ReadFile(trust.Path(root))
	if err != nil {
		return ""
	}
	return string(data)
}

func TestTrustTokensPlaceRemoveAndReportOnce(t *testing.T) {
	h := newTrustHarness(t)
	ex := h.root(t, "example")
	shop := h.root(t, "shop")
	h.sites = []trust.Site{
		{Names: []string{"*.example.com"}, Root: h.root(t, "wild")},
		{Names: []string{"example.com", "www.example.com"}, Root: ex},
		{Names: []string{"www.shop.example.org"}, Root: shop},
	}

	applyTrustTokens(nil, tokens("example.com", trustTokA, "Shop.Example.org", trustTokB, "nosite.example.net", trustTokA))
	want := []string{
		"trust_token_placed example.com " + trust.Path(ex),
		"trust_token_failed nosite.example.net no_document_root",
		"trust_token_placed shop.example.org " + trust.Path(shop),
	}
	if got := h.take(); !reflect.DeepEqual(got, want) {
		t.Fatalf("events %q\nwant %q", got, want)
	}
	if got := readTrustFile(t, ex); got != trust.Header+"\n"+trustTokA+"\n" {
		t.Errorf("example file %q", got)
	}
	if got := readTrustFile(t, shop); got != trust.Header+"\n"+trustTokB+"\n" {
		t.Errorf("shop file (via www.) %q", got)
	}
	if entries, _ := os.ReadDir(filepath.Join(h.base, "wild")); len(entries) != 0 {
		t.Error("a wildcard server got the file")
	}

	// The same list again (every sync): nothing reported, nothing rewritten.
	before, _ := os.Stat(trust.Path(ex))
	for range 3 {
		applyTrustTokens(nil, tokens("example.com", trustTokA, "shop.example.org", trustTokB, "nosite.example.net", trustTokA))
	}
	if got := h.take(); len(got) != 0 {
		t.Errorf("repeated sync reported %q", got)
	}
	if after, _ := os.Stat(trust.Path(ex)); !os.SameFile(before, after) {
		t.Error("file rewritten on an unchanged sync")
	}

	// A second domain of the same document root: one line per token.
	applyTrustTokens(nil, tokens("example.com", trustTokA, "www.example.com", trustTokB, "shop.example.org", trustTokB))
	if got := readTrustFile(t, ex); got != trust.Header+"\n"+trustTokA+"\n"+trustTokB+"\n" {
		t.Errorf("two tokens: %q", got)
	}
	if got := h.take(); !reflect.DeepEqual(got, []string{"trust_token_placed www.example.com " + trust.Path(ex)}) {
		t.Errorf("events %q", got)
	}

	// example.com no longer listed: its line goes, the file stays for www.
	// The failed domain is dropped without a removal event.
	applyTrustTokens(nil, tokens("www.example.com", trustTokB, "shop.example.org", trustTokB))
	if got := readTrustFile(t, ex); got != trust.Header+"\n"+trustTokB+"\n" {
		t.Errorf("after removing one token: %q", got)
	}
	if got := h.take(); !reflect.DeepEqual(got, []string{"trust_token_removed example.com"}) {
		t.Errorf("events %q", got)
	}

	// Nothing listed: every file and the .well-known created for it go.
	applyTrustTokens(nil, nil)
	for _, r := range []string{ex, shop} {
		if _, err := os.Lstat(filepath.Join(r, trust.WellKnown)); !os.IsNotExist(err) {
			t.Errorf("%s: .well-known left behind", r)
		}
	}
	if got := h.take(); !reflect.DeepEqual(got, []string{"trust_token_removed shop.example.org", "trust_token_removed www.example.com"}) {
		t.Errorf("events %q", got)
	}
	if _, err := os.Stat(trustStatePath); !os.IsNotExist(err) {
		t.Error("empty state file left behind")
	}
}

func TestTrustTokensStateAcrossRestart(t *testing.T) {
	h := newTrustHarness(t)
	ex := h.root(t, "example")
	h.sites = []trust.Site{{Names: []string{"example.com"}, Root: ex}}
	applyTrustTokens(nil, tokens("example.com", trustTokA))
	h.take()

	var st trustPersisted
	data, err := os.ReadFile(trustStatePath)
	if err != nil || json.Unmarshal(data, &st) != nil {
		t.Fatalf("state: %v %s", err, data)
	}
	if r := st.Roots[ex]; r == nil || !r.CreatedDir || r.Tokens["example.com"] != trustTokA {
		t.Fatalf("state %s", data)
	}
	if info, _ := os.Stat(trustStatePath); info.Mode().Perm() != 0o600 {
		t.Errorf("state mode %v", info.Mode())
	}

	// After a restart (only the file remains) and with the web server
	// configuration changed so that nothing serves the domain any more, the
	// next sync without it still removes exactly what was written.
	h.sites = nil
	applyTrustTokens(nil, tokens("example.com", trustTokA))
	if got := h.take(); !reflect.DeepEqual(got, []string{"trust_token_failed example.com no_document_root"}) {
		t.Errorf("events %q", got)
	}
	if _, err := os.Lstat(filepath.Join(ex, trust.WellKnown)); !os.IsNotExist(err) {
		t.Error("file kept in a document root that no longer serves the domain")
	}
	applyTrustTokens(nil, nil)
	if got := h.take(); len(got) != 0 {
		t.Errorf("a failed domain reported %q on removal", got)
	}
}

func TestTrustTokensForeignFileAndInvalid(t *testing.T) {
	h := newTrustHarness(t)
	ex := h.root(t, "example")
	os.MkdirAll(filepath.Join(ex, trust.WellKnown), 0o755)
	os.WriteFile(trust.Path(ex), []byte("theirs\n"), 0o644)
	h.sites = []trust.Site{{Names: []string{"example.com"}, Root: ex}}

	applyTrustTokens(nil, tokens("example.com", trustTokA, "*.example.com", trustTokB, "bad.example.com", "ifv_nothex"))
	want := []string{
		"trust_token_failed *.example.com invalid_request",
		"trust_token_failed bad.example.com invalid_request",
		"trust_token_failed example.com file_exists",
	}
	if got := h.take(); !reflect.DeepEqual(got, want) {
		t.Errorf("events %q\nwant %q", got, want)
	}
	if got := readTrustFile(t, ex); got != "theirs\n" {
		t.Errorf("foreign file changed: %q", got)
	}
	applyTrustTokens(nil, tokens("example.com", trustTokA))
	if got := h.take(); len(got) != 0 {
		t.Errorf("failure reported again: %q", got)
	}
	// The owner removes their file: the next sync places ours.
	os.Remove(trust.Path(ex))
	applyTrustTokens(nil, tokens("example.com", trustTokA))
	if got := h.take(); !reflect.DeepEqual(got, []string{"trust_token_placed example.com " + trust.Path(ex)}) {
		t.Errorf("events %q", got)
	}
	// .well-known was there before: removing the token keeps it.
	applyTrustTokens(nil, nil)
	if _, err := os.Stat(filepath.Join(ex, trust.WellKnown)); err != nil {
		t.Error(".well-known the site had was removed")
	}
}

func TestTrustTokensNotWrittenWhileProtectionOff(t *testing.T) {
	h := newTrustHarness(t)
	ex := h.root(t, "example")
	h.sites = []trust.Site{{Names: []string{"example.com"}, Root: ex}}
	protCtl.Lock()
	saved := protCtl.disabledAt
	protCtl.disabledAt = time.Now()
	protCtl.Unlock()
	t.Cleanup(func() { protCtl.Lock(); protCtl.disabledAt = saved; protCtl.Unlock() })

	applyTrustTokens(nil, tokens("example.com", trustTokA))
	if entries, _ := os.ReadDir(ex); len(entries) != 0 || len(h.take()) != 0 {
		t.Errorf("written while protection is off: %v", entries)
	}
}

func TestRemoveTrustFiles(t *testing.T) {
	h := newTrustHarness(t)
	ex := h.root(t, "example")
	h.sites = []trust.Site{{Names: []string{"example.com"}, Root: ex}}
	applyTrustTokens(nil, tokens("example.com", trustTokA))
	removed, err := removeTrustFiles()
	if err != nil || !reflect.DeepEqual(removed, []string{trust.Path(ex)}) {
		t.Fatalf("removed %v, %v", removed, err)
	}
	if _, err := os.Lstat(filepath.Join(ex, trust.WellKnown)); !os.IsNotExist(err) {
		t.Error(".well-known left behind")
	}
	if _, err := os.Stat(trustStatePath); !os.IsNotExist(err) {
		t.Error("state left behind")
	}
}

func TestTrustTokensFailedRewriteKeepsServedDomain(t *testing.T) {
	h := newTrustHarness(t)
	ex := h.root(t, "example")
	h.sites = []trust.Site{{Names: []string{"example.com", "www.example.com"}, Root: ex}}
	applyTrustTokens(nil, tokens("example.com", trustTokA))
	h.take()

	saved := trustPlace
	t.Cleanup(func() { trustPlace = saved })
	trustPlace = func(string, []string) (bool, error) {
		return false, &trust.Error{Reason: trust.ReasonWriteFailed, Err: os.ErrPermission}
	}
	// A second domain cannot be added: only the new one failed, the one the
	// file still serves is not reported again.
	applyTrustTokens(nil, tokens("example.com", trustTokA, "www.example.com", trustTokB))
	if got := h.take(); !reflect.DeepEqual(got, []string{"trust_token_failed www.example.com write_failed"}) {
		t.Errorf("events %q", got)
	}
	if got := readTrustFile(t, ex); got != trust.Header+"\n"+trustTokA+"\n" {
		t.Errorf("file %q", got)
	}
	trustPlace = saved
	applyTrustTokens(nil, tokens("example.com", trustTokA, "www.example.com", trustTokB))
	if got := h.take(); !reflect.DeepEqual(got, []string{"trust_token_placed www.example.com " + trust.Path(ex)}) {
		t.Errorf("events after the retry %q", got)
	}
}

func TestTrustTokensDomainMovesToAnotherRoot(t *testing.T) {
	h := newTrustHarness(t)
	oldRoot, newRoot := h.root(t, "old"), h.root(t, "new")
	h.sites = []trust.Site{{Names: []string{"example.com"}, Root: oldRoot}}
	applyTrustTokens(nil, tokens("example.com", trustTokA))
	h.take()
	h.sites = []trust.Site{{Names: []string{"example.com"}, Root: newRoot}}
	applyTrustTokens(nil, tokens("example.com", trustTokA))
	if got := h.take(); !reflect.DeepEqual(got, []string{"trust_token_placed example.com " + trust.Path(newRoot)}) {
		t.Errorf("events %q", got)
	}
	if _, err := os.Lstat(filepath.Join(oldRoot, trust.WellKnown)); !os.IsNotExist(err) {
		t.Error("old document root still has the file")
	}
	if readTrustFile(t, newRoot) == "" {
		t.Error("new document root has no file")
	}
}

func TestTrustTokensDuplicates(t *testing.T) {
	h := newTrustHarness(t)
	ex := h.root(t, "example")
	h.sites = []trust.Site{{Names: []string{"example.com"}, Root: ex}}
	for _, list := range [][]api.TrustToken{
		tokens("example.com", "ifv_bad", "example.com", trustTokA),
		tokens("example.com", trustTokA, "example.com", "ifv_bad", "EXAMPLE.com", trustTokB),
	} {
		applyTrustTokens(nil, list)
		if got := readTrustFile(t, ex); got != trust.Header+"\n"+trustTokA+"\n" {
			t.Errorf("%v: file %q", list, got)
		}
	}
	if got := h.take(); !reflect.DeepEqual(got, []string{"trust_token_placed example.com " + trust.Path(ex)}) {
		t.Errorf("events %q", got)
	}
}

func TestTrustStateCorruptOrNull(t *testing.T) {
	newTrustHarness(t)
	os.MkdirAll(filepath.Dir(trustStatePath), 0o700)
	os.WriteFile(trustStatePath, []byte(`{"roots":{"/x":null,"relative":{"tokens":{}}},"reported":{}}`), 0o600)
	if st := loadTrustState(); len(st.Roots) != 0 {
		t.Errorf("null and relative roots kept: %v", st.Roots)
	}
	applyTrustTokens(nil, nil) // no panic

	os.WriteFile(trustStatePath, []byte(`{not json`), 0o600)
	loadTrustState()
	if _, err := os.Stat(trustStatePath + ".corrupt"); err != nil {
		t.Error("corrupt state not set aside")
	}
}

func TestTrustRemovalRetriedOnUnsafePath(t *testing.T) {
	h := newTrustHarness(t)
	ex := h.root(t, "example")
	h.sites = []trust.Site{{Names: []string{"example.com"}, Root: ex}}
	applyTrustTokens(nil, tokens("example.com", trustTokA))
	h.take()

	saved := trustRemove
	t.Cleanup(func() { trustRemove = saved })
	trustRemove = func(string, bool) error {
		return &trust.Error{Reason: trust.ReasonUnsafePath, Err: os.ErrInvalid}
	}
	applyTrustTokens(nil, nil)
	if got := h.take(); len(got) != 0 {
		t.Errorf("removal reported although the file may still be there: %q", got)
	}
	trustRemove = saved
	applyTrustTokens(nil, nil)
	if got := h.take(); !reflect.DeepEqual(got, []string{"trust_token_removed example.com"}) {
		t.Errorf("events %q", got)
	}
	if _, err := os.Lstat(filepath.Join(ex, trust.WellKnown)); !os.IsNotExist(err) {
		t.Error("file not removed on the retry")
	}
}
