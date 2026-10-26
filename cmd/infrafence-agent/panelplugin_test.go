package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/panel"
)

// withPluginFiles points the WHM plugin's VERSION file into a temporary
// directory and fakes the package database.
func withPluginFiles(t *testing.T, pkgVersion string) (versionFile string, queries *int) {
	t.Helper()
	saved, savedQuery := panelPluginByPanel["cpanel"], panelPluginQuery
	p := saved
	p.versionFile = filepath.Join(t.TempDir(), "VERSION")
	panelPluginByPanel["cpanel"] = p
	n := 0
	panelPluginQuery = func(pkg string) string {
		n++
		if pkg != "infrafence-whm" {
			t.Errorf("package %q", pkg)
		}
		return pkgVersion
	}
	resetPanelPluginCache()
	t.Cleanup(func() {
		panelPluginByPanel["cpanel"], panelPluginQuery = saved, savedQuery
		resetPanelPluginCache()
	})
	return p.versionFile, &n
}

func TestDetectPanelPlugin(t *testing.T) {
	file, queries := withPluginFiles(t, "")
	if p := detectPanelPlugin("cpanel"); p != nil {
		t.Errorf("nothing installed: %+v", p)
	}
	os.WriteFile(file, []byte("1.0.2\n"), 0o644)
	if p := detectPanelPlugin("cpanel"); p == nil || *p != (api.PanelPlugin{Panel: "whm", Version: "1.0.2"}) {
		t.Errorf("VERSION file: %+v", p)
	}
	if *queries != 1 {
		t.Errorf("package database asked %d times, want only without the file", *queries)
	}
	for _, bad := range []string{"", "unknown\n", "1.0.2<script>\n", "\n1.0.2\n"} {
		os.WriteFile(file, []byte(bad), 0o644)
		if p := detectPanelPlugin("cpanel"); p != nil {
			t.Errorf("%q: %+v", bad, p)
		}
	}
	// A link is not followed.
	target := filepath.Join(t.TempDir(), "elsewhere")
	os.WriteFile(target, []byte("9.9.9\n"), 0o644)
	os.Remove(file)
	os.Symlink(target, file)
	if p := detectPanelPlugin("cpanel"); p != nil {
		t.Errorf("symlink followed: %+v", p)
	}
	// Other panels have no plugin version yet.
	for _, id := range []string{"plesk", "directadmin", ""} {
		if p := detectPanelPlugin(id); p != nil {
			t.Errorf("%s: %+v", id, p)
		}
	}
}

func TestDetectPanelPluginFromPackage(t *testing.T) {
	withPluginFiles(t, "1.0.3")
	if p := detectPanelPlugin("cpanel"); p == nil || p.Version != "1.0.3" {
		t.Errorf("package: %+v", p)
	}
}

// Detected once, then at most hourly; the heartbeat uses the cache.
func TestPanelPluginCachedHourly(t *testing.T) {
	saved := panelPluginDetect
	t.Cleanup(func() { panelPluginDetect = saved; resetPanelPluginCache() })
	resetPanelPluginCache()
	n, ver := 0, "1.0.2"
	panelPluginDetect = func(string) *api.PanelPlugin { n++; return &api.PanelPlugin{Panel: "whm", Version: ver} }
	for range 5 {
		if p := panelPlugin("cpanel"); p == nil || p.Version != "1.0.2" {
			t.Fatalf("got %+v", p)
		}
	}
	if n != 1 {
		t.Fatalf("detected %d times, want 1", n)
	}
	ver = "1.0.3"
	panelPluginCache.Lock()
	panelPluginCache.at = time.Now().Add(-panelPluginEvery)
	panelPluginCache.Unlock()
	if p := panelPlugin("cpanel"); p == nil || p.Version != "1.0.3" || n != 2 {
		t.Fatalf("after an hour: %+v (%d)", p, n)
	}
	// Not a panel with a plugin: nothing is read.
	if p := panelPlugin("plesk"); p != nil || n != 2 {
		t.Fatalf("plesk: %+v (%d)", p, n)
	}
	// The caller's copy can't change the cache.
	panelPlugin("cpanel").Version = "x"
	if p := panelPlugin("cpanel"); p.Version != "1.0.3" {
		t.Fatalf("cache changed: %+v", p)
	}
}

func TestPanelStatusPluginVersions(t *testing.T) {
	withFakePanel(t)
	r := handlePanel(panel.Request{Command: "status"})
	if r["plugin_installed"] != "1.0.2" || r["plugin_latest"] != nil {
		t.Errorf("before a sync with it: %v %v", r["plugin_installed"], r["plugin_latest"])
	}
	panelNoteSync(&api.SyncResponse{PanelPluginLatest: []byte(`{"whm":"1.0.3"}`)})
	if r := handlePanel(panel.Request{Command: "status"}); r["plugin_installed"] != "1.0.2" || r["plugin_latest"] != "1.0.3" {
		t.Errorf("after: %v %v", r["plugin_installed"], r["plugin_latest"])
	}
	// A dashboard that stops sending it, or sends garbage.
	panelNoteSync(&api.SyncResponse{PanelPluginLatest: []byte(`{"whm":"<b>"}`)})
	if r := handlePanel(panel.Request{Command: "status"}); r["plugin_latest"] != nil {
		t.Errorf("garbage: %v", r["plugin_latest"])
	}
	// Plesk: no plugin version yet, both null but present.
	panelInfo.panelID = "plesk"
	panelNoteSync(&api.SyncResponse{PanelPluginLatest: []byte(`{"whm":"1.0.3"}`)})
	r = handlePanel(panel.Request{Command: "status"})
	if v, ok := r["plugin_installed"]; !ok || v != nil {
		t.Errorf("plesk installed: %v", v)
	}
	if v, ok := r["plugin_latest"]; !ok || v != nil {
		t.Errorf("plesk latest: %v", v)
	}
}
