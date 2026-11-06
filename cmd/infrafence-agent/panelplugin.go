package main

import (
	"context"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
)

// The InfraFence plugin installed in the hosting panel, for the dashboard
// (heartbeat "panel_plugin") and "panel status" ("plugin_installed"): the
// plugin is updated from the dashboard, not with the agent, so both show
// its own version. Read only: the VERSION file the plugin installs, else
// one query of the package database. Detected at most once per
// panelPluginEvery, and again as soon as the VERSION file changes (an
// update from WHM or the dashboard), never by running the panel.

// panelPluginByPanel: where each panel's plugin says its version.
var panelPluginByPanel = map[string]struct {
	name, versionFile, pkg string
}{
	"cpanel": {"whm", "/usr/local/share/infrafence-whm/VERSION", "infrafence-whm"},
}

const panelPluginEvery = time.Hour

// Replaced in tests.
var (
	panelPluginDetect = detectPanelPlugin
	panelPluginQuery  = queryPackageVersion
	panelPluginStamp  = versionFileStamp
)

var panelPluginCache struct {
	sync.Mutex
	panelID string
	at      time.Time
	stamp   string // the VERSION file when detected (versionFileStamp)
	v       *api.PanelPlugin
	busy    bool // a detection is running
}

func resetPanelPluginCache() {
	panelPluginCache.Lock()
	panelPluginCache.panelID, panelPluginCache.at, panelPluginCache.stamp, panelPluginCache.v, panelPluginCache.busy = "", time.Time{}, "", nil, false
	panelPluginCache.Unlock()
}

// panelPlugin is the plugin of panelID, detected again when the last
// detection is at least panelPluginEvery old or the VERSION file changed
// since (one stat per call). The detection runs outside the lock:
// meanwhile other callers get the last answer.
func panelPlugin(panelID string) *api.PanelPlugin {
	p, ok := panelPluginByPanel[panelID]
	if !ok {
		return nil
	}
	stamp := panelPluginStamp(p.versionFile)
	c := &panelPluginCache
	c.Lock()
	// A clock set back never stops the detection for long.
	since := time.Since(c.at)
	stale := c.panelID != panelID || c.at.IsZero() || since < 0 || since >= panelPluginEvery || stamp != c.stamp
	if !stale || c.busy {
		v := c.v
		if c.panelID != panelID {
			v = nil
		}
		c.Unlock()
		return copyPlugin(v)
	}
	c.busy = true
	c.Unlock()

	v := panelPluginDetect(panelID)

	c.Lock()
	c.panelID, c.at, c.stamp, c.v, c.busy = panelID, time.Now(), stamp, v, false
	c.Unlock()
	return copyPlugin(v)
}

func copyPlugin(p *api.PanelPlugin) *api.PanelPlugin {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// pluginVersionOf is the plugin's version for a reply, or nil.
func pluginVersionOf(p *api.PanelPlugin) any {
	if p == nil {
		return nil
	}
	return p.Version
}

// detectPanelPlugin reads the plugin's VERSION file, or asks the package
// database when there is none.
func detectPanelPlugin(panelID string) *api.PanelPlugin {
	p, ok := panelPluginByPanel[panelID]
	if !ok {
		return nil
	}
	v := readVersionFile(p.versionFile)
	if v == "" {
		v = panelPluginQuery(p.pkg)
	}
	if !api.ValidPluginVersion(v) {
		return nil
	}
	return &api.PanelPlugin{Panel: p.name, Version: v}
}

// versionFileStamp: the file's modification time and size, "" when it is
// missing or not a regular file.
func versionFileStamp(path string) string {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return ""
	}
	return fi.ModTime().UTC().Format(time.RFC3339Nano) + " " + strconv.FormatInt(fi.Size(), 10)
}

// readVersionFile: the first line of a small regular file (not a link).
func readVersionFile(path string) string {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, 64))
	line, _, _ := strings.Cut(string(b), "\n")
	return strings.TrimSpace(line)
}

// queryPackageVersion is the version of an installed rpm or deb package,
// "" when it is not installed. Bounded in time.
func queryPackageVersion(pkg string) string {
	if out, ok := runQuery("rpm", "-q", "--qf", "%{VERSION}", pkg); ok {
		return out
	}
	// A removed package whose configuration is left is not installed.
	if out, ok := runQuery("dpkg-query", "-W", "-f", "${Status}|${Version}", pkg); ok {
		if status, v, _ := strings.Cut(out, "|"); status == "install ok installed" {
			return v
		}
	}
	return ""
}

// packageTools: the package databases' query tools, by absolute path (never
// looked up in the caller's PATH: "panel status" runs as root).
var packageTools = map[string][]string{
	"rpm":        {"/usr/bin/rpm", "/bin/rpm"},
	"dpkg-query": {"/usr/bin/dpkg-query", "/bin/dpkg-query"},
}

func runQuery(name string, args ...string) (string, bool) {
	path := ""
	for _, p := range packageTools[name] {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			path = p
			break
		}
	}
	if path == "" {
		return "", false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, args...).Output()
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(out)), true
}
