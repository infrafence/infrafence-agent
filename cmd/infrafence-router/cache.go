package main

import (
	"encoding/json"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/infrafence/infrafence-agent/internal/router/fw"
)

// The last sync, kept in tmpfs (never on flash): when procd restarts the
// agent (crash, upgrade) while the dashboard is unreachable, the router
// keeps the protection it had instead of falling back to Learning with
// empty sets. It does not survive a reboot: then the agent waits for the
// dashboard, in Learning.
const (
	cacheFile   = "last-sync.json"
	cacheMaxAge = 24 * time.Hour
)

type cachedElement struct {
	Prefix  string    `json:"p"`
	Expires time.Time `json:"e,omitempty"`
	Source  string    `json:"s,omitempty"`
}

type syncCache struct {
	SavedAt    time.Time       `json:"saved_at"`
	Mode       string          `json:"mode"`
	Suspended  bool            `json:"suspended,omitempty"`
	ShareNames bool            `json:"share_names,omitempty"`
	ListURL    string          `json:"list_url,omitempty"`
	ListETag   string          `json:"list_etag,omitempty"`
	Bans       []cachedElement `json:"bans"`
	Feed       []cachedElement `json:"feed"`
	C2         []cachedElement `json:"c2"`
}

func toCached(els []fw.Element, sources map[netip.Prefix]string) []cachedElement {
	out := make([]cachedElement, 0, len(els))
	for _, e := range els {
		out = append(out, cachedElement{Prefix: e.Prefix.String(), Expires: e.Expires, Source: sources[e.Prefix]})
	}
	return out
}

func fromCached(cs []cachedElement, now time.Time) ([]fw.Element, map[netip.Prefix]string) {
	out := make([]fw.Element, 0, len(cs))
	src := map[netip.Prefix]string{}
	for _, c := range cs {
		p, err := netip.ParsePrefix(c.Prefix)
		if err != nil || !c.Expires.IsZero() && !c.Expires.After(now) {
			continue
		}
		out = append(out, fw.Element{Prefix: p, Expires: c.Expires})
		if c.Source != "" {
			src[p] = c.Source
		}
	}
	return out, src
}

func saveCache(c *syncCache) {
	c.SavedAt = time.Now()
	data, err := json.Marshal(c)
	if err != nil {
		return
	}
	if err := writeFileAtomic(filepath.Join(stateDir, cacheFile), data, 0o600); err != nil {
		log.Printf("[cache] %v", err)
	}
}

func loadCache() *syncCache {
	data, err := os.ReadFile(filepath.Join(stateDir, cacheFile))
	if err != nil {
		return nil
	}
	var c syncCache
	if json.Unmarshal(data, &c) != nil || time.Since(c.SavedAt) > cacheMaxAge || c.SavedAt.After(time.Now().Add(time.Minute)) {
		return nil
	}
	return &c
}

// restoreCache puts the last sync back in force at start. The entries
// pass the guard again (the router's addresses may have changed).
func (a *agent) restoreCache() bool {
	c := loadCache()
	if c == nil {
		return false
	}
	now := time.Now()
	mode := fw.Learning
	if c.Mode == fw.Full.String() && !c.Suspended {
		mode = fw.Full
	}
	guarded := func(els []fw.Element) []fw.Element {
		out := els[:0]
		for _, e := range els {
			if a.guard.Check(e.Prefix) == nil {
				out = append(out, e)
			}
		}
		return out
	}
	bans, _ := fromCached(c.Bans, now)
	feed, _ := fromCached(c.Feed, now)
	c2, src := fromCached(c.C2, now)
	bans, feed, c2 = guarded(bans), guarded(feed), guarded(c2)
	a.mu.Lock()
	a.mode = mode
	a.suspended = c.Suspended
	a.synced = true
	a.lastSync = c.SavedAt
	a.shareNames = c.ShareNames && a.set.DeviceNames != "never"
	a.c2FromSync = c2
	a.c2Sources = src
	a.mu.Unlock()
	a.find.setShareNames(a.shareNames)
	a.find.setMode(mode)
	if a.fw != nil {
		if err := a.fw.SetMode(mode); err != nil {
			log.Printf("[firewall] restore: %v", err)
		}
		_ = a.fw.Set(fw.KindBan, bans)
		_ = a.fw.Set(fw.KindFeed, feed)
		_ = a.fw.Set(fw.KindC2, a.allC2(now))
	}
	// The domain list still in tmpfs from the previous run.
	if c.ListETag != "" && a.dns.Adopt() {
		a.mu.Lock()
		a.listETag, a.listURL = c.ListETag, c.ListURL
		a.mu.Unlock()
	}
	log.Printf("[cache] restored the last sync of %s: mode %s, %d bans, %d feed, %d C2", c.SavedAt.UTC().Format(time.RFC3339), mode, len(bans), len(feed), len(c2))
	return true
}
