package main

import (
	"testing"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/watcher"
)

func TestApplyBotPolicy(t *testing.T) {
	list := []watcher.BotFingerprintInput{
		{Slug: "googlebot", Category: "search-engine", Action: "allow", Pattern: "Googlebot"},
		{Slug: "gptbot", Category: "ai-crawler", Action: "log", Pattern: "GPTBot"},
		{Slug: "claudebot", Category: "ai-crawler", Action: "log", Pattern: "ClaudeBot"},
		{Slug: "ahrefsbot", Category: "seo", Action: "allow", Pattern: "AhrefsBot"},
		{Slug: "semrushbot", Category: "seo", Action: "allow", Pattern: "SemrushBot"},
	}
	p := api.BotPolicy{
		Categories: map[string]string{"ai-crawler": "block", "seo": "log", "search-engine": "nonsense"},
		Bots:       map[string]string{"claudebot": "allow", "semrushbot": "block", "unknownbot": "block"},
	}
	got := map[string]string{}
	for _, fp := range applyBotPolicy(list, p) {
		got[fp.Slug] = fp.Action
	}
	want := map[string]string{
		"googlebot":  "allow", // invalid category action ignored: list default
		"gptbot":     "block", // category override
		"claudebot":  "allow", // the bot's own entry wins over its category
		"ahrefsbot":  "log",   // category override
		"semrushbot": "block", // bot override
	}
	for slug, a := range want {
		if got[slug] != a {
			t.Errorf("%s: action %q, want %q", slug, got[slug], a)
		}
	}
	if list[1].Action != "log" {
		t.Error("applyBotPolicy modified its input")
	}
	// No policy: list defaults.
	for i, fp := range applyBotPolicy(list, api.BotPolicy{}) {
		if fp.Action != list[i].Action {
			t.Errorf("empty policy changed %s", fp.Slug)
		}
	}
}

func TestBotPolicyReappliedOnChangeOnly(t *testing.T) {
	botState.Lock()
	botState.downloaded, botState.policyKey, botState.effective = nil, "", nil
	botState.Unlock()

	setDownloadedBots(nil, []watcher.BotFingerprintInput{
		{Slug: "gptbot", Category: "ai-crawler", Action: "log", Pattern: "GPTBot"},
		{Slug: "bytespider", Category: "ai-crawler", Action: "log", Pattern: "Bytespider"},
	})
	if n := len(blockedBotUAs()); n != 0 {
		t.Fatalf("list defaults block nothing, got %d", n)
	}
	setBotPolicy(nil, &api.BotPolicy{Bots: map[string]string{"bytespider": "block"}})
	if b := blockedBotUAs(); len(b) != 1 || b[0].Pattern != "Bytespider" {
		t.Fatalf("blocked = %+v", b)
	}
	// A new download keeps the policy.
	setDownloadedBots(nil, []watcher.BotFingerprintInput{
		{Slug: "bytespider", Category: "ai-crawler", Action: "log", Pattern: "Bytespider"},
		{Slug: "ccbot", Category: "ai-crawler", Action: "log", Pattern: "CCBot"},
	})
	if b := blockedBotUAs(); len(b) != 1 || b[0].Pattern != "Bytespider" {
		t.Fatalf("policy lost after a new download: %+v", b)
	}
	// Removing the policy (nil from an older dashboard) restores defaults.
	setBotPolicy(nil, nil)
	if n := len(blockedBotUAs()); n != 0 {
		t.Fatalf("defaults not restored, %d blocked", n)
	}
}
