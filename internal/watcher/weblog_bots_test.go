package watcher

import "testing"

func TestBotLiteralIndex(t *testing.T) {
	w := &WebWatcher{}
	w.UpdateBotFingerprints([]BotFingerprintInput{
		{Slug: "googlebot", Pattern: `Googlebot\/`, IsRegex: true},
		{Slug: "wget", Pattern: `[wW]get`, IsRegex: true},
		{Slug: "claudebot", Pattern: "ClaudeBot"},
	})
	for _, b := range w.botFingerprints {
		want := map[string]string{"googlebot": "googlebot/", "wget": "", "claudebot": "claudebot"}[b.Slug]
		if b.lit != want {
			t.Errorf("%s: literal prefix %q, want %q", b.Slug, b.lit, want)
		}
	}
}

func TestBotEventCooldown(t *testing.T) {
	w := &WebWatcher{}
	if !w.botEventDue("203.0.113.1", "googlebot") {
		t.Error("first event should be due")
	}
	if w.botEventDue("203.0.113.1", "googlebot") {
		t.Error("second event within the hour should be suppressed")
	}
	if !w.botEventDue("203.0.113.2", "googlebot") || !w.botEventDue("203.0.113.1", "bingbot") {
		t.Error("other IPs and other bots are independent")
	}
}
