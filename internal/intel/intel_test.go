package intel

import (
	"testing"
)

func TestParseDROP(t *testing.T) {
	data := []byte(`{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}
{"cidr":"2a06:e480::/29","sblid":"SBL1","rir":"ripencc"}
{"cidr":"bad"}
{"type":"metadata","timestamp":1790329442,"records":2,"copyright":"(c) 2026 The Spamhaus Project SLU"}
`)
	got := ParseDROP(data, "drop")
	if len(got) != 2 || *got[0].CIDR != "1.10.16.0/20" || *got[1].CIDR != "2a06:e480::/29" || got[0].Source != "drop" {
		t.Fatalf("got %+v", got)
	}
}

func TestParseIPList(t *testing.T) {
	got := ParseIPList([]byte("# header\n203.0.113.5\n  198.51.100.0/24 # trailing\n\nnot-an-ip\n"), "et")
	if len(got) != 2 || got[0].IP == nil || *got[0].IP != "203.0.113.5" || got[1].CIDR == nil || *got[1].CIDR != "198.51.100.0/24" {
		t.Fatalf("got %+v", got)
	}
}

func TestParseCrawlerUserAgents(t *testing.T) {
	data := []byte(`[
 {"pattern":"Googlebot\\/","tags":["search-engine"]},
 {"pattern":"Slurp","tags":["search-engine"]},
 {"pattern":"facebookexternalhit","tags":["social-preview"]},
 {"pattern":"GPTBot","tags":["ai-crawler"]},
 {"pattern":"python-requests","tags":["http-library"]},
 {"pattern":"broken(","tags":["seo"]}
]`)
	got, err := ParseCrawlerUserAgents(data)
	if err != nil || len(got) != 5 {
		t.Fatalf("got %d entries, err %v", len(got), err)
	}
	want := []struct{ slug, category, action string }{
		{"googlebot", "search-engine", "allow"},
		{"yahoo-slurp", "search-engine", "allow"},
		{"facebookbot", "social-preview", "allow"},
		{"gptbot", "ai-crawler", "log"},
		{"python-requests", "http-library", "log"},
	}
	for i, w := range want {
		g := got[i]
		if g.Slug != w.slug || g.Category != w.category || g.Action != w.action || !g.IsRegex {
			t.Errorf("%d: got %+v want %+v", i, g, w)
		}
	}
}

func TestMergeBotsSkipsCoveredAICrawlers(t *testing.T) {
	crawlers, _ := ParseCrawlerUserAgents([]byte(`[{"pattern":"GPTBot","tags":["ai-crawler"]}]`))
	ai, err := ParseAIRobots([]byte(`{"GPTBot":{},"ClaudeBot":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	got := MergeBots(crawlers, ai)
	if len(got) != 2 {
		t.Fatalf("got %d, want 2 (GPTBot once, plus ClaudeBot): %+v", len(got), got)
	}
	if got[1].Name != "ClaudeBot" || got[1].IsRegex || got[1].Action != "log" {
		t.Errorf("added AI crawler: %+v", got[1])
	}
}
