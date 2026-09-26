package intel

import (
	"context"
	"os"
	"testing"
	"time"
)

// Downloads the real lists; run with INFRAFENCE_INTEL_E2E=1.
func TestFetchRealLists(t *testing.T) {
	if os.Getenv("INFRAFENCE_INTEL_E2E") != "1" {
		t.Skip("set INFRAFENCE_INTEL_E2E=1 to run")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	feeds, errs := FetchThreatFeeds(ctx)
	if len(errs) > 0 {
		t.Errorf("feed errors: %v", errs)
	}
	bySource := map[string]int{}
	for _, e := range feeds {
		bySource[e.Source]++
	}
	t.Logf("threat entries: %d %v", len(feeds), bySource)
	if bySource["drop"] < 500 || bySource["et-compromised"] < 100 {
		t.Errorf("suspiciously few entries: %v", bySource)
	}

	bots, err := FetchBotFingerprints(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cats := map[string]int{}
	slugs := map[string]bool{}
	for _, b := range bots {
		cats[b.Action]++
		slugs[b.Slug] = true
	}
	t.Logf("bot fingerprints: %d, by action %v", len(bots), cats)
	for _, s := range []string{"googlebot", "bingbot", "yahoo-slurp", "facebookbot", "applebot", "duckduckbot"} {
		if !slugs[s] {
			t.Errorf("missing slug %q needed for FCrDNS verification", s)
		}
	}
}
