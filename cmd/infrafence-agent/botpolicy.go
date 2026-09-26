package main

import (
	"encoding/json"
	"log"
	"sync"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/watcher"
	"github.com/infrafence/infrafence-agent/internal/webserver"
)

// Bot fingerprints come from public lists downloaded daily (internal/intel),
// each with a default action for its category. The dashboard's bot policy
// overrides that action per category and per bot; it is re-applied whenever
// either the lists or the policy change, without downloading anything again.
var botState struct {
	sync.Mutex
	downloaded []watcher.BotFingerprintInput
	policy     api.BotPolicy
	policyKey  string
	effective  []watcher.BotFingerprintInput
}

func validBotAction(a string) bool {
	return a == "allow" || a == "log" || a == "block"
}

// applyBotPolicy returns fps with the policy's actions applied: the bot's own
// entry first, then its category's, else the list default. fps is not changed.
func applyBotPolicy(fps []watcher.BotFingerprintInput, p api.BotPolicy) []watcher.BotFingerprintInput {
	out := make([]watcher.BotFingerprintInput, len(fps))
	for i, fp := range fps {
		if a, ok := p.Bots[fp.Slug]; ok && validBotAction(a) {
			fp.Action = a
		} else if a, ok := p.Categories[fp.Category]; ok && validBotAction(a) {
			fp.Action = a
		}
		out[i] = fp
	}
	return out
}

// setDownloadedBots installs a freshly downloaded (or cached) bot list.
func setDownloadedBots(webW *watcher.WebWatcher, fps []watcher.BotFingerprintInput) {
	if len(fps) == 0 {
		return
	}
	botState.Lock()
	botState.downloaded = fps
	botState.Unlock()
	reapplyBots(webW)
}

// setBotPolicy installs the dashboard's bot policy; re-applies only when it
// changed. nil (older dashboard) means no overrides.
func setBotPolicy(webW *watcher.WebWatcher, p *api.BotPolicy) {
	var pol api.BotPolicy
	if p != nil {
		pol = *p
	}
	key, _ := json.Marshal(pol)
	botState.Lock()
	changed := string(key) != botState.policyKey
	if changed {
		botState.policy, botState.policyKey = pol, string(key)
	}
	botState.Unlock()
	if changed {
		log.Printf("[bots] policy: %d category and %d bot override(s)", len(pol.Categories), len(pol.Bots))
		reapplyBots(webW)
	}
}

func reapplyBots(webW *watcher.WebWatcher) {
	botState.Lock()
	if len(botState.downloaded) == 0 {
		botState.Unlock()
		return
	}
	eff := applyBotPolicy(botState.downloaded, botState.policy)
	botState.effective = eff
	botState.Unlock()
	// Fingerprints sent by an older dashboard take precedence, as before.
	if webW == nil || dashboardBots.Load() {
		return
	}
	webW.UpdateBotFingerprints(eff)
}

// blockedBotUAs returns the User-Agent patterns of bots the policy blocks,
// for web-server-level blocking (only used when web server changes are
// allowed; the firewall ban applies either way).
func blockedBotUAs() []webserver.UAFingerprint {
	botState.Lock()
	defer botState.Unlock()
	var out []webserver.UAFingerprint
	for _, fp := range botState.effective {
		if fp.Action == "block" {
			out = append(out, webserver.UAFingerprint{Pattern: fp.Pattern, IsRegex: fp.IsRegex})
		}
	}
	return out
}
