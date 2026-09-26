package watcher

import "sort"

// WAFCatalog describes every built-in WAF rule of this agent build. It is
// generated at release time (cmd/wafcatalog) and published as
// waf-catalog.json, so the dashboard shows exactly what the agent applies.
type WAFCatalog struct {
	AgentVersion        string                `json:"agent_version"`
	Patterns            []WAFCatalogPattern   `json:"patterns"`
	Thresholds          []WAFCatalogThreshold `json:"thresholds"`
	ScorePoints         map[string]int        `json:"score_points"`
	ActionLevels        map[string]int        `json:"action_levels"`
	ScoreDecayPerMinute int                   `json:"score_decay_per_minute"`
	CustomRuleTargets   []string              `json:"custom_rule_targets"`
}

// WAFCatalogPattern is one built-in substring pattern.
type WAFCatalogPattern struct {
	// ID is stable across releases and is what waf_config.disabled_patterns
	// refers to.
	ID        string `json:"id"`
	Group     string `json:"group"`
	EventType string `json:"event_type"`
	// Target: "uri", "ua" (User-Agent) or "ua_or_referer".
	Target  string `json:"target"`
	Pattern string `json:"pattern"`
}

// WAFCatalogThreshold is a rate rule: Threshold hits within WindowSeconds.
// ConfigKey is the waf_config.thresholds key that overrides Threshold.
type WAFCatalogThreshold struct {
	Rule             string `json:"rule"`
	EventType        string `json:"event_type"`
	ConfigKey        string `json:"config_key"`
	DefaultThreshold int    `json:"default_threshold"`
	WindowSeconds    int    `json:"window_seconds"`
}

// thresholdConfigKeys mirrors the wafThreshold() keys used in processLine.
var thresholdConfigKeys = map[string]string{
	"wp_login":    "wp_bruteforce",
	"xmlrpc":      "xmlrpc_abuse",
	"wp_ajax":     "wp_bruteforce",
	"drupal_auth": "cms_bruteforce",
	"joomla_auth": "cms_bruteforce",
	"plugin_scan": "scanner_detected",
	"404_flood":   "404_flood",
}

// BuiltinWAFCatalog returns the catalog of built-in rules.
func BuiltinWAFCatalog(version string) WAFCatalog {
	c := WAFCatalog{
		AgentVersion: version,
		ScorePoints:  map[string]int{},
		ActionLevels: map[string]int{
			"observe":   thresholdObserve,
			"throttle":  thresholdThrottle,
			"block":     thresholdBlock,
			"blacklist": thresholdBlacklist,
		},
		ScoreDecayPerMinute: decayPointsPerMin,
		CustomRuleTargets:   []string{"uri", "ua", "referer"},
	}
	for k, v := range defaultScorePoints {
		c.ScorePoints[k] = v
	}

	for _, g := range instantBanPatterns {
		for _, p := range g.patterns {
			c.Patterns = append(c.Patterns, WAFCatalogPattern{
				ID: g.name + ":" + p, Group: g.name, EventType: g.eventType, Target: "uri", Pattern: p,
			})
		}
	}
	for _, a := range scannerAgents {
		c.Patterns = append(c.Patterns, WAFCatalogPattern{
			ID: "scanner_ua:" + a, Group: "scanner_ua", EventType: "scanner_detected", Target: "ua", Pattern: a,
		})
	}
	for _, p := range headerInjectionPatterns {
		c.Patterns = append(c.Patterns, WAFCatalogPattern{
			ID: "header_injection:" + p, Group: "header_injection", EventType: "header_injection", Target: "ua_or_referer", Pattern: p,
		})
	}
	c.Patterns = append(c.Patterns, WAFCatalogPattern{
		ID: "shellshock:" + shellshockPattern, Group: "shellshock", EventType: "shellshock", Target: "ua_or_referer", Pattern: shellshockPattern,
	})

	for _, r := range []thresholdRule{ruleWPLogin, ruleXMLRPC, ruleWPAjax, ruleDrupalAuth, ruleJoomlaAuth, rulePluginScan, rule404Flood} {
		c.Thresholds = append(c.Thresholds, WAFCatalogThreshold{
			Rule:             r.key,
			EventType:        r.eventType,
			ConfigKey:        thresholdConfigKeys[r.key],
			DefaultThreshold: r.threshold,
			WindowSeconds:    int(r.window.Seconds()),
		})
	}
	sort.SliceStable(c.Thresholds, func(i, j int) bool { return c.Thresholds[i].Rule < c.Thresholds[j].Rule })
	return c
}
