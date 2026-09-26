// Package intel downloads public threat-intelligence lists directly from their
// publishers, on each server, at most once a day. Downloading on the server
// (rather than redistributing through the InfraFence backend) keeps each
// source's terms simple; see the per-source notes below.
package intel

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/watcher"
)

const (
	// Spamhaus asks for no more than one fetch per hour; once a day is plenty.
	RefreshInterval = 24 * time.Hour
	maxBody         = 20 << 20
	cacheDir        = "/etc/infrafence/intel"
)

// Source URLs. Terms checked 2026-09-26:
//   - Spamhaus DROP: free of charge; do not use the Spamhaus name in
//     marketing; keep the copyright with the data.
//   - Emerging Threats compromised IPs: no license stated by the publisher.
//   - monperrus/crawler-user-agents: MIT.
//   - ai-robots-txt/ai.robots.txt: MIT.
var (
	dropV4URL     = "https://www.spamhaus.org/drop/drop_v4.json"
	dropV6URL     = "https://www.spamhaus.org/drop/drop_v6.json"
	etCompromised = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
	crawlerUAURL  = "https://raw.githubusercontent.com/monperrus/crawler-user-agents/master/crawler-user-agents.json"
	aiRobotsURL   = "https://raw.githubusercontent.com/ai-robots-txt/ai.robots.txt/main/robots.json"
	httpClient    = &http.Client{Timeout: 60 * time.Second}
	userAgent     = "InfraFenceAgent"
)

// SetVersion sets the User-Agent sent to list publishers.
func SetVersion(v string) { userAgent = "InfraFenceAgent/" + v }

func get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxBody {
		return nil, fmt.Errorf("%s: response larger than %d bytes", url, maxBody)
	}
	return body, nil
}

// ── Threat feeds ────────────────────────────────────────────────────────

// ParseDROP parses Spamhaus DROP JSON (one object per line, last line is
// metadata).
func ParseDROP(data []byte, source string) []api.ThreatEntry {
	var out []api.ThreatEntry
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		var row struct {
			CIDR string `json:"cidr"`
		}
		if json.Unmarshal(sc.Bytes(), &row) != nil || row.CIDR == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(row.CIDR); err == nil {
			c := n.String()
			out = append(out, api.ThreatEntry{CIDR: &c, Source: source})
		}
	}
	return out
}

// ParseIPList parses a plain list with one IP or CIDR per line; '#' starts a
// comment.
func ParseIPList(data []byte, source string) []api.ThreatEntry {
	var out []api.ThreatEntry
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if ip := net.ParseIP(line); ip != nil {
			s := ip.String()
			out = append(out, api.ThreatEntry{IP: &s, Source: source})
		} else if _, n, err := net.ParseCIDR(line); err == nil {
			c := n.String()
			out = append(out, api.ThreatEntry{CIDR: &c, Source: source})
		}
	}
	return out
}

// FetchThreatFeeds downloads every threat feed. A source that fails is
// reported in errs and simply missing from the result.
func FetchThreatFeeds(ctx context.Context) ([]api.ThreatEntry, []error) {
	var all []api.ThreatEntry
	var errs []error
	for _, s := range []struct {
		url, source string
		parse       func([]byte, string) []api.ThreatEntry
	}{
		{dropV4URL, "drop", ParseDROP},
		{dropV6URL, "drop", ParseDROP},
		{etCompromised, "et-compromised", ParseIPList},
	} {
		body, err := get(ctx, s.url)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		entries := s.parse(body, s.source)
		if len(entries) == 0 {
			errs = append(errs, fmt.Errorf("%s: no entries parsed", s.url))
			continue
		}
		all = append(all, entries...)
	}
	return all, errs
}

// ── Bot fingerprints ────────────────────────────────────────────────────

// Default action per crawler-user-agents tag. Anything that looks like a
// legitimate crawler is allowed (and FCrDNS-verified where we know its
// domains); AI crawlers, scanners and scripted clients are logged.
var botActionByTag = map[string]string{
	"ai-crawler":         "log",
	"scanner":            "log",
	"http-library":       "log",
	"browser-automation": "log",
}

// Slugs that must match watcher.knownBotDomains for FCrDNS verification.
var slugAliases = map[string]string{
	"slurp":                "yahoo-slurp",
	"facebookexternalhit":  "facebookbot",
	"adsbot-google":        "google-adsbot",
	"mediapartners-google": "google-mediabot",
	"feedfetcher-google":   "google-feedfetch",
}

var slugToken = regexp.MustCompile(`[a-z0-9][a-z0-9_-]*`)

func slugOf(pattern string) string {
	s := strings.ToLower(strings.ReplaceAll(pattern, `\`, ""))
	tok := slugToken.FindString(s)
	if tok == "" {
		tok = "bot"
	}
	if a, ok := slugAliases[tok]; ok {
		return a
	}
	return tok
}

// ParseCrawlerUserAgents parses monperrus/crawler-user-agents.
func ParseCrawlerUserAgents(data []byte) ([]watcher.BotFingerprintInput, error) {
	var rows []struct {
		Pattern string   `json:"pattern"`
		Tags    []string `json:"tags"`
	}
	if err := json.Unmarshal(data, &rows); err != nil {
		return nil, err
	}
	out := make([]watcher.BotFingerprintInput, 0, len(rows))
	for _, r := range rows {
		if r.Pattern == "" {
			continue
		}
		if _, err := regexp.Compile(r.Pattern); err != nil {
			continue
		}
		category := "crawler"
		action := "allow"
		if len(r.Tags) > 0 {
			category = r.Tags[0]
			for _, t := range r.Tags {
				if a, ok := botActionByTag[t]; ok {
					category, action = t, a
					break
				}
			}
		}
		out = append(out, watcher.BotFingerprintInput{
			Slug:     slugOf(r.Pattern),
			Name:     strings.ReplaceAll(r.Pattern, `\`, ""),
			Pattern:  r.Pattern,
			IsRegex:  true,
			Category: category,
			Action:   action,
		})
	}
	return out, nil
}

// ParseAIRobots parses ai-robots-txt/ai.robots.txt robots.json (keyed by
// user-agent token).
func ParseAIRobots(data []byte) ([]watcher.BotFingerprintInput, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	out := make([]watcher.BotFingerprintInput, 0, len(m))
	for name := range m {
		if strings.TrimSpace(name) == "" {
			continue
		}
		out = append(out, watcher.BotFingerprintInput{
			Slug:     slugOf(name),
			Name:     name,
			Pattern:  name,
			Category: "ai-crawler",
			Action:   "log",
		})
	}
	return out, nil
}

// MergeBots returns crawler-user-agents entries plus AI crawlers not
// already covered by one of them.
func MergeBots(crawlers, ai []watcher.BotFingerprintInput) []watcher.BotFingerprintInput {
	out := append([]watcher.BotFingerprintInput{}, crawlers...)
	compiled := make([]*regexp.Regexp, 0, len(crawlers))
	for _, c := range crawlers {
		if re, err := regexp.Compile("(?i)" + c.Pattern); err == nil {
			compiled = append(compiled, re)
		}
	}
	for _, a := range ai {
		covered := false
		for _, re := range compiled {
			if re.MatchString(a.Name) {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, a)
		}
	}
	return out
}

// FetchBotFingerprints downloads both bot lists.
func FetchBotFingerprints(ctx context.Context) ([]watcher.BotFingerprintInput, error) {
	body, err := get(ctx, crawlerUAURL)
	if err != nil {
		return nil, err
	}
	crawlers, err := ParseCrawlerUserAgents(body)
	if err != nil {
		return nil, fmt.Errorf("crawler-user-agents: %w", err)
	}
	var ai []watcher.BotFingerprintInput
	if body, err := get(ctx, aiRobotsURL); err == nil {
		ai, _ = ParseAIRobots(body)
	}
	return MergeBots(crawlers, ai), nil
}

// ── Cache ───────────────────────────────────────────────────────────────

type cached[T any] struct {
	FetchedAt time.Time `json:"fetched_at"`
	Items     []T       `json:"items"`
}

// LoadCache returns cached items and when they were fetched.
func LoadCache[T any](name string) ([]T, time.Time) {
	data, err := os.ReadFile(filepath.Join(cacheDir, name))
	if err != nil {
		return nil, time.Time{}
	}
	var c cached[T]
	if json.Unmarshal(data, &c) != nil {
		return nil, time.Time{}
	}
	return c.Items, c.FetchedAt
}

// SaveCache stores items with the current time.
func SaveCache[T any](name string, items []T) error {
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return err
	}
	data, err := json.Marshal(cached[T]{FetchedAt: time.Now().UTC(), Items: items})
	if err != nil {
		return err
	}
	tmp := filepath.Join(cacheDir, name+".tmp")
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(cacheDir, name))
}
