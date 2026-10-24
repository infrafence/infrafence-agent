package api

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// AttackMap is where this server's attacks came from in the last Hours
// (GET /api/v1/agent/map): attacks only, by country and by category.
type AttackMap struct {
	Hours       int    `json:"hours"`
	GeneratedAt string `json:"generated_at"`
	Total       struct {
		Attacks int64 `json:"attacks"`
	} `json:"total"`
	Countries  []MapCountry  `json:"countries"`
	Categories []MapCategory `json:"categories"`
}

type MapCountry struct {
	Code    string `json:"code"`
	Attacks int64  `json:"attacks"`
}

type MapCategory struct {
	Cat     string `json:"cat"`
	Attacks int64  `json:"attacks"`
}

const (
	// maxInfoBody: 250 countries are about 8 KB.
	maxInfoBody      = 64 << 10
	maxMapCountries  = 250
	maxMapCategories = 32
)

var (
	mapCountryCode = regexp.MustCompile(`^[A-Z]{2}$`)
	mapCategory    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	errInfoInvalid = errors.New("invalid answer from the dashboard")
)

// AttackMap asks the dashboard for this server's attack map.
func (c *Client) AttackMap(ctx context.Context, hours int) (*AttackMap, error) {
	var m AttackMap
	if err := c.getInfo(ctx, "/api/v1/agent/map?hours="+strconv.Itoa(hours), &m); err != nil {
		return nil, err
	}
	if err := m.check(hours); err != nil {
		return nil, err
	}
	return &m, nil
}

// getInfo fetches what the panel plugins show (attack map, security
// score). It is informational: it never starts or resets the refusal
// backoff (the heartbeat and the sync do), but nothing is sent while that
// backoff runs. The answer is bounded in time (ctx and the client's 15 s)
// and size; the caller checks it field by field.
func (c *Client) getInfo(ctx context.Context, path string, out any) error {
	if wait := c.gate.Wait(); wait > 0 {
		code, _ := c.gate.State()
		return &statusError{code: code, held: true, retryAfter: wait}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("User-Agent", c.userAgent)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Only the status is kept (it ends up in the agent's log), never
		// the body.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("the dashboard answered HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxInfoBody+1))
	if err != nil {
		return err
	}
	if len(body) > maxInfoBody {
		return fmt.Errorf("%w: larger than %d bytes", errInfoInvalid, maxInfoBody)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("%w: %v", errInfoInvalid, err)
	}
	return nil
}

// check refuses an answer that is not the map asked for, and normalizes
// the rest: generated_at in UTC, lists sorted by attacks (most first),
// never null.
func (m *AttackMap) check(hours int) error {
	if m.Hours != hours {
		return fmt.Errorf("%w: hours %d, asked for %d", errInfoInvalid, m.Hours, hours)
	}
	t, err := time.Parse(time.RFC3339Nano, m.GeneratedAt)
	if err != nil {
		return fmt.Errorf("%w: generated_at", errInfoInvalid)
	}
	m.GeneratedAt = t.UTC().Format(time.RFC3339)
	if m.Total.Attacks < 0 || len(m.Countries) > maxMapCountries || len(m.Categories) > maxMapCategories {
		return fmt.Errorf("%w: total or list sizes", errInfoInvalid)
	}
	seen := map[string]bool{}
	for _, c := range m.Countries {
		if !mapCountryCode.MatchString(c.Code) || c.Attacks < 0 || seen[c.Code] {
			return fmt.Errorf("%w: country %s", errInfoInvalid, shortQ(c.Code))
		}
		seen[c.Code] = true
	}
	clear(seen)
	for _, c := range m.Categories {
		if !mapCategory.MatchString(c.Cat) || c.Attacks < 0 || seen[c.Cat] {
			return fmt.Errorf("%w: category %s", errInfoInvalid, shortQ(c.Cat))
		}
		seen[c.Cat] = true
	}
	if m.Countries == nil {
		m.Countries = []MapCountry{}
	}
	if m.Categories == nil {
		m.Categories = []MapCategory{}
	}
	slices.SortStableFunc(m.Countries, func(a, b MapCountry) int { return cmp.Compare(b.Attacks, a.Attacks) })
	slices.SortStableFunc(m.Categories, func(a, b MapCategory) int { return cmp.Compare(b.Attacks, a.Attacks) })
	return nil
}

// SecurityScore is this server's security score (GET /api/v1/agent/score):
// the score with its grade, what takes points off, and the daily scores of
// the last 30 days.
type SecurityScore struct {
	GeneratedAt string       `json:"generated_at"`
	Score       int          `json:"score"`
	Grade       string       `json:"grade"`
	Items       []ScoreItem  `json:"items"`
	Trend       []ScorePoint `json:"trend"`
}

// ScoreItem is one finding that takes points off. Detail holds the counts
// the plugin words it with ({"failed":22,"total":43}).
type ScoreItem struct {
	Key    string         `json:"key"`
	Points int            `json:"points"`
	Detail map[string]any `json:"detail"`
}

type ScorePoint struct {
	Day   string `json:"day"` // YYYY-MM-DD
	Score int    `json:"score"`
}

const (
	maxScoreItems  = 32
	maxScoreTrend  = 62
	maxDetailKeys  = 16
	maxDetailList  = 64
	scoreGradeList = "ABCDEF"
)

var scoreKey = regexp.MustCompile(`^[a-z][a-z0-9_]{0,47}$`)

// SecurityScore asks the dashboard for this server's security score.
func (c *Client) SecurityScore(ctx context.Context) (*SecurityScore, error) {
	var s SecurityScore
	if err := c.getInfo(ctx, "/api/v1/agent/score", &s); err != nil {
		return nil, err
	}
	if err := s.check(); err != nil {
		return nil, err
	}
	return &s, nil
}

// check refuses an answer out of range and normalizes the rest:
// generated_at in UTC, items by points (most first), trend oldest first,
// details reduced to short text, numbers and lists of them.
func (s *SecurityScore) check() error {
	t, err := time.Parse(time.RFC3339Nano, s.GeneratedAt)
	if err != nil {
		return fmt.Errorf("%w: generated_at", errInfoInvalid)
	}
	s.GeneratedAt = t.UTC().Format(time.RFC3339)
	if s.Score < 0 || s.Score > 100 || len(s.Grade) != 1 || !strings.Contains(scoreGradeList, s.Grade) {
		return fmt.Errorf("%w: score %d, grade %s", errInfoInvalid, s.Score, shortQ(s.Grade))
	}
	if len(s.Items) > maxScoreItems || len(s.Trend) > maxScoreTrend {
		return fmt.Errorf("%w: list sizes", errInfoInvalid)
	}
	for i := range s.Items {
		it := &s.Items[i]
		if !scoreKey.MatchString(it.Key) || it.Points < 0 || it.Points > 100 {
			return fmt.Errorf("%w: item %s", errInfoInvalid, shortQ(it.Key))
		}
		d, ok := cleanDetail(it.Detail)
		if !ok {
			return fmt.Errorf("%w: detail of %s", errInfoInvalid, shortQ(it.Key))
		}
		it.Detail = d
	}
	for _, p := range s.Trend {
		if _, err := time.Parse(time.DateOnly, p.Day); err != nil || p.Score < 0 || p.Score > 100 {
			return fmt.Errorf("%w: trend day %s", errInfoInvalid, shortQ(p.Day))
		}
	}
	if s.Items == nil {
		s.Items = []ScoreItem{}
	}
	if s.Trend == nil {
		s.Trend = []ScorePoint{}
	}
	slices.SortStableFunc(s.Items, func(a, b ScoreItem) int { return cmp.Compare(b.Points, a.Points) })
	slices.SortStableFunc(s.Trend, func(a, b ScorePoint) int { return strings.Compare(a.Day, b.Day) })
	return nil
}

// cleanDetail keeps a detail object the plugin can show safely: at most
// maxDetailKeys keys, each a number, a boolean, null, short printable text,
// or a short list of numbers and text.
func cleanDetail(d map[string]any) (map[string]any, bool) {
	if d == nil {
		return map[string]any{}, true
	}
	if len(d) > maxDetailKeys {
		return nil, false
	}
	out := make(map[string]any, len(d))
	for k, v := range d {
		if !scoreKey.MatchString(k) {
			return nil, false
		}
		switch x := v.(type) {
		case nil, bool, float64:
			out[k] = x
		case string:
			t, ok := detailText(x)
			if !ok {
				return nil, false
			}
			out[k] = t
		case []any:
			if len(x) > maxDetailList {
				return nil, false
			}
			list := make([]any, len(x))
			for i, e := range x {
				switch y := e.(type) {
				case float64:
					list[i] = y
				case string:
					t, ok := detailText(y)
					if !ok {
						return nil, false
					}
					list[i] = t
				default:
					return nil, false
				}
			}
			out[k] = list
		default:
			return nil, false
		}
	}
	return out, true
}

// detailText: versions, names and the like. No markup characters, even
// though the plugins escape everything they show.
var detailTextRe = regexp.MustCompile(`^[A-Za-z0-9 ._:/@+,()-]{0,64}$`)

func detailText(s string) (string, bool) {
	return s, detailTextRe.MatchString(s)
}

// shortQ quotes a value from the dashboard for an error (and the log):
// at most 40 bytes of it.
func shortQ(v string) string {
	if len(v) > 40 {
		v = v[:40]
	}
	return strconv.Quote(v)
}
