package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Router agent (cmd/infrafence-router, OpenWrt and GL.iNet): the parts of
// the protocol only it uses. Everything here is additive: the server agent
// never sends these fields, and an older dashboard ignores them.

// AgentKindRouter is the "kind" a router agent registers with.
const AgentKindRouter = "router"

// RouterInfo is the router state sent with every heartbeat (router_info).
type RouterInfo struct {
	Mode             string   `json:"mode"`             // "full" or "learning"
	Firewall         string   `json:"firewall"`         // "fw4", "fw3" or "none"
	FirewallBackend  string   `json:"firewall_backend"` // "nftables", "iptables" or "none" (detect only)
	FirewallOK       bool     `json:"firewall_ok"`      // our table/chains are in place
	FlowOffloading   bool     `json:"flow_offloading"`
	FlowOffloadingHW bool     `json:"flow_offloading_hw"`
	DNSCapture       bool     `json:"dns_capture"`
	DNSBlocking      string   `json:"dns_blocking"` // "active", "learning", "off", "unavailable"
	BlockedDomains   int      `json:"blocked_domains"`
	DomainListETag   string   `json:"domain_list_etag,omitempty"`
	C2Entries        int      `json:"c2_entries"`
	FeedEntries      int      `json:"feed_entries"`
	BanCapacity      int      `json:"ban_capacity"`
	DomainCapacity   int      `json:"domain_capacity"`
	LANDevices       int      `json:"lan_devices"`
	FlaggedDevices   int      `json:"flagged_devices"`
	Board            string   `json:"board,omitempty"`
	Model            string   `json:"model,omitempty"`
	Release          string   `json:"release,omitempty"` // e.g. "OpenWrt 24.10.8"
	Target           string   `json:"target,omitempty"`  // e.g. "ramips/mt7621"
	Arch             string   `json:"arch,omitempty"`    // package arch, e.g. "mipsel_24kc"
	PackageManager   string   `json:"package_manager,omitempty"`
	Vendor           string   `json:"vendor,omitempty"` // "openwrt" or "glinet"
	OverlayFree      uint64   `json:"overlay_free_bytes,omitempty"`
	Coexisting       []string `json:"coexisting,omitempty"` // other blockers found (adblock, banip, adguardhome...)
	Capabilities     []string `json:"capabilities"`
}

// RouterSyncResponse is the sync reply a router reads: the generic parts of
// SyncResponse plus the router block. It is a struct of its own so a large
// server-oriented reply (WAF rules, signatures) is never kept in memory on
// a 128 MB device: unknown fields are skipped while decoding.
type RouterSyncResponse struct {
	Config     SyncConfig       `json:"config"`
	Rules      []Rule           `json:"rules"`
	Bans       []Ban            `json:"bans"`
	Whitelists []WhitelistEntry `json:"whitelists"`
	ThreatFeed []ThreatEntry    `json:"threat_feed"`
	Router     *RouterSync      `json:"router,omitempty"`
}

// RouterSync is the router block of a sync (absent from older dashboards).
type RouterSync struct {
	// C2 are command-and-control / malware hosting addresses: LAN traffic to
	// them is reported (and dropped in Full protection).
	C2         []ThreatEntry `json:"c2"`
	DomainList *DomainList   `json:"domain_list,omitempty"`
	// Caps the dashboard sets per device; 0: the agent's own (from RAM).
	MaxBans    int `json:"max_bans,omitempty"`
	MaxDomains int `json:"max_domains,omitempty"`
	// ShareDeviceNames: the organization opted in to DHCP host names.
	ShareDeviceNames bool `json:"share_device_names,omitempty"`
}

// DomainList points at the blocked-domain list, downloaded on its own
// (never inside the sync JSON). URL is a path on the dashboard (or an
// absolute URL on the same origin); the ETag changes with the content.
type DomainList struct {
	URL   string `json:"url"`
	ETag  string `json:"etag"`
	Count int    `json:"count"`
}

// maxRouterSync bounds the bytes of a router's sync reply that are read.
// An older dashboard sends the server payload (WAF, signatures) too: it is
// skipped token by token, never held in memory, so only the router's own
// fields count against the router's RAM.
const maxRouterSync = 32 << 20

// routerHTTP is the HTTP client of the router-only requests: the shared
// transport, and no redirects (a redirect could carry the agent token to
// another host or over plain HTTP).
func (c *Client) routerHTTP(timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: c.transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func redirectErr(resp *http.Response) error {
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return fmt.Errorf("the dashboard answered %d (redirect): not followed", resp.StatusCode)
	}
	return nil
}

// SyncRouter fetches the sync as a router: kind=router asks the dashboard
// for the slim reply (older dashboards ignore it and send everything, of
// which only RouterSyncResponse's fields are decoded).
func (c *Client) SyncRouter() (*RouterSyncResponse, error) {
	req, err := http.NewRequest(http.MethodGet, c.baseURL+"/api/v1/agent/sync?kind="+AgentKindRouter, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("User-Agent", c.userAgent)
	resp, err := c.do(c.routerHTTP(60*time.Second), req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, c.statusErr(resp)
	}
	if err := redirectErr(resp); err != nil {
		return nil, err
	}
	lr := &io.LimitedReader{R: resp.Body, N: maxRouterSync + 1}
	out, err := decodeRouterSync(lr)
	if err != nil {
		if lr.N <= 0 {
			return nil, fmt.Errorf("sync reply larger than %d bytes", maxRouterSync)
		}
		return nil, err
	}
	return out, nil
}

// decodeRouterSync reads the top-level object key by key: the router's
// fields are decoded, every other value is skipped without being kept.
func decodeRouterSync(r io.Reader) (*RouterSyncResponse, error) {
	dec := json.NewDecoder(r)
	var out RouterSyncResponse
	if t, err := dec.Token(); err != nil {
		return nil, err
	} else if d, ok := t.(json.Delim); !ok || d != '{' {
		return nil, errors.New("sync reply is not a JSON object")
	}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, _ := t.(string)
		var dst any
		switch key {
		case "config":
			dst = &out.Config
		case "rules":
			dst = &out.Rules
		case "bans":
			dst = &out.Bans
		case "whitelists":
			dst = &out.Whitelists
		case "threat_feed":
			dst = &out.ThreatFeed
		case "router":
			dst = &out.Router
		}
		if dst != nil {
			if err := dec.Decode(dst); err != nil {
				return nil, fmt.Errorf("sync %s: %w", key, err)
			}
			continue
		}
		if err := skipValue(dec); err != nil {
			return nil, err
		}
	}
	return &out, nil
}

// skipValue consumes one JSON value token by token.
func skipValue(dec *json.Decoder) error {
	depth := 0
	for {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := t.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		}
		if depth == 0 {
			return nil
		}
	}
}

// MaxDomainListBytes bounds a domain list download (300 000 domains are
// about 9 MB).
const MaxDomainListBytes = 24 << 20

// ErrNotModified is returned by FetchDomainList when the list did not change.
var ErrNotModified = errors.New("not modified")

// DomainListURL resolves a domain list location against the dashboard. Only
// the dashboard's own origin is accepted: the request carries the agent
// token, which must never be sent elsewhere.
func (c *Client) DomainListURL(loc string) (string, error) {
	base, err := url.Parse(c.baseURL)
	if err != nil {
		return "", err
	}
	u, err := base.Parse(loc)
	if err != nil {
		return "", err
	}
	if u.Scheme != base.Scheme || !strings.EqualFold(u.Host, base.Host) || u.User != nil {
		return "", fmt.Errorf("domain list must be on the dashboard (%s://%s)", base.Scheme, base.Host)
	}
	return u.String(), nil
}

// FetchDomainList downloads the domain list at loc (see DomainListURL),
// streaming the body to fn. With etag set, a 304 returns ErrNotModified.
// The returned string is the reply's ETag.
func (c *Client) FetchDomainList(ctx context.Context, loc, etag string, fn func(io.Reader) error) (string, error) {
	u, err := c.DomainListURL(loc)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "text/plain")
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("User-Agent", c.userAgent)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	// No overall client timeout: a large list on a slow uplink can take
	// more than the 15 s of the API client; the context bounds it.
	resp, err := c.do(c.routerHTTP(0), req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return etag, ErrNotModified
	}
	if resp.StatusCode >= 400 {
		return "", c.statusErr(resp)
	}
	if err := redirectErr(resp); err != nil {
		return "", err
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "text/plain") && !strings.HasPrefix(ct, "application/octet-stream") {
		return "", fmt.Errorf("domain list has content type %q (a captive portal or proxy?)", ct)
	}
	if err := fn(io.LimitReader(resp.Body, MaxDomainListBytes)); err != nil {
		return "", err
	}
	return resp.Header.Get("ETag"), nil
}

// RouterDevice is one LAN device in the router's inventory. DeviceKey is an
// HMAC of the MAC address with a secret that never leaves the router: the
// dashboard can follow a device over time without learning its MAC. Name is
// the DHCP host name, sent only when the organization opted in.
type RouterDevice struct {
	DeviceKey string   `json:"device_key"`
	MACVendor string   `json:"mac_oui,omitempty"` // first three octets, e.g. "A4:83:E7"; empty for randomized MACs
	Random    bool     `json:"randomized_mac,omitempty"`
	IP        string   `json:"ip,omitempty"`
	IPv6      string   `json:"ipv6,omitempty"`
	Name      string   `json:"name,omitempty"`
	FirstSeen string   `json:"first_seen"`
	LastSeen  string   `json:"last_seen"`
	Flagged   bool     `json:"flagged,omitempty"`
	Findings  []string `json:"findings,omitempty"` // event types raised for it in the last 24 h
}

// RouterDevicesRequest is the body of /api/v1/agent/router-devices.
type RouterDevicesRequest struct {
	Devices   []RouterDevice `json:"devices"`
	Total     int            `json:"total"` // devices known, may exceed len(Devices)
	NamesSent bool           `json:"names_sent"`
	ScannedAt string         `json:"scanned_at"`
}

// ReportRouterDevices sends the LAN device inventory. A dashboard without
// the endpoint answers 404 (IsNotFound): the caller stops trying for a while.
func (c *Client) ReportRouterDevices(req RouterDevicesRequest) error {
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}
	hreq, err := http.NewRequest(http.MethodPost, c.baseURL+"/api/v1/agent/router-devices", bytes.NewReader(data))
	if err != nil {
		return err
	}
	hreq.Header.Set("Content-Type", "application/json")
	hreq.Header.Set("Accept", "application/json")
	hreq.Header.Set("Authorization", "Bearer "+c.token)
	hreq.Header.Set("User-Agent", c.userAgent)
	resp, err := c.do(c.routerHTTP(15*time.Second), hreq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode >= 400 {
		return c.statusErr(resp)
	}
	return redirectErr(resp)
}

// RateLimited reports a 429 reply and the wait it asked for (Retry-After;
// 0 when absent). A rate limit means "later": not an error to show, and
// not a refusal (the 401/403 back-off is not involved).
func RateLimited(err error) (time.Duration, bool) {
	var se *statusError
	if !errors.As(err, &se) || se.held || se.code != http.StatusTooManyRequests {
		return 0, false
	}
	return se.retryAfter, true
}
