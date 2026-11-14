package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// DefaultUploadURL is the dashboard's audit endpoint.
const DefaultUploadURL = "https://infrafence.com/api/v1/audit/report"

const (
	uploadTimeout    = 20 * time.Second
	maxResponseBytes = 64 << 10
)

// UploadResult is the dashboard's answer (201).
type UploadResult struct {
	Token     string `json:"token"`
	URL       string `json:"url"`
	ExpiresAt string `json:"expires_at"`
}

var tokenRe = regexp.MustCompile(`^[0-9A-Za-z]{32,128}$`)

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// secureLink: https, or http to a loopback address.
func secureLink(u *url.URL) bool {
	return u.Scheme == "https" || (u.Scheme == "http" && loopback(u.Hostname()))
}

// CheckUploadURL accepts an https URL, or http to a loopback address (a
// local test of the endpoint).
func CheckUploadURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return nil, fmt.Errorf("invalid upload URL %q", raw)
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && loopback(u.Hostname()):
	default:
		return nil, fmt.Errorf("the upload URL must use https: %q", raw)
	}
	return u, nil
}

// Upload POSTs the report body to endpoint and returns the result link.
// It follows no redirect. The link must be on the endpoint's own site,
// with the token in its fragment.
func Upload(ctx context.Context, endpoint string, body []byte, version string) (UploadResult, error) {
	var res UploadResult
	u, err := CheckUploadURL(endpoint)
	if err != nil {
		return res, err
	}
	if len(body) > maxReportBytes {
		return res, fmt.Errorf("report is %d bytes (max %d)", len(body), maxReportBytes)
	}
	ctx, cancel := context.WithTimeout(ctx, uploadTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return res, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "infrafence-agent/"+version+" (audit)")
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return res, fmt.Errorf("upload failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return res, fmt.Errorf("reading the answer: %w", err)
	}
	if resp.StatusCode != http.StatusCreated {
		msg := clean(string(data))
		if len(msg) > 120 {
			msg = msg[:120]
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			return res, errors.New("too many reports from this address: try again in an hour, or use --no-upload")
		}
		return res, fmt.Errorf("the server answered %d: %s", resp.StatusCode, msg)
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return res, fmt.Errorf("unreadable answer: %w", err)
	}
	if !tokenRe.MatchString(res.Token) {
		return res, errors.New("the answer has no valid token")
	}
	link, err := url.Parse(res.URL)
	if err != nil || link.Host != u.Host || !secureLink(link) ||
		link.Fragment != res.Token || strings.ContainsAny(res.URL, " \t\r\n\x1b") {
		return res, fmt.Errorf("the answer's link is not on %s", u.Host)
	}
	res.ExpiresAt = clean(res.ExpiresAt)
	return res, nil
}
