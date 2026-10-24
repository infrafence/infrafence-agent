package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// GeoIPDownload is the dashboard's answer to DownloadGeoIP.
type GeoIPDownload struct {
	// NotModified: the agent's copy is current (304); nothing was written.
	NotModified bool
	// ETag is the database's tag: the SHA-256 of the file, in quotes.
	ETag string
	// Source names the database and its licence (X-Geoip-Source).
	Source string
	// Size is the number of bytes written.
	Size int64
}

var sha256ETag = regexp.MustCompile(`^"([0-9a-f]{64})"$`)

// DownloadGeoIP fetches the country database (GET /api/v1/agent/geoip)
// into w, at most maxBytes, unless the dashboard's tag is etag (304). When
// the tag is a SHA-256 the bytes must match it. ctx bounds the whole
// download.
func (c *Client) DownloadGeoIP(ctx context.Context, etag string, w io.Writer, maxBytes int64) (*GeoIPDownload, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/agent/geoip", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/octet-stream")
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("User-Agent", c.userAgent)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	resp, err := c.do(c.longClient, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	out := &GeoIPDownload{ETag: resp.Header.Get("ETag"), Source: resp.Header.Get("X-Geoip-Source")}
	switch {
	case resp.StatusCode == http.StatusNotModified:
		out.NotModified = true
		return out, nil
	case resp.StatusCode >= 400:
		return nil, c.statusErr(resp)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	if resp.ContentLength > maxBytes {
		return nil, fmt.Errorf("database too large (%d bytes)", resp.ContentLength)
	}

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(w, h), io.LimitReader(resp.Body, maxBytes+1))
	out.Size = n
	if err != nil {
		return nil, err
	}
	if n > maxBytes {
		return nil, fmt.Errorf("database larger than %d bytes", maxBytes)
	}
	if resp.ContentLength >= 0 && n != resp.ContentLength {
		return nil, fmt.Errorf("short download: %d of %d bytes", n, resp.ContentLength)
	}
	if m := sha256ETag.FindStringSubmatch(out.ETag); m != nil {
		if got := hex.EncodeToString(h.Sum(nil)); got != m[1] {
			return nil, fmt.Errorf("checksum mismatch: got %s, tag %s", got, m[1])
		}
	}
	return out, nil
}

// HTTPStatus returns the status of the dashboard's answer that err reports
// (0 for none: a network error, or a request not sent) and the wait it
// asked for.
func HTTPStatus(err error) (code int, retryAfter time.Duration) {
	var se *statusError
	if !errors.As(err, &se) || se.held {
		return 0, 0
	}
	return se.code, se.retryAfter
}

// ETagOf returns the tag the dashboard gives a file with these contents'
// SHA-256 (hex): the agent asks with it whether its copy is current.
func ETagOf(sumHex string) string {
	return `"` + strings.ToLower(sumHex) + `"`
}
