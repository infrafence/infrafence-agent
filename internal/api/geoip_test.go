package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestDownloadGeoIP(t *testing.T) {
	db := bytes.Repeat([]byte("mmdb"), 1000)
	sum := sha256.Sum256(db)
	tag := ETagOf(hex.EncodeToString(sum[:]))
	var body []byte
	var etagHeader string
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/geoip" || r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "unexpected", http.StatusBadRequest)
			return
		}
		if status != http.StatusOK {
			w.Header().Set("Retry-After", "600")
			http.Error(w, `{"error":"no database"}`, status)
			return
		}
		w.Header().Set("ETag", etagHeader)
		w.Header().Set("X-Geoip-Source", "DB-IP IP to Country Lite (CC BY 4.0)")
		if r.Header.Get("If-None-Match") == etagHeader {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	c := New(srv.URL, "tok")
	ctx := context.Background()

	body, etagHeader = db, tag
	var out bytes.Buffer
	d, err := c.DownloadGeoIP(ctx, "", &out, 1<<20)
	if err != nil || d.NotModified || !bytes.Equal(out.Bytes(), db) || d.ETag != tag || d.Size != int64(len(db)) {
		t.Fatalf("download: %+v %v", d, err)
	}

	out.Reset()
	if d, err := c.DownloadGeoIP(ctx, tag, &out, 1<<20); err != nil || !d.NotModified || out.Len() != 0 {
		t.Fatalf("304: %+v %v (%d bytes)", d, err, out.Len())
	}

	// The bytes must match the tag.
	etagHeader = ETagOf(hex.EncodeToString(make([]byte, 32)))
	if _, err := c.DownloadGeoIP(ctx, "", &out, 1<<20); err == nil {
		t.Fatal("a download that does not match its tag was accepted")
	}

	// Never more than maxBytes.
	etagHeader = tag
	if _, err := c.DownloadGeoIP(ctx, "", &out, 100); err == nil {
		t.Fatal("an oversized download was accepted")
	}

	// No database on the dashboard: the status and its Retry-After.
	status = http.StatusServiceUnavailable
	_, err = c.DownloadGeoIP(ctx, "", &out, 1<<20)
	if code, wait := HTTPStatus(err); code != 503 || wait != 10*time.Minute {
		t.Fatalf("503: code %d, wait %s (%v)", code, wait, err)
	}
	status = http.StatusTooManyRequests
	_, err = c.DownloadGeoIP(ctx, "", &out, 1<<20)
	if code, _ := HTTPStatus(err); code != 429 {
		t.Fatalf("429: code %d (%v)", code, err)
	}
}
