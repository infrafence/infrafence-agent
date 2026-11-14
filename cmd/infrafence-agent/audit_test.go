package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/infrafence/infrafence-agent/internal/audit"
)

func TestParseAuditArgs(t *testing.T) {
	a, err := parseAuditArgs(nil)
	if err != nil || a.upload != audit.DefaultUploadURL || a.noUpload || a.json {
		t.Errorf("defaults: %+v %v", a, err)
	}
	a, err = parseAuditArgs([]string{"--no-upload", "--json"})
	if err != nil || !a.noUpload || !a.json {
		t.Errorf("%+v %v", a, err)
	}
	a, err = parseAuditArgs([]string{"--upload", "http://127.0.0.1:9999/api/v1/audit/report"})
	if err != nil || a.upload != "http://127.0.0.1:9999/api/v1/audit/report" {
		t.Errorf("%+v %v", a, err)
	}
	for _, bad := range [][]string{
		{"--upload"}, {"--upload", "http://infrafence.com/x"}, {"--upload", "https://x/", "--no-upload"}, {"--yes"},
	} {
		if _, err := parseAuditArgs(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestPauseBeforeUpload(t *testing.T) {
	var out strings.Builder
	if !pauseBeforeUpload(context.Background(), &out, 10*time.Millisecond) {
		t.Fatal("the wait ended without a cancel")
	}
	if !strings.Contains(out.String(), "press Ctrl+C to cancel (or run with --no-upload)") {
		t.Errorf("no notice: %q", out.String())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out.Reset()
	start := time.Now()
	if pauseBeforeUpload(ctx, &out, uploadWait) {
		t.Fatal("cancelled, yet the upload would go on")
	}
	if time.Since(start) > time.Second || !strings.Contains(out.String(), "Cancelled: nothing was sent.") {
		t.Errorf("cancel: %q after %s", out.String(), time.Since(start))
	}
	if !strings.Contains(out.String(), "Uploading in 5 s") {
		t.Errorf("notice %q", out.String())
	}
}
