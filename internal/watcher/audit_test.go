package watcher

import (
	"testing"
	"time"

	"github.com/infrafence/infrafence-agent/internal/netstate"
)

func TestSuspiciousRequest(t *testing.T) {
	for _, tc := range []struct {
		line, server, ip, kind string
	}{
		{`203.0.113.5 - - [13/Nov/2026:09:00:00 +0000] "GET /.env HTTP/1.1" 404 153 "-" "curl/8"`, "nginx", "203.0.113.5", "env_probe"},
		{`203.0.113.6 - - [13/Nov/2026:09:00:00 +0000] "GET /index.php?id=1%27%20or%20%271%27=%271 HTTP/1.1" 200 10 "-" "Mozilla"`, "apache", "203.0.113.6", "sql_injection"},
		{`203.0.113.7 - - [13/Nov/2026:09:00:00 +0000] "GET /cgi-bin/../../etc/passwd HTTP/1.1" 400 0 "-" "Mozilla"`, "", "203.0.113.7", "path_traversal"},
		{`203.0.113.8 - - [13/Nov/2026:09:00:00 +0000] "GET / HTTP/1.1" 200 10 "-" "sqlmap/1.7"`, "nginx", "203.0.113.8", "scanner_detected"},
		{`example.com 203.0.113.9 - - [13/Nov/2026:09:00:00 +0000] "GET /wp-config.php.bak HTTP/1.1" 404 0 "-" "x"`, "apache", "203.0.113.9", "config_probe"},
	} {
		ip, kind, ok := SuspiciousRequest(tc.line, tc.server)
		if !ok || ip != tc.ip || kind != tc.kind {
			t.Errorf("%s: %q %q %v, want %q %q", tc.line, ip, kind, ok, tc.ip, tc.kind)
		}
	}
	for _, line := range []string{
		`203.0.113.5 - - [13/Nov/2026:09:00:00 +0000] "GET /about HTTP/1.1" 200 10 "-" "Mozilla"`,
		`203.0.113.5 - - [13/Nov/2026:09:00:00 +0000] "GET /static/app.js?v=../ HTTP/1.1" 200 10 "-" "Mozilla"`,
		`10.0.0.5 - - [13/Nov/2026:09:00:00 +0000] "GET /.env HTTP/1.1" 404 10 "-" "Mozilla"`,
		`not a log line`,
	} {
		if ip, kind, ok := SuspiciousRequest(line, "nginx"); ok {
			t.Errorf("%s: matched %q %q", line, ip, kind)
		}
	}
}

func TestAccessLogTime(t *testing.T) {
	want := time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)
	for _, line := range []string{
		`203.0.113.5 - - [13/Nov/2026:10:00:00 +0100] "GET / HTTP/1.1" 200 1 "-" "x"`,
		`{"level":"info","ts":1794560400,"request":{"remote_ip":"203.0.113.5"}}`,
		`{"ClientHost":"203.0.113.5","StartUTC":"2026-11-13T09:00:00Z"}`,
		`{"time":"2026-11-13T09:00:00Z","remote_addr":"203.0.113.5"}`,
	} {
		got, ok := AccessLogTime(line)
		if !ok || !got.Equal(want) {
			t.Errorf("%s: %v %v", line, got, ok)
		}
	}
	if _, ok := AccessLogTime("garbage"); ok {
		t.Errorf("garbage has a time")
	}
}

func TestExposedPortList(t *testing.T) {
	got := exposedPorts([]netstate.Conn{listenSock("0.0.0.0", 9200)}, false, []PortService{{9200, "Elasticsearch"}, {6379, "Redis"}})
	if len(got) != 1 || got[0].Port != 9200 || got[0].Service != "Elasticsearch" {
		t.Errorf("%+v", got)
	}
}
