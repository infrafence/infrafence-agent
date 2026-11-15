package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSyncRouter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/sync" || r.URL.Query().Get("kind") != "router" || r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "bad", 400)
			return
		}
		// An older dashboard: the server payload is skipped, not kept.
		_, _ = io.WriteString(w, `{"config":{"monitor_mode":true},"bans":[{"id":1,"ip_address":"203.0.113.7"}],"waf_rules":[{"id":1,"pattern":"x"}],
			"router":{"c2":[{"ip":"192.0.2.66","source":"feodo"}],"domain_list":{"url":"/api/v1/agent/router/domains","etag":"\"v1\"","count":2},"share_device_names":true}}`)
	}))
	defer srv.Close()
	c := New(srv.URL, "tok")
	s, err := c.SyncRouter()
	if err != nil {
		t.Fatal(err)
	}
	if !s.Config.MonitorMode || len(s.Bans) != 1 || s.Router == nil || len(s.Router.C2) != 1 || s.Router.DomainList.Count != 2 || !s.Router.ShareDeviceNames {
		t.Errorf("sync = %+v", s)
	}
}

func TestSyncRouterSkipsServerPayload(t *testing.T) {
	chunk := strings.Repeat(`{"id":1,"pattern":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx","nested":{"a":[1,2,{"b":"}"}]}},`, 1000)
	big := func(n int) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{"waf_rules":[`)
			for i := 0; i < n; i++ {
				_, _ = io.WriteString(w, chunk)
			}
			_, _ = io.WriteString(w, `{}],"config":{"monitor_mode":true},"bans":[{"id":1,"ip_address":"203.0.113.7"}],"malware_signatures":[]}`)
		}
	}
	// 8 MB of server payload: skipped, the router's fields still read.
	srv := httptest.NewServer(big(8 << 20 / len(chunk)))
	s, err := New(srv.URL, "tok").SyncRouter()
	srv.Close()
	if err != nil || !s.Config.MonitorMode || len(s.Bans) != 1 {
		t.Fatalf("sync = %+v, %v", s, err)
	}
	// Over the cap: refused.
	srv = httptest.NewServer(big(maxRouterSync/len(chunk) + 2))
	defer srv.Close()
	if _, err := New(srv.URL, "tok").SyncRouter(); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("err = %v", err)
	}
}

func TestRouterRequestsDoNotFollowRedirects(t *testing.T) {
	var leaked bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked = true
		}
		_, _ = io.WriteString(w, "{}")
	}))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	c := New(srv.URL, "tok")
	if _, err := c.SyncRouter(); err == nil {
		t.Error("sync followed a redirect")
	}
	if _, err := c.FetchDomainList(context.Background(), "/l", "", func(io.Reader) error { return nil }); err == nil {
		t.Error("list followed a redirect")
	}
	if err := c.ReportRouterDevices(RouterDevicesRequest{}); err == nil {
		t.Error("device report followed a redirect")
	}
	if leaked {
		t.Error("token sent to the redirect target")
	}
}

func TestFetchDomainListRefusesHTML(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html>captive portal</html>")
	}))
	defer srv.Close()
	if _, err := New(srv.URL, "tok").FetchDomainList(context.Background(), "/l", "", func(io.Reader) error { return nil }); err == nil {
		t.Error("html accepted")
	}
}

func TestDomainListURL(t *testing.T) {
	c := New("https://dash.example.com", "tok")
	for loc, want := range map[string]string{
		"/api/v1/agent/router/domains?v=2":                "https://dash.example.com/api/v1/agent/router/domains?v=2",
		"https://dash.example.com/api/v1/agent/router/dl": "https://dash.example.com/api/v1/agent/router/dl",
	} {
		if got, err := c.DomainListURL(loc); err != nil || got != want {
			t.Errorf("%s -> %s, %v", loc, got, err)
		}
	}
	for _, bad := range []string{"https://evil.example.net/list", "http://dash.example.com/list", "//evil.example.net/x", "https://user@dash.example.com/x"} {
		if _, err := c.DomainListURL(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestFetchDomainList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		_, _ = io.WriteString(w, "evil.example.com c2\n")
	}))
	defer srv.Close()
	c := New(srv.URL, "tok")
	var got string
	tag, err := c.FetchDomainList(context.Background(), "/l", "", func(r io.Reader) error {
		b, _ := io.ReadAll(r)
		got = string(b)
		return nil
	})
	if err != nil || tag != `"v1"` || got != "evil.example.com c2\n" {
		t.Errorf("fetch = %q %q %v", tag, got, err)
	}
	if _, err := c.FetchDomainList(context.Background(), "/l", `"v1"`, func(io.Reader) error { return nil }); !errors.Is(err, ErrNotModified) {
		t.Errorf("304: %v", err)
	}
}

func TestRegisterAndHeartbeatKind(t *testing.T) {
	// The server agent's bodies are unchanged: no kind, no router fields.
	b, _ := json.Marshal(RegisterRequest{Name: "x"})
	if strings.Contains(string(b), "kind") || strings.Contains(string(b), "capabilities") {
		t.Errorf("server register body: %s", b)
	}
	h, _ := json.Marshal(HeartbeatRequest{Status: "online"})
	if strings.Contains(string(h), "router_info") || strings.Contains(string(h), `"kind"`) {
		t.Errorf("server heartbeat body: %s", h)
	}
	b, _ = json.Marshal(RegisterRequest{Kind: AgentKindRouter, Capabilities: []string{"ip_bans"}})
	if !strings.Contains(string(b), `"kind":"router"`) {
		t.Errorf("router register body: %s", b)
	}
}

func TestRateLimited(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	c := New(srv.URL, "tok")
	_, err := c.FetchDomainList(context.Background(), "/l", "", func(io.Reader) error { return nil })
	if d, ok := RateLimited(err); !ok || d != 120*time.Second {
		t.Errorf("list: %v %v (%v)", d, ok, err)
	}
	err = c.ReportRouterDevices(RouterDevicesRequest{})
	if _, ok := RateLimited(err); !ok {
		t.Errorf("devices: %v", err)
	}
	// Not a refusal: the next request is sent.
	if wait := c.Gate().Wait(); wait != 0 {
		t.Errorf("gate holds requests after a 429: %v", wait)
	}
	if _, ok := RateLimited(errors.New("x")); ok {
		t.Error("plain error is a rate limit")
	}
}
