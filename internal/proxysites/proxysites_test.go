package proxysites

import (
	"errors"
	"reflect"
	"strconv"
	"testing"

	"github.com/infrafence/infrafence-agent/internal/monitor"
)

// Labels as Coolify v4 writes them on an application container (Traefik
// proxy), trimmed of the unrelated ones.
var coolifyTraefik = map[string]string{
	"coolify.managed":                        "true",
	"coolify.applicationId":                  "3",
	"coolify.type":                           "application",
	"traefik.enable":                         "true",
	"traefik.http.middlewares.gzip.compress": "true",
	"traefik.http.middlewares.redirect-to-https.redirectscheme.scheme": "https",
	"traefik.http.routers.http-0-qk8s0o4.entryPoints":                  "http",
	"traefik.http.routers.http-0-qk8s0o4.middlewares":                  "redirect-to-https",
	"traefik.http.routers.http-0-qk8s0o4.rule":                         "Host(`shop.example.com`) && PathPrefix(`/`)",
	"traefik.http.routers.https-0-qk8s0o4.entryPoints":                 "https",
	"traefik.http.routers.https-0-qk8s0o4.rule":                        "Host(`shop.example.com`) && PathPrefix(`/`)",
	"traefik.http.routers.https-0-qk8s0o4.tls.certresolver":            "letsencrypt",
	"traefik.http.routers.https-1-qk8s0o4.rule":                        "Host(`www.shop.example.com`) && PathPrefix(`/`)",
	"traefik.http.services.https-0-qk8s0o4.loadbalancer.server.port":   "3000",
}

// The same application with the Caddy proxy (caddy-docker-proxy labels).
var coolifyCaddy = map[string]string{
	"coolify.managed":                     "true",
	"caddy_0":                             "https://blog.example.org",
	"caddy_0.encode":                      "zstd gzip",
	"caddy_0.handle_path":                 "/*",
	"caddy_0.handle_path.0_reverse_proxy": "{{upstreams 80}}",
	"caddy_0.header":                      "-Server",
	"caddy_1":                             "http://blog.example.org:80, https://news.example.org/app",
	"caddy_1.reverse_proxy":               "{{upstreams 80}}",
}

func TestTraefikHosts(t *testing.T) {
	cases := map[string][]string{
		"Host(`a.example.com`)":                                       {"a.example.com"},
		"Host(`a.example.com`) && PathPrefix(`/api`)":                 {"a.example.com"},
		"Host(`a.example.com`) || Host(`b.example.com`)":              {"a.example.com", "b.example.com"},
		"Host(`a.example.com`, `b.example.com`)":                      {"a.example.com", "b.example.com"},
		"(Host(\"a.example.com\") || HostHeader(`c.example.com`))":    {"a.example.com", "c.example.com"},
		"HostRegexp(`{sub:[a-z]+}.example.com`)":                      nil,
		"HostRegexp(`^.+\\.example\\.com$`) && Host(`d.example.com`)": {"d.example.com"},
		"Host(`a.example.com`) && !Host(`b.example.com`)":             {"a.example.com"},
		"PathPrefix(`/`)": nil,
		"HostSNI(`*`)":    nil,
	}
	for rule, want := range cases {
		if got := TraefikHosts(rule); !reflect.DeepEqual(got, want) {
			t.Errorf("TraefikHosts(%q) = %v, want %v", rule, got, want)
		}
	}
}

func TestCaddyHosts(t *testing.T) {
	cases := map[string][]string{
		"example.com": {"example.com"},
		"https://a.example.com, http://b.example.com:8080/x": {"a.example.com", "b.example.com"},
		"a.example.com b.example.com":                        {"a.example.com", "b.example.com"},
		"*.example.com":                                      nil,
		"{{upstreams 80}}":                                   nil,
		":80":                                                nil,
	}
	for v, want := range cases {
		if got := CaddyHosts(v); !reflect.DeepEqual(got, want) {
			t.Errorf("CaddyHosts(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestFromLabelsCoolify(t *testing.T) {
	got := FromLabels(coolifyTraefik)
	want := []Domain{{"shop.example.com", SourceTraefik}, {"www.shop.example.com", SourceTraefik}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("traefik: got %v, want %v", got, want)
	}
	got = FromLabels(coolifyCaddy)
	want = []Domain{{"blog.example.org", SourceCaddy}, {"news.example.org", SourceCaddy}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("caddy: got %v, want %v", got, want)
	}
}

func TestFromLabelsOther(t *testing.T) {
	// traefik.enable=false: Traefik ignores the routers, so do we.
	off := map[string]string{"traefik.enable": "false", "traefik.http.routers.x.rule": "Host(`a.example.com`)"}
	if got := FromLabels(off); got != nil {
		t.Errorf("traefik.enable=false: got %v", got)
	}
	// Label keys are case-insensitive for Traefik; infrafence.domain
	// adds to them; addresses, wildcards and junk are dropped.
	l := map[string]string{
		"traefik.http.routers.X.Rule": "Host(`A.Example.com.`)",
		"traefik.tcp.routers.db.rule": "HostSNI(`db.example.com`)",
		"infrafence.domain":           "a.example.com, c.example.com,10.0.0.1, *.example.com,",
	}
	want := []Domain{{"a.example.com", SourceTraefik}, {"c.example.com", SourceLabel}}
	if got := FromLabels(l); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	long := map[string]string{"caddy": "a.example.com " + string(make([]byte, maxLabel))}
	if got := FromLabels(long); got != nil {
		t.Errorf("oversized label: got %v", got)
	}
}

func TestFlavour(t *testing.T) {
	cases := map[string]string{
		"traefik:v3.7": "traefik",
		"docker.io/library/traefik:v2.11@sha256:abc": "traefik",
		"lucaslorentz/caddy-docker-proxy:2.9-alpine": "caddy",
		"caddy:2":    "caddy",
		"nginx:1.27": "",
		"registry.example.com:5000/traefik-tools/nginx": "",
		"ghcr.io/library/traefik:3":                     "traefik",
		"evil/caddy-nginx:1":                            "",
		"mytraefik-shop:latest":                         "",
	}
	for img, want := range cases {
		if got := Flavour(img); got != want {
			t.Errorf("Flavour(%q) = %q, want %q", img, got, want)
		}
	}
}

func TestCache(t *testing.T) {
	var fail bool
	cs := []monitor.DockerContainer{
		{ID: "p", Image: "traefik:v3.7", Labels: map[string]string{"traefik.enable": "true"}},
		{ID: "a", Image: "app", Labels: coolifyTraefik},
		{ID: "b", Image: "app", Labels: coolifyCaddy},
		{ID: "c", Image: "app", Labels: map[string]string{"caddy": "shop.example.com"}},
		{ID: "d", Image: "app", Labels: map[string]string{"infrafence.monitor": "false", "caddy": "hidden.example.com"}},
	}
	c := NewCache(func() ([]monitor.DockerContainer, error) {
		if fail {
			return nil, errors.New("daemon down")
		}
		return cs, nil
	})
	if c.Domains() != nil {
		t.Fatal("empty before the first refresh")
	}
	c.Refresh()
	want := []Domain{
		{"blog.example.org", SourceCaddy},
		{"news.example.org", SourceCaddy},
		{"shop.example.com", SourceTraefik},
		{"www.shop.example.com", SourceTraefik},
	}
	if got := c.Domains(); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if !c.Has("shop.example.com") || c.Has("hidden.example.com") {
		t.Error("Has")
	}
	fail = true
	c.Refresh()
	if got := c.Domains(); len(got) != 4 {
		t.Errorf("a failed listing keeps the last one, got %v", got)
	}
}

func TestFromContainersBounded(t *testing.T) {
	var cs []monitor.DockerContainer
	for i := 0; i < maxDomains+50; i++ {
		cs = append(cs, monitor.DockerContainer{Labels: map[string]string{
			"caddy": "s" + string(rune('a'+i%26)) + strconv.Itoa(i) + ".example.com",
		}})
	}
	if got := FromContainers(cs); len(got) != maxDomains {
		t.Errorf("got %d domains, want %d", len(got), maxDomains)
	}
	// One container with many names keeps perContainer; the next one is
	// still listed.
	big := map[string]string{}
	for i := range perContainer + 20 {
		big["caddy_"+strconv.Itoa(i)] = "a" + strconv.Itoa(i) + ".example.com"
	}
	got := FromContainers([]monitor.DockerContainer{{Labels: big}, {Labels: map[string]string{"caddy": "zz.example.com"}}})
	if len(got) != perContainer+1 || got[len(got)-1].Domain != "zz.example.com" {
		t.Errorf("per-container cap: %d domains, last %v", len(got), got[len(got)-1])
	}
}
