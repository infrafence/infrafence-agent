package watcher

import (
	"encoding/json"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// Access log formats besides the combined format of nginx, Apache and
// LiteSpeed (parseAccessLog): Traefik (JSON and its default CLF-like
// format), Caddy (JSON) and HAProxy (option httplog). Each line is turned
// into the same accessLogEntry, so the same rules see every web server.

// Formats a line was parsed as (reported per source in the heartbeat).
const (
	formatCombined    = "combined"
	formatTraefikJSON = "traefik-json"
	formatTraefikCLF  = "traefik-clf"
	formatCaddyJSON   = "caddy-json"
	formatHAProxy     = "haproxy"
)

type parseResult int

const (
	parseFail parseResult = iota // not an access log line in a known format
	parseOK
	parseSkip // a known format's other output (a proxy's own log lines)
)

// parseLine parses an access log line of a source whose web server is
// server. A known server's log is parsed in that server's formats only, so
// a request cannot make its own line look like another format (a fake
// HAProxy line in a User-Agent, say); a log of an unknown server (a path
// given by hand) is tried in every format, the combined format last.
func parseLine(line, server string) (accessLogEntry, parseResult) {
	switch server {
	case "nginx", "apache", "litespeed":
		return parseCombined(line)
	case "haproxy":
		if e, ok := parseHAProxyLog(line); ok {
			return e, parseOK
		}
		return accessLogEntry{}, parseFail
	case "traefik", "caddy":
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "{") {
			e, r := parseJSONAccessLog(trimmed)
			if r == parseOK && e.format != map[string]string{"traefik": formatTraefikJSON, "caddy": formatCaddyJSON}[server] {
				return e, parseSkip
			}
			return e, r
		}
		if server == "traefik" {
			if e, ok := parseTraefikCLF(line); ok {
				return e, parseOK
			}
			return accessLogEntry{}, parseFail
		}
		// Caddy 1 and log transforms write the common log format.
		return parseCombined(line)
	}
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, "{") {
		return parseJSONAccessLog(trimmed)
	}
	if e, ok := parseHAProxyLog(line); ok {
		return e, parseOK
	}
	if e, ok := parseTraefikCLF(line); ok {
		return e, parseOK
	}
	return parseCombined(line)
}

func parseCombined(line string) (accessLogEntry, parseResult) {
	e, ok := parseAccessLog(line)
	if !ok {
		return e, parseFail
	}
	e.format = formatCombined
	return e, parseOK
}

// jsonAccessLine holds the fields of a Traefik or a Caddy JSON access log
// line that the rules use.
type jsonAccessLine struct {
	// Traefik (--accesslog.format=json). Request headers are logged only
	// when kept (--accesslog.fields.headers.names.<Name>=keep).
	ClientHost       string `json:"ClientHost"`
	ClientAddr       string `json:"ClientAddr"`
	RequestHost      string `json:"RequestHost"`
	RequestMethod    string `json:"RequestMethod"`
	RequestPath      string `json:"RequestPath"`
	DownstreamStatus int    `json:"DownstreamStatus"`
	DownstreamSize   int    `json:"DownstreamContentSize"`
	RouterName       string `json:"RouterName"`
	UserAgent        string `json:"request_User-Agent"`
	Referer          string `json:"request_Referer"`
	ForwardedFor     string `json:"request_X-Forwarded-For"`
	CFConnectingIP   string `json:"request_Cf-Connecting-Ip"`

	// Caddy (log directive, JSON encoder).
	Logger  string `json:"logger"`
	Request *struct {
		RemoteIP string              `json:"remote_ip"`
		ClientIP string              `json:"client_ip"`
		Host     string              `json:"host"`
		Method   string              `json:"method"`
		URI      string              `json:"uri"`
		Headers  map[string][]string `json:"headers"`
	} `json:"request"`
	Status int `json:"status"`
	Size   int `json:"size"`
}

func parseJSONAccessLog(line string) (accessLogEntry, parseResult) {
	var e accessLogEntry
	var j jsonAccessLine
	if err := json.Unmarshal([]byte(line), &j); err != nil {
		return e, parseFail
	}
	switch {
	case j.RequestPath != "" || j.ClientHost != "" || j.ClientAddr != "":
		e.format = formatTraefikJSON
		e.ip = j.ClientHost
		if e.ip == "" {
			e.ip = hostOnly(j.ClientAddr)
		}
		e.method = j.RequestMethod
		e.uri = j.RequestPath
		e.status = j.DownstreamStatus
		e.bodySize = j.DownstreamSize
		e.userAgent = j.UserAgent
		e.referer = j.Referer
		e.domain = hostOnly(j.RequestHost)
		e.forwardedFor = j.ForwardedFor
		e.cfConnectingIP = j.CFConnectingIP
		e.router = j.RouterName
	case j.Request != nil && strings.HasPrefix(j.Logger, "http.log.access"):
		r := j.Request
		e.format = formatCaddyJSON
		// client_ip is the client after Caddy's own trusted_proxies.
		e.ip = r.ClientIP
		if e.ip == "" {
			e.ip = r.RemoteIP
		}
		e.method = r.Method
		e.uri = r.URI
		e.status = j.Status
		e.bodySize = j.Size
		e.domain = hostOnly(r.Host)
		e.userAgent = firstHeader(r.Headers, "User-Agent")
		e.referer = firstHeader(r.Headers, "Referer")
		e.forwardedFor = strings.Join(r.Headers[http.CanonicalHeaderKey("X-Forwarded-For")], ",")
		e.cfConnectingIP = firstHeader(r.Headers, "Cf-Connecting-Ip")
	default:
		return e, parseSkip // the proxy's own log lines
	}
	e.ip = normIP(e.ip)
	if e.ip == "" || e.uri == "" {
		return e, parseSkip
	}
	return e, parseOK
}

func firstHeader(h map[string][]string, name string) string {
	if v := h[http.CanonicalHeaderKey(name)]; len(v) > 0 {
		return v[0]
	}
	for k, v := range h {
		if strings.EqualFold(k, name) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

// hostOnly removes a port (and IPv6 brackets) from host[:port].
func hostOnly(hp string) string {
	if h, _, err := net.SplitHostPort(hp); err == nil {
		return h
	}
	return strings.Trim(hp, "[]")
}

// normIP returns the address in its canonical form ("" when it is not an
// address); an IPv4-mapped IPv6 address becomes IPv4.
func normIP(s string) string {
	ip := net.ParseIP(strings.Trim(s, "[]"))
	if ip == nil {
		return ""
	}
	return ip.String()
}

// traefikCLFRe matches what Traefik's default format adds after the user
// agent: request count, router ("-" or name@provider), server URL and
// duration.
var traefikCLFRe = regexp.MustCompile(`^(.*") (\d+) "(-|[^"]*@[^"]*)" "([^"]*)" (\d+)ms$`)

// parseTraefikCLF parses Traefik's default access log format:
//
//	IP - USER [time] "METHOD PATH PROTO" STATUS SIZE "REFERER" "UA" COUNT "ROUTER" "SERVER" DURATIONms
func parseTraefikCLF(line string) (accessLogEntry, bool) {
	if !strings.HasSuffix(line, "ms") {
		return accessLogEntry{}, false
	}
	m := traefikCLFRe.FindStringSubmatch(line)
	if m == nil {
		return accessLogEntry{}, false
	}
	e, ok := parseAccessLog(m[1])
	if !ok {
		return e, false
	}
	e.format = formatTraefikCLF
	e.ip = normIP(e.ip)
	if m[3] != "-" {
		e.router = m[3]
	}
	return e, e.ip != ""
}

// haproxyRe matches an HAProxy HTTP log line (option httplog), with the
// syslog prefix rsyslog writes or without it (log stdout format raw):
//
//	[... haproxy[PID]: ]IP:PORT [date] FRONTEND BACKEND/SERVER TR/Tw/Tc/Tr/Ta STATUS BYTES ... "METHOD URI PROTO"
var haproxyRe = regexp.MustCompile(`^(?:(?:[A-Z][a-z]{2} +\d{1,2} \d\d:\d\d:\d\d|\d{4}-\d\d-\d\dT[0-9:.+Z-]+) \S+ haproxy\[\d+\]: )?([0-9A-Fa-f:.]+):(\d{1,5}) \[[0-9]{2}/[A-Za-z]{3}/[0-9]{4}:[^\]]*\] \S+ \S+ [-+0-9/]+ (-?\d+) \+?(\d+) .*"([A-Za-z]+) ([^ "]+)[^"]*"$`)

func parseHAProxyLog(line string) (accessLogEntry, bool) {
	var e accessLogEntry
	// Cheap test first. The line starts with the syslog header or the
	// client's address:port (never request data: the regexp is anchored).
	if !strings.Contains(line, "] ") || !strings.HasSuffix(line, `"`) {
		return e, false
	}
	m := haproxyRe.FindStringSubmatch(line)
	if m == nil {
		return e, false
	}
	e.format = formatHAProxy
	e.ip = normIP(m[1])
	e.status, _ = strconv.Atoi(m[3])
	e.bodySize, _ = strconv.Atoi(m[4])
	e.method = m[5]
	e.uri = m[6]
	// HTTP/2 requests are logged with the absolute URI.
	for _, scheme := range []string{"https://", "http://"} {
		if rest, ok := strings.CutPrefix(e.uri, scheme); ok {
			host, path, _ := strings.Cut(rest, "/")
			e.domain, e.uri = hostOnly(host), "/"+path
			break
		}
	}
	return e, e.ip != ""
}

// quotedFields returns the double-quoted strings of a log line (\" kept
// as is).
func quotedFields(line string) []string {
	var out []string
	for i := 0; i < len(line); i++ {
		if line[i] != '"' {
			continue
		}
		j := i + 1
		for j < len(line) && (line[j] != '"' || line[j-1] == '\\') {
			j++
		}
		if j >= len(line) {
			break
		}
		out = append(out, line[i+1:j])
		i = j
	}
	return out
}

// fixForwardedFor handles nginx's "main" format (the official Docker
// image's): combined plus a quoted X-Forwarded-For at the end, which
// parseAccessLog takes for the user agent.
func fixForwardedFor(e *accessLogEntry, line string) {
	q := quotedFields(line)
	if len(q) != 4 || !looksLikeAddrList(q[3]) {
		return
	}
	e.referer, e.userAgent, e.forwardedFor = q[1], q[2], q[3]
}

func looksLikeAddrList(s string) bool {
	if s == "-" {
		return true
	}
	for _, p := range strings.Split(s, ",") {
		if net.ParseIP(strings.TrimSpace(p)) == nil {
			return false
		}
	}
	return s != ""
}

// lastForwardedFor is the rightmost address of an X-Forwarded-For value:
// the one the proxy in front added itself (the ones before it are what the
// client claimed).
func lastForwardedFor(v string) string {
	if i := strings.LastIndexByte(v, ','); i >= 0 {
		v = v[i+1:]
	}
	return normIP(strings.TrimSpace(v))
}

// Cloudflare's published edge ranges (https://www.cloudflare.com/ips/). A
// request from one of them is a visitor's, relayed: the edge itself is
// never banned (that would cut off every visitor of the site), and the
// visitor is taken from CF-Connecting-IP, which only Cloudflare sets.
var cloudflareCIDRs = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
	"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
}

var (
	cloudflareNets     []*net.IPNet
	cloudflareNetsOnce sync.Once
)

func isCloudflareIP(s string) bool {
	cloudflareNetsOnce.Do(func() {
		for _, c := range cloudflareCIDRs {
			if _, n, err := net.ParseCIDR(c); err == nil {
				cloudflareNets = append(cloudflareNets, n)
			}
		}
	})
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	for _, n := range cloudflareNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
