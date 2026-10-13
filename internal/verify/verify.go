// Package verify checks that a host change left the server reachable: every
// SSH port that accepted a connection before still does, and every site
// that answered without a server error, over HTTP and over HTTPS, still
// does. Callers take a Snapshot just before the change, Check (or
// CheckAfterReload, for changes that reload or restart a service) right
// after, and undo the change when the check fails.
//
// What it checks is limited to TCP reachability of the SSH ports and the
// HTTP status of the sites from localhost. It does NOT detect a change to
// SSH authentication: a server that still accepts connections on port 22
// but would now refuse the owner's login passes. For that reason the
// dashboard only automates hardening fixes that do not touch
// authentication; anything that does needs a person.
package verify

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// State is what the host looked like just before a change.
type State struct {
	SSH   map[int]bool   // port -> accepting a TCP connection on 127.0.0.1
	Sites map[string]int // domain -> HTTP status from localhost (Host header), -1 = no answer
	// SitesTLS is the same over HTTPS: a site that answered over HTTPS
	// before is checked over HTTPS again, so a broken certificate setup or
	// TLS vhost is not hidden by the plain HTTP answer (often a redirect).
	SitesTLS map[string]int
}

type Result struct {
	SSHOK   bool
	SitesOK bool
	Details string // short, human readable
}

// OK reports whether both checks passed.
func (r Result) OK() bool { return r.SSHOK && r.SitesOK }

const (
	probeTimeout = 3 * time.Second
	totalTimeout = 10 * time.Second

	// maxSites bounds the probes on hosts with hundreds of vhosts; the rest
	// are not checked.
	maxSites = 20
	workers  = 8
)

// Replaced in tests.
var (
	retryDelay = 2 * time.Second
	// settleTime is how long CheckAfterReload keeps probing a host whose
	// services are still coming back after a reload or restart.
	settleTime = 20 * time.Second
	sshAddr    = func(port int) string { return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) }
	httpBase   = map[string]string{"http": "http://127.0.0.1", "https": "https://127.0.0.1"}
)

// Snapshot probes SSH ports and sites with short timeouts (≤ 3 s each, ≤ 10 s total).
func Snapshot(ctx context.Context, sshPorts []int, domains []string) State {
	ctx, cancel := context.WithTimeout(ctx, totalTimeout)
	defer cancel()
	st := newState()
	for _, p := range sshPorts {
		if p > 0 && p < 65536 {
			st.SSH[p] = false
		}
	}
	for _, d := range validDomains(domains) {
		st.Sites[d] = -1
		st.SitesTLS[d] = -1
	}
	probeAll(ctx, &st)
	return st
}

func newState() State {
	return State{SSH: map[int]bool{}, Sites: map[string]int{}, SitesTLS: map[string]int{}}
}

// Check probes again (with one retry after 2 s) and compares with before: an SSH port that
// accepted before must accept now; a site that answered < 500 before must still answer < 500.
func Check(ctx context.Context, before State) Result {
	res := compare(ctx, before)
	if res.OK() {
		return res
	}
	select {
	case <-ctx.Done():
		return res
	case <-time.After(retryDelay):
	}
	return compare(ctx, before)
}

// CheckAfterReload is Check for changes that reload or restart a service
// (web server, sshd): the first probe is just as quick, but a failure is
// only final once the host still fails after up to 20 s of probing every
// 2 s, the time a service needs to come back.
func CheckAfterReload(ctx context.Context, before State) Result {
	deadline := time.Now().Add(settleTime)
	res := compare(ctx, before)
	for !res.OK() && time.Now().Add(retryDelay).Before(deadline) {
		select {
		case <-ctx.Done():
			return res
		case <-time.After(retryDelay):
		}
		res = compare(ctx, before)
	}
	return res
}

// compare probes only what was healthy before and reports what is not now.
func compare(ctx context.Context, before State) Result {
	ctx, cancel := context.WithTimeout(ctx, totalTimeout)
	defer cancel()
	now := newState()
	for p, ok := range before.SSH {
		if ok {
			now.SSH[p] = false
		}
	}
	for d, code := range before.Sites {
		if healthy(code) {
			now.Sites[d] = -1
		}
	}
	for d, code := range before.SitesTLS {
		if healthy(code) {
			now.SitesTLS[d] = -1
		}
	}
	probeAll(ctx, &now)

	res := Result{SSHOK: true, SitesOK: true}
	var bad []string
	for _, p := range sortedPorts(now.SSH) {
		if !now.SSH[p] {
			res.SSHOK = false
			bad = append(bad, fmt.Sprintf("ssh port %d not accepting", p))
		}
	}
	for _, s := range []struct {
		scheme      string
		now, before map[string]int
	}{{"http", now.Sites, before.Sites}, {"https", now.SitesTLS, before.SitesTLS}} {
		label := ""
		if s.scheme == "https" {
			label = " https"
		}
		for _, d := range sortedDomains(s.now) {
			if code := s.now[d]; !healthy(code) {
				res.SitesOK = false
				if code < 0 {
					bad = append(bad, fmt.Sprintf("%s%s no answer (was %d)", d, label, s.before[d]))
				} else {
					bad = append(bad, fmt.Sprintf("%s%s %d (was %d)", d, label, code, s.before[d]))
				}
			}
		}
	}
	if len(bad) == 0 {
		res.Details = fmt.Sprintf("ssh ok on %d port(s), %d site(s) ok", len(now.SSH), countSites(now))
	} else {
		res.Details = strings.Join(bad, "; ")
		if len(res.Details) > 500 {
			res.Details = res.Details[:500]
		}
	}
	return res
}

// countSites counts the domains checked over either scheme.
func countSites(st State) int {
	seen := map[string]bool{}
	for d := range st.Sites {
		seen[d] = true
	}
	for d := range st.SitesTLS {
		seen[d] = true
	}
	return len(seen)
}

func healthy(code int) bool { return code >= 0 && code < 500 }

// probeAll fills st in place, with at most `workers` probes at a time.
func probeAll(ctx context.Context, st *State) {
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)
	// Keys first: the workers write to the maps.
	ports := sortedPorts(st.SSH)
	for _, p := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ok := probeTCP(ctx, sshAddr(p))
			mu.Lock()
			st.SSH[p] = ok
			mu.Unlock()
		}(p)
	}
	for _, s := range []struct {
		scheme string
		m      map[string]int
	}{{"http", st.Sites}, {"https", st.SitesTLS}} {
		for _, d := range sortedDomains(s.m) {
			wg.Add(1)
			go func(scheme string, m map[string]int, d string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				code := probeSite(ctx, scheme, d)
				mu.Lock()
				m[d] = code
				mu.Unlock()
			}(s.scheme, s.m, d)
		}
	}
	wg.Wait()
}

func probeTCP(ctx context.Context, addr string) bool {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// probeSite asks the local web server for domain's home page over scheme.
// A redirect to the same site (relative, or the same host name over either
// scheme) is followed once, locally, so a redirect cannot hide a broken
// target; a redirect to another host keeps its 3xx status.
func probeSite(ctx context.Context, scheme, domain string) int {
	code, loc := probeURL(ctx, scheme, "/", domain)
	if code < 300 || code > 399 || loc == "" {
		return code
	}
	u, err := url.Parse(loc)
	if err != nil {
		return code
	}
	next := scheme
	if u.IsAbs() || u.Host != "" {
		if !strings.EqualFold(u.Hostname(), domain) {
			return code
		}
		if u.Scheme != "" {
			next = strings.ToLower(u.Scheme)
		}
	}
	if next != "http" && next != "https" {
		return code
	}
	path := u.EscapedPath()
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	code, _ = probeURL(ctx, next, path, domain)
	return code
}

// probeURL requests path on the local server for domain, without following
// redirects, and returns the status (-1 = no answer) and Location header.
func probeURL(ctx context.Context, scheme, path, domain string) (int, string) {
	base, ok := httpBase[scheme]
	if !ok {
		return -1, ""
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return -1, ""
	}
	req.Host = domain
	req.Header.Set("User-Agent", "InfraFence-verify")
	client := &http.Client{
		Transport: &http.Transport{
			// Local probe of the host's own certificate: only the status
			// matters, the name on the certificate is the site's, not 127.0.0.1.
			TLSClientConfig:   &tls.Config{ServerName: domain, InsecureSkipVerify: true},
			DisableKeepAlives: true,
			Proxy:             nil,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return -1, ""
	}
	resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("Location")
}

// validDomains keeps plain host names (no wildcards, ports or paths),
// deduplicated and sorted, at most maxSites of them.
func validDomains(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range in {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" || len(d) > 253 || seen[d] || !isHostname(d) {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	sort.Strings(out)
	if len(out) > maxSites {
		out = out[:maxSites]
	}
	return out
}

func isHostname(d string) bool {
	if !strings.Contains(d, ".") {
		return d == "localhost"
	}
	for _, r := range d {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.') {
			return false
		}
	}
	return !strings.HasPrefix(d, ".") && !strings.HasSuffix(d, ".")
}

func sortedPorts(m map[int]bool) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

func sortedDomains(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
