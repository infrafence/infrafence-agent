package main

import (
	"sort"
	"strings"
)

// maxVerifyDomains bounds the sites checked after a host change.
const maxVerifyDomains = 20

// chooseVerifyDomains picks the sites the verifier checks after a host
// change: only names the web server configuration declares (ServerName,
// ServerAlias, server_name), the ones that also appear in the access logs
// first (they get traffic), at most maxVerifyDomains. A host seen only in
// the logs is not a configured site (a scanner's Host header, a stale
// name) and is never checked.
func chooseVerifyDomains(configured, logged []string) []string {
	norm := func(d string) string { return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".") }
	seenInLogs := map[string]bool{}
	for _, d := range logged {
		seenInLogs[norm(d)] = true
	}
	var busy, quiet []string
	seen := map[string]bool{}
	for _, d := range configured {
		d = norm(d)
		if d == "" || seen[d] || strings.ContainsAny(d, "*_ ") {
			continue
		}
		seen[d] = true
		if seenInLogs[d] {
			busy = append(busy, d)
		} else {
			quiet = append(quiet, d)
		}
	}
	sort.Strings(busy)
	sort.Strings(quiet)
	out := append(busy, quiet...)
	if len(out) > maxVerifyDomains {
		out = out[:maxVerifyDomains]
	}
	return out
}
