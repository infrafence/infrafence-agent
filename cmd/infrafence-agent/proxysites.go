package main

import (
	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/proxysites"
)

// Domains of the containers behind a reverse proxy (Coolify's
// coolify-proxy, Traefik, Caddy), from their labels: refreshed every
// proxysites.RefreshEvery, reported with each heartbeat and used by the
// trust badge sync (a container site has no document root on the host:
// its badge is verified with a DNS TXT record).
var proxyDomains = proxysites.NewCache(nil)

// maxHeartbeatDomains is what the dashboard keeps of monitored_domains.
const maxHeartbeatDomains = 500

// heartbeatDomains is monitored_domains: the web server and log domains
// as names, then each container domain not among them as an object
// {domain, source, verify: "dns"}.
func heartbeatDomains(static []string, proxied []proxysites.Domain) []any {
	out := make([]any, 0, len(static)+len(proxied))
	seen := make(map[string]bool, len(static))
	for _, d := range static {
		if len(out) == maxHeartbeatDomains {
			return out
		}
		seen[d] = true
		out = append(out, d)
	}
	for _, d := range proxied {
		if len(out) == maxHeartbeatDomains {
			break
		}
		if !seen[d.Domain] {
			seen[d.Domain] = true
			out = append(out, api.ProxyDomain{Domain: d.Domain, Source: d.Source, Verify: api.VerifyDNS})
		}
	}
	return out
}
