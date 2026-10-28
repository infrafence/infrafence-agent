package main

import (
	"encoding/json"
	"reflect"
	"strconv"
	"testing"

	"github.com/infrafence/infrafence-agent/internal/proxysites"
	"github.com/infrafence/infrafence-agent/internal/trust"
)

func TestHeartbeatDomains(t *testing.T) {
	got, err := json.Marshal(heartbeatDomains(
		[]string{"example.com", "shop.example.com"},
		[]proxysites.Domain{
			{Domain: "app.example.com", Source: proxysites.SourceTraefik},
			{Domain: "shop.example.com", Source: proxysites.SourceCaddy}, // has a host docroot
			{Domain: "tagged.example.com", Source: proxysites.SourceLabel},
		},
	))
	if err != nil {
		t.Fatal(err)
	}
	want := `["example.com","shop.example.com",` +
		`{"domain":"app.example.com","source":"traefik","verify":"dns"},` +
		`{"domain":"tagged.example.com","source":"label","verify":"dns"}]`
	if string(got) != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	// Old behaviour kept: no domain at all is omitted from the heartbeat.
	if got := heartbeatDomains(nil, nil); len(got) != 0 {
		t.Errorf("empty: %v", got)
	}
	var many []proxysites.Domain
	for i := range maxHeartbeatDomains + 10 {
		many = append(many, proxysites.Domain{Domain: "s" + strconv.Itoa(i) + ".example.com"})
	}
	if got := heartbeatDomains([]string{"a.example.com"}, many); len(got) > maxHeartbeatDomains {
		t.Errorf("%d entries, want at most %d", len(got), maxHeartbeatDomains)
	}
}

func TestTrustTokensContainerDomainIsDNSOnly(t *testing.T) {
	h := newTrustHarness(t)
	saved := trustProxied
	trustProxied = func(d string) bool { return d == "app.example.com" }
	t.Cleanup(func() { trustProxied = saved })
	h.sites = []trust.Site{{Names: []string{"example.com"}, Root: h.root(t, "example")}}

	applyTrustTokens(nil, tokens("app.example.com", trustTokA, "other.example.com", trustTokB))
	want := []string{
		"trust_token_failed app.example.com dns_only",
		"trust_token_failed other.example.com no_document_root",
	}
	if got := h.take(); !reflect.DeepEqual(got, want) {
		t.Fatalf("events %q\nwant %q", got, want)
	}
}
