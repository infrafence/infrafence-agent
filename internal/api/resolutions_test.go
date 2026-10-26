package api

import (
	"encoding/json"
	"testing"
)

func TestSyncResolutions(t *testing.T) {
	var top SyncResponse
	if err := json.Unmarshal([]byte(`{"config":{"resolutions":[{"subject":"file:/a","resolved_at":"2026-10-25T19:56:00Z","how":"marked_resolved"}]},
		"firewall_state":{"closed_ports":[],"egress_blocked":[]},
		"resolutions":[{"subject":"port:tcp/3306","resolved_at":"2026-10-25T19:56:00Z","how":"port_closed","by":"user"}]}`), &top); err != nil {
		t.Fatal(err)
	}
	if r := top.SyncResolutions(); len(r) != 1 || r[0].Subject != "port:tcp/3306" || r[0].How != "port_closed" || r[0].By != "user" {
		t.Fatalf("top level: %+v", r)
	}
	var inConfig SyncResponse
	json.Unmarshal([]byte(`{"config":{"resolutions":[{"subject":"file:/a","resolved_at":"2026-10-25T19:56:00Z","how":"marked_resolved"}]}}`), &inConfig)
	if r := inConfig.SyncResolutions(); len(r) != 1 || r[0].Subject != "file:/a" {
		t.Fatalf("fallback to config: %+v", r)
	}
	var none SyncResponse
	json.Unmarshal([]byte(`{"config":{}}`), &none)
	if r := none.SyncResolutions(); r != nil {
		t.Fatalf("none: %+v", r)
	}
	// An empty top-level list (nothing resolved) wins over config.
	var empty SyncResponse
	json.Unmarshal([]byte(`{"resolutions":[],"config":{"resolutions":[{"subject":"file:/a","resolved_at":"2026-10-25T19:56:00Z","how":"x"}]}}`), &empty)
	if r := empty.SyncResolutions(); r == nil || len(r) != 0 {
		t.Fatalf("empty: %+v", r)
	}
}
