// Command mockapi is a stand-in for the InfraFence dashboard used by
// test/distro/run.sh: it serves the agent binary to install.sh, answers the
// agent API with a minimal configuration and records the bans and events the
// agent reports, which the test reads back from /state.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

type state struct {
	mu         sync.Mutex
	Registered bool `json:"registered"`
	Heartbeats int  `json:"heartbeats"`
	// LastHeartbeat is the body of the latest heartbeat.
	LastHeartbeat json.RawMessage `json:"last_heartbeat,omitempty"`
	Syncs         int             `json:"syncs"`
	// Denied counts the agent API calls refused while /deny is on.
	Denied int               `json:"denied"`
	Bans   []json.RawMessage `json:"bans"`
	Events []json.RawMessage `json:"events"`
	// InfoCalls counts the requests for the attack map ("map:24",
	// "map:168") and the security score ("score").
	InfoCalls map[string]int `json:"info_calls"`
	// extra holds fields set through /set-sync, merged into every sync
	// reply; version bumps on each change so the agent syncs again.
	extra   map[string]json.RawMessage
	version int
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	binary := flag.String("binary", "", "agent binary served at /releases/infrafence-agent-linux-<arch>")
	flag.Parse()

	bin, err := os.ReadFile(*binary)
	if err != nil {
		log.Fatalf("read binary: %v", err)
	}
	sum := sha256.Sum256(bin)
	st := &state{extra: map[string]json.RawMessage{}, InfoCalls: map[string]int{}}
	// offline: the agent API answers 503, as a dashboard that is down.
	var offline atomic.Bool
	// deny: the agent API refuses the agent, "suspended" (403
	// {"error":"suspended"}) or "unauthorized" (401); empty: off.
	var deny atomic.Value
	deny.Store("")

	reply := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}

	// Test control: /checksum?mode=missing (404) or mode=bad (another
	// file's) for the release checksum; mode=ok: the right one.
	var checksum atomic.Value
	checksum.Store("ok")
	mux := http.NewServeMux()
	mux.HandleFunc("/checksum", func(w http.ResponseWriter, r *http.Request) {
		checksum.Store(r.URL.Query().Get("mode"))
		reply(w, map[string]any{"status": "ok"})
	})
	mux.HandleFunc("/releases/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sha256") {
			switch checksum.Load() {
			case "missing":
				http.NotFound(w, r)
			case "bad":
				other := sha256.Sum256([]byte("not the agent"))
				_, _ = io.WriteString(w, hex.EncodeToString(other[:])+"  infrafence-agent\n")
			default:
				_, _ = io.WriteString(w, hex.EncodeToString(sum[:])+"  infrafence-agent\n")
			}
			return
		}
		_, _ = w.Write(bin)
	})
	mux.HandleFunc("/api/v1/agents/register", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		st.Registered = true
		st.mu.Unlock()
		reply(w, map[string]any{"token": "distro-test-token", "agent": map[string]any{"id": 1}})
	})
	mux.HandleFunc("/api/v1/agent/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		st.mu.Lock()
		st.Heartbeats++
		if json.Valid(body) {
			st.LastHeartbeat = body
		}
		version := st.version
		st.mu.Unlock()
		reply(w, map[string]any{"status": "ok", "config_version": strconv.Itoa(version)})
	})
	mux.HandleFunc("/api/v1/agent/sync", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		st.Syncs++
		out := map[string]any{
			"status": "ok",
			"config": map[string]any{"bf_threshold": 5, "bf_window": 60, "monitor_mode": false},
			"rules":  []any{}, "bans": []any{}, "whitelists": []any{},
		}
		for k, v := range st.extra {
			out[k] = v
		}
		st.mu.Unlock()
		reply(w, out)
	})
	// Test control: top-level keys of the posted object replace those of the
	// sync reply (null removes one; send the whole "config" to change it).
	mux.HandleFunc("/set-sync", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		st.mu.Lock()
		for k, v := range body {
			if string(v) == "null" {
				delete(st.extra, k)
			} else {
				st.extra[k] = v
			}
		}
		st.version++
		st.mu.Unlock()
		reply(w, map[string]any{"status": "ok"})
	})
	// Test control: /offline?on=1 makes every agent API call fail with 503
	// until /offline?on=0.
	mux.HandleFunc("/offline", func(w http.ResponseWriter, r *http.Request) {
		offline.Store(r.URL.Query().Get("on") == "1")
		reply(w, map[string]any{"status": "ok", "offline": offline.Load()})
	})
	// Test control: /deny?mode=suspended (403 {"error":"suspended"}) or
	// /deny?mode=unauthorized (401) refuses every agent API call until
	// /deny?mode=off.
	mux.HandleFunc("/deny", func(w http.ResponseWriter, r *http.Request) {
		mode := r.URL.Query().Get("mode")
		if mode == "off" {
			mode = ""
		}
		deny.Store(mode)
		reply(w, map[string]any{"status": "ok", "deny": mode})
	})
	// Test control: listen on a TCP port (accept and close), for the
	// close_port / block_egress cases.
	mux.HandleFunc("/listen", func(w http.ResponseWriter, r *http.Request) {
		ln, err := net.Listen("tcp", r.URL.Query().Get("addr"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
		reply(w, map[string]any{"status": "ok"})
	})
	mux.HandleFunc("/api/v1/agent/bans", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		st.mu.Lock()
		st.Bans = append(st.Bans, body)
		st.mu.Unlock()
		reply(w, map[string]any{"status": "ok", "id": len(st.Bans)})
	})
	mux.HandleFunc("/api/v1/agent/events", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Events []json.RawMessage `json:"events"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		st.mu.Lock()
		st.Events = append(st.Events, body.Events...)
		st.mu.Unlock()
		reply(w, map[string]any{"status": "ok"})
	})
	// The attack map and the security score of "panel map" and "panel
	// score"; /info-down?on=1 answers 404 (a dashboard without them).
	var infoDown atomic.Bool
	mux.HandleFunc("/info-down", func(w http.ResponseWriter, r *http.Request) {
		infoDown.Store(r.URL.Query().Get("on") == "1")
		reply(w, map[string]any{"status": "ok"})
	})
	info := func(key string, body any) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			k := key
			if key == "map" {
				k = "map:" + r.URL.Query().Get("hours")
			}
			st.mu.Lock()
			st.InfoCalls[k]++
			st.mu.Unlock()
			if infoDown.Load() {
				http.NotFound(w, r)
				return
			}
			if key == "map" {
				h := 24
				if r.URL.Query().Get("hours") == "168" {
					h = 168
				}
				b := maps.Clone(body.(map[string]any))
				b["hours"] = h
				reply(w, b)
				return
			}
			reply(w, body)
		}
	}
	mux.HandleFunc("/api/v1/agent/map", info("map", map[string]any{"generated_at": "2026-10-24T10:00:00Z",
		"total":      map[string]any{"attacks": 123},
		"countries":  []any{map[string]any{"code": "CN", "attacks": 40}, map[string]any{"code": "US", "attacks": 12}},
		"categories": []any{map[string]any{"cat": "ssh", "attacks": 30}, map[string]any{"cat": "web", "attacks": 5}}}))
	mux.HandleFunc("/api/v1/agent/score", info("score", map[string]any{"generated_at": "2026-10-24T10:00:00Z",
		"score": 72, "grade": "C",
		"items": []any{map[string]any{"key": "hardening", "points": 12, "detail": map[string]any{"failed": 22, "total": 43}}},
		"trend": []any{map[string]any{"day": "2026-10-20", "score": 70}, map[string]any{"day": "2026-10-24", "score": 72}}}))
	mux.HandleFunc("/state", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		reply(w, st)
	})
	// Everything else the agent posts (metrics, scans, audits...): accepted.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		reply(w, map[string]any{"status": "ok"})
	})

	log.Printf("mockapi listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if offline.Load() && strings.HasPrefix(r.URL.Path, "/api/") {
			http.Error(w, "offline", http.StatusServiceUnavailable)
			return
		}
		if mode := deny.Load().(string); mode != "" && strings.HasPrefix(r.URL.Path, "/api/") {
			_, _ = io.Copy(io.Discard, r.Body)
			st.mu.Lock()
			st.Denied++
			st.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			if mode == "unauthorized" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = io.WriteString(w, `{"message":"Unauthenticated."}`)
				return
			}
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"error":"suspended"}`)
			return
		}
		mux.ServeHTTP(w, r)
	})))
}
