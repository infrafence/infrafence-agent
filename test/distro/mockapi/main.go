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
	"net/http"
	"os"
	"strings"
	"sync"
)

type state struct {
	mu         sync.Mutex
	Registered bool              `json:"registered"`
	Heartbeats int               `json:"heartbeats"`
	Syncs      int               `json:"syncs"`
	Bans       []json.RawMessage `json:"bans"`
	Events     []json.RawMessage `json:"events"`
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
	st := &state{}

	reply := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/releases/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sha256") {
			_, _ = io.WriteString(w, hex.EncodeToString(sum[:])+"  infrafence-agent\n")
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
		st.mu.Lock()
		st.Heartbeats++
		st.mu.Unlock()
		reply(w, map[string]any{"status": "ok"})
	})
	mux.HandleFunc("/api/v1/agent/sync", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		st.Syncs++
		st.mu.Unlock()
		reply(w, map[string]any{
			"status": "ok",
			"config": map[string]any{"bf_threshold": 5, "bf_window": 60, "monitor_mode": false},
			"rules":  []any{}, "bans": []any{}, "whitelists": []any{},
		})
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
	log.Fatal(http.ListenAndServe(*addr, mux))
}
