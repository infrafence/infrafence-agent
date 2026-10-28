package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
)

// serveDocker answers the Docker Engine API calls the agent makes, on a
// Unix socket, with the containers of a Coolify server: coolify-proxy
// (Traefik) and two applications, one with Coolify's Traefik labels and
// one with its Caddy labels (test/distro/coolify.sh).
func serveDocker(sock string) {
	containers := []map[string]any{
		{"Id": "proxy0000001", "Names": []string{"/coolify-proxy"}, "Image": "traefik:v3.7", "Labels": map[string]string{
			"coolify.managed": "true", "coolify.proxy": "true", "traefik.enable": "true",
			"traefik.http.routers.traefik.entrypoints": "http",
			"traefik.http.routers.traefik.service":     "api@internal",
		}},
		{"Id": "app000000001", "Names": []string{"/qk8s0o4-101530312345"}, "Image": "qk8s0o4:abc123", "Labels": map[string]string{
			"coolify.managed": "true", "coolify.type": "application", "traefik.enable": "true",
			"traefik.http.routers.http-0-qk8s0o4.entryPoints": "http",
			"traefik.http.routers.http-0-qk8s0o4.rule":        "Host(`shop.coolify-e2e.example.com`) && PathPrefix(`/`)",
			"traefik.http.routers.https-0-qk8s0o4.rule":       "Host(`shop.coolify-e2e.example.com`) && PathPrefix(`/`)",
			"traefik.http.routers.https-0-qk8s0o4.tls":        "true",
			"traefik.http.routers.https-1-qk8s0o4.rule":       "Host(`www.coolify-e2e.example.com`) || Host(`coolify-e2e.example.com`)",
			"traefik.http.routers.regex-qk8s0o4.rule":         "HostRegexp(`^.+\\.preview\\.example\\.com$`)",
		}},
		{"Id": "app000000002", "Names": []string{"/blog-x1"}, "Image": "ghost:5", "Labels": map[string]string{
			"coolify.managed":       "true",
			"caddy_0":               "https://blog.coolify-e2e.example.com",
			"caddy_0.encode":        "zstd gzip",
			"caddy_0.reverse_proxy": "{{upstreams 2368}}",
		}},
	}
	mux := http.NewServeMux()
	reply := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, _ *http.Request) { reply(w, containers) })
	mux.HandleFunc("/version", func(w http.ResponseWriter, _ *http.Request) {
		reply(w, map[string]string{"Version": "5.4.0"})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) })
	_ = os.Remove(sock)
	l, err := net.Listen("unix", sock)
	if err != nil {
		log.Fatalf("listen %s: %v", sock, err)
	}
	log.Printf("mock docker API on %s", sock)
	log.Fatal(http.Serve(l, mux))
}
