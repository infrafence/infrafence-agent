package main

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// serveDocker answers the Docker Engine API calls the agent makes, on a
// Unix socket, with the containers of a Coolify server: coolify-proxy
// (Traefik) and two applications, one with Coolify's Traefik labels and
// one with its Caddy labels (test/distro/coolify.sh). traefikLog is the
// proxy's access log as its command sets it: off (""), "file"
// (/traefik/access.log, /data/coolify/proxy mounted at /traefik) or
// "stdout", whose lines are those a real Traefik writes to traefikOut
// (test/distro/traefik.sh).
func serveDocker(sock, traefikLog, traefikOut string) {
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
	// Coolify's proxy command (/data/coolify/proxy/docker-compose.yml).
	args := []string{"--ping=true", "--ping.entrypoint=http", "--api.dashboard=true", "--entrypoints.http.address=:80",
		"--entrypoints.https.address=:443", "--providers.file.directory=/traefik/dynamic/", "--providers.file.watch=true",
		"--providers.docker=true", "--providers.docker.exposedbydefault=false"}
	switch traefikLog {
	case "file":
		args = append(args, "--accesslog=true", "--accesslog.format=json", "--accesslog.filepath=/traefik/access.log",
			"--accesslog.fields.headers.names.User-Agent=keep")
	case "stdout":
		args = append(args, "--accesslog=true")
	}
	inspect := map[string]any{
		"Id": "proxy0000001", "Name": "/coolify-proxy", "Path": "/entrypoint.sh", "Args": args,
		"Config": map[string]any{"Image": "traefik:v3.7", "Env": []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}, "Tty": false},
		"Mounts": []map[string]string{
			{"Type": "bind", "Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock"},
			{"Type": "bind", "Source": "/data/coolify/proxy", "Destination": "/traefik"},
		},
	}
	for _, n := range []string{"proxy0000001", "coolify-proxy"} {
		mux.HandleFunc("/containers/"+n+"/json", func(w http.ResponseWriter, _ *http.Request) { reply(w, inspect) })
		mux.HandleFunc("/containers/"+n+"/logs", func(w http.ResponseWriter, r *http.Request) {
			if traefikLog != "stdout" || r.URL.Query().Get("follow") != "1" {
				http.NotFound(w, r)
				return
			}
			followFile(w, r, traefikOut)
		})
	}
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

// followFile streams the lines appended to path from now on, framed as a
// non-TTY container's output (stdout frames), until the client goes away.
func followFile(w http.ResponseWriter, r *http.Request, path string) {
	f, err := os.Open(path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return
	}
	w.Header().Set("Content-Type", "application/vnd.docker.raw-stream")
	w.WriteHeader(http.StatusOK)
	fl, _ := w.(http.Flusher)
	if fl != nil {
		fl.Flush()
	}
	buf := make([]byte, 32<<10)
	var partial string
	for {
		select {
		case <-r.Context().Done():
			return
		case <-time.After(200 * time.Millisecond):
		}
		for {
			n, _ := f.Read(buf)
			if n == 0 {
				break
			}
			partial += string(buf[:n])
		}
		i := strings.LastIndexByte(partial, '\n')
		if i < 0 {
			continue
		}
		out := partial[:i+1]
		partial = partial[i+1:]
		h := make([]byte, 8)
		h[0] = 1
		binary.BigEndian.PutUint32(h[4:], uint32(len(out)))
		if _, err := w.Write(append(h, out...)); err != nil {
			return
		}
		if fl != nil {
			fl.Flush()
		}
	}
}
