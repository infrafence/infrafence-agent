package watcher

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/infrafence/infrafence-agent/internal/monitor"
	"github.com/infrafence/infrafence-agent/internal/proxysites"
)

// Web logs that are not a file a host web server writes: reverse proxies
// in containers (Traefik, Caddy: Coolify, Dokploy and plain setups) and
// web servers in containers that log to their output (the official nginx,
// httpd, Caddy and WordPress images). Everything is read through the
// Docker (or Podman) API, read only: inspect, and the container's output
// as `docker logs -f` gives it. Nothing is changed in a container or in a
// proxy's configuration; when a proxy's access log is off, the agent says
// what to add and how.

// containerLogPrefix marks a source that is a container's output, not a
// file: "docker://<container name>".
const containerLogPrefix = "docker://"

const (
	// maxContainerSources bounds the containers whose output is followed.
	maxContainerSources = 20
	// maxProxyConfig bounds a Traefik static configuration file read.
	maxProxyConfig = 1 << 20
)

// Hint reasons.
const (
	HintAccessLogOff  = "access_log_off"   // the proxy writes no access log
	HintLogNotOnHost  = "log_not_on_host"  // it writes a file no mount shows on the host
	HintLogFileAbsent = "log_file_missing" // the file is configured but not there (yet)
)

// WebLogHint is a web server whose requests are not seen, and what to
// change in its configuration so they are.
type WebLogHint struct {
	Server    string `json:"server"`
	Container string `json:"container,omitempty"`
	Reason    string `json:"reason"`
	// Platform is "coolify" when the proxy is Coolify's (its settings are
	// then changed in Coolify: Servers > server > Proxy > Configuration).
	Platform string `json:"platform,omitempty"`
	// Path is the configured log file (inside the container).
	Path     string   `json:"path,omitempty"`
	Settings []string `json:"settings,omitempty"`
}

// WebLogSource is one access log being read.
type WebLogSource struct {
	Server    string `json:"server,omitempty"`
	Format    string `json:"format,omitempty"` // of the last line parsed; "" before the first
	Path      string `json:"path,omitempty"`
	Container string `json:"container,omitempty"`
	Requests  uint64 `json:"requests"` // parsed since the agent started
}

// WebDetection is what the heartbeat reports about web attack detection:
// "on" with the logs read, or "off"; Hints lists the web servers whose
// requests are not seen, either way.
type WebDetection struct {
	State   string         `json:"state"`
	Sources []WebLogSource `json:"sources,omitempty"`
	Hints   []WebLogHint   `json:"hints,omitempty"`
}

// maxReportedSources bounds the heartbeat's list.
const maxReportedSources = 50

var (
	dockerStateMu sync.Mutex
	// webLogHints: the last detection's hints.
	webLogHints []WebLogHint
	// loggedHints: hints already logged (each is logged once while it lasts).
	loggedHints = map[string]bool{}
	// routerHosts: Traefik router name -> its first host, from the
	// containers' labels (Traefik's default format logs the router, not the
	// host).
	routerHosts = map[string]string{}
	// lastDockerSources: the last detection's sources, kept when the Docker
	// API fails (a daemon restart must not stop the reading).
	lastDockerSources []LogPathInfo
)

// CurrentWebLogHints returns the last detection's hints.
func CurrentWebLogHints() []WebLogHint {
	dockerStateMu.Lock()
	defer dockerStateMu.Unlock()
	return append([]WebLogHint(nil), webLogHints...)
}

func setDockerState(hints []WebLogHint, routers map[string]string) {
	dockerStateMu.Lock()
	defer dockerStateMu.Unlock()
	webLogHints = hints
	routerHosts = routers
	now := map[string]bool{}
	for _, h := range hints {
		k := h.Container + "|" + h.Reason + "|" + h.Path
		now[k] = true
		if !loggedHints[k] {
			logHint(h)
		}
	}
	loggedHints = now
}

func routerHost(router string) string {
	if router == "" {
		return ""
	}
	if i := strings.LastIndexByte(router, '@'); i > 0 {
		router = router[:i]
	}
	dockerStateMu.Lock()
	defer dockerStateMu.Unlock()
	return routerHosts[router]
}

func logHint(h WebLogHint) {
	switch h.Reason {
	case HintAccessLogOff:
		log.Printf("[webwatcher] docker: %s is a %s proxy with its access log off: web attack detection cannot see the requests to its sites", h.Container, h.Server)
	case HintLogNotOnHost:
		log.Printf("[webwatcher] docker: %s writes its access log to %s, which no mount shows on the host", h.Container, h.Path)
	case HintLogFileAbsent:
		log.Printf("[webwatcher] docker: %s writes its access log to %s, not there yet (checked again every 5 minutes)", h.Container, h.Path)
	}
	if len(h.Settings) == 0 {
		return
	}
	if h.Platform == "coolify" {
		log.Printf("[webwatcher] hint: in Coolify, Servers > (this server) > Proxy > Configuration, add these lines to the command of the proxy, save and restart the proxy:")
	} else {
		log.Printf("[webwatcher] hint: add these arguments to the %s container's command and recreate it:", h.Server)
	}
	for _, s := range h.Settings {
		log.Printf("[webwatcher]   - %s", s)
	}
	log.Printf("[webwatcher] InfraFence only reads the log; it never changes the proxy's configuration")
}

// coolifyTraefikSettings: Coolify mounts /data/coolify/proxy at /traefik,
// so the file is /data/coolify/proxy/access.log on the host.
var coolifyTraefikSettings = []string{
	"--accesslog=true",
	"--accesslog.format=json",
	"--accesslog.filepath=/traefik/access.log",
	"--accesslog.fields.headers.names.User-Agent=keep",
}

// traefikStdoutSettings: anywhere else, the agent reads the log from the
// container's output.
var traefikStdoutSettings = []string{
	"--accesslog=true",
	"--accesslog.format=json",
	"--accesslog.fields.headers.names.User-Agent=keep",
}

// traefikAccessLog is a Traefik access log configuration.
type traefikAccessLog struct {
	Enabled  bool
	FilePath string // "" = the container's output
	Format   string
}

// traefikConfigFromArgs reads the access log settings from Traefik's
// command line (--accesslog, --accesslog.filepath=..., any other
// --accesslog.* option, which turns the section on too). ok: the command
// line configures Traefik at all (it has a --flag).
func traefikConfigFromArgs(args []string) (cfg traefikAccessLog, ok bool) {
	explicitOff := false
	sub := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			continue
		}
		ok = true
		key, val, hasVal := strings.Cut(strings.TrimLeft(a, "-"), "=")
		key = strings.ToLower(key)
		if key != "accesslog" && !strings.HasPrefix(key, "accesslog.") {
			continue
		}
		if !hasVal && key != "accesslog" && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			val, hasVal = args[i+1], true
			i++
		}
		switch key {
		case "accesslog":
			on := true
			if hasVal {
				on, _ = strconv.ParseBool(val)
			}
			cfg.Enabled, explicitOff = on, !on
		case "accesslog.filepath":
			cfg.FilePath, sub = val, true
		case "accesslog.format":
			cfg.Format, sub = strings.ToLower(val), true
		default:
			sub = true
		}
	}
	if sub && !explicitOff {
		cfg.Enabled = true
	}
	return cfg, ok
}

// traefikConfigFromEnv reads TRAEFIK_ACCESSLOG* variables.
func traefikConfigFromEnv(env []string) (cfg traefikAccessLog, ok bool) {
	explicitOff, sub := false, false
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		k = strings.ToUpper(k)
		if !strings.HasPrefix(k, "TRAEFIK_") {
			continue
		}
		ok = true
		switch {
		case k == "TRAEFIK_ACCESSLOG":
			on, _ := strconv.ParseBool(v)
			cfg.Enabled, explicitOff = on, !on
		case k == "TRAEFIK_ACCESSLOG_FILEPATH":
			cfg.FilePath, sub = v, true
		case k == "TRAEFIK_ACCESSLOG_FORMAT":
			cfg.Format, sub = strings.ToLower(v), true
		case strings.HasPrefix(k, "TRAEFIK_ACCESSLOG_"):
			sub = true
		}
	}
	if sub && !explicitOff {
		cfg.Enabled = true
	}
	return cfg, ok
}

var (
	yamlSectionRe = regexp.MustCompile(`^([A-Za-z]\w*)\s*:\s*(#.*)?$`)
	yamlKeyRe     = regexp.MustCompile(`^\s+(filePath|format)\s*:\s*["']?([^"'#\s]+)["']?`)
	tomlSectionRe = regexp.MustCompile(`^\s*\[([A-Za-z][\w.]*)\]`)
	tomlKeyRe     = regexp.MustCompile(`^\s*(filePath|format)\s*=\s*["']([^"']*)["']`)
)

// traefikConfigFromFile reads the accessLog section of a Traefik static
// configuration file (YAML or TOML; only filePath and format matter).
func traefikConfigFromFile(content string, toml bool) traefikAccessLog {
	var cfg traefikAccessLog
	in := false
	sc := bufio.NewScanner(strings.NewReader(content))
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	for sc.Scan() {
		line := sc.Text()
		if toml {
			if m := tomlSectionRe.FindStringSubmatch(line); m != nil {
				in = strings.EqualFold(m[1], "accessLog") || strings.HasPrefix(strings.ToLower(m[1]), "accesslog.")
				if in {
					cfg.Enabled = true
				}
				continue
			}
			if m := tomlKeyRe.FindStringSubmatch(line); in && m != nil {
				setTraefikKey(&cfg, m[1], m[2])
			}
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "---") {
			continue
		}
		if m := yamlSectionRe.FindStringSubmatch(line); m != nil {
			in = strings.EqualFold(m[1], "accessLog")
			if in {
				cfg.Enabled = true
			}
			continue
		}
		if strings.TrimSpace(line) != "" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			in = false // another top-level key (accessLog: {} or a scalar)
			if strings.HasPrefix(strings.ToLower(line), "accesslog:") {
				cfg.Enabled = true
			}
			continue
		}
		if m := yamlKeyRe.FindStringSubmatch(line); in && m != nil {
			setTraefikKey(&cfg, m[1], m[2])
		}
	}
	return cfg
}

func setTraefikKey(cfg *traefikAccessLog, k, v string) {
	if k == "filePath" {
		cfg.FilePath = v
	} else {
		cfg.Format = strings.ToLower(v)
	}
}

// traefikConfigFile returns the static configuration file a Traefik
// container uses, as a host path ("" for none): --configfile, or one of
// Traefik's default locations, through the container's mounts.
func traefikConfigFile(args []string, mounts map[string]string) string {
	candidates := []string{"/etc/traefik/traefik.yml", "/etc/traefik/traefik.yaml", "/etc/traefik/traefik.toml",
		"/traefik.yml", "/traefik.yaml", "/traefik.toml"}
	for i, a := range args {
		key, val, hasVal := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if strings.HasPrefix(a, "-") && strings.EqualFold(key, "configfile") {
			if !hasVal && i+1 < len(args) {
				val = args[i+1]
			}
			candidates = []string{val}
			break
		}
	}
	for _, c := range candidates {
		if h := hostPathInMount(c, mounts); h != "" {
			return h
		}
	}
	return ""
}

// hostPathInMount is the host file a container path is, through the
// container's mounts: "" when no mount shows it, when it is not a regular
// file, or when it leaves the mount (.., or a symlink pointing out of it:
// the container's owner chooses these paths, the agent reads as root).
func hostPathInMount(containerPath string, mounts map[string]string) string {
	if !filepath.IsAbs(containerPath) || strings.Contains(containerPath, "..") {
		return ""
	}
	h := resolveDockerMount(filepath.Clean(containerPath), mounts)
	if h == "" {
		return ""
	}
	real, err := filepath.EvalSymlinks(h)
	if err != nil {
		return ""
	}
	inside := false
	for _, src := range mounts {
		rs, err := filepath.EvalSymlinks(src)
		if err != nil {
			continue
		}
		if rel, err := filepath.Rel(rs, real); err == nil && rel != ".." && !strings.HasPrefix(rel, "../") {
			inside = true
			break
		}
	}
	if fi, err := os.Stat(real); !inside || err != nil || !fi.Mode().IsRegular() {
		return ""
	}
	return real
}

// traefikAccessLogOf works out a Traefik container's access log the way
// Traefik does: a configuration file when there is one, else the command
// line, else the environment.
func traefikAccessLogOf(d *monitor.ContainerDetails, mounts map[string]string) traefikAccessLog {
	if f := traefikConfigFile(d.Args, mounts); f != "" {
		if data, err := readBounded(f, maxProxyConfig); err == nil {
			return traefikConfigFromFile(string(data), strings.HasSuffix(f, ".toml"))
		}
	}
	if cfg, ok := traefikConfigFromArgs(d.Args); ok {
		return cfg
	}
	cfg, _ := traefikConfigFromEnv(d.Env)
	return cfg
}

func readBounded(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%s: larger than %d bytes", path, max)
	}
	return data, nil
}

func mountMap(ms []monitor.DockerMount) map[string]string {
	m := make(map[string]string, len(ms))
	for _, x := range ms {
		m[x.Destination] = x.Source
	}
	return m
}

func containerName(c monitor.DockerContainer) string {
	if len(c.Names) > 0 {
		return strings.TrimPrefix(c.Names[0], "/")
	}
	if len(c.ID) > 12 {
		return c.ID[:12]
	}
	return c.ID
}

func monitorDisabled(labels map[string]string) bool {
	v := strings.ToLower(labels["infrafence.monitor"])
	return v == "false" || v == "0" || v == "no"
}

func containerIPs(c monitor.DockerContainer) []string {
	var out []string
	for _, n := range c.NetworkSettings.Networks {
		for _, a := range []string{n.IPAddress, n.GlobalIPv6Address} {
			if ip := normIP(a); ip != "" {
				out = append(out, ip)
			}
		}
	}
	return out
}

// webServerOfImage is the web server an image runs, when it is one that
// logs requests to its output: "nginx", "apache", "litespeed" or "".
func webServerOfImage(image string) string {
	// The repository's last part and the tag: an image merely named after a
	// web server (apache/superset, apache/airflow) runs another program.
	im := strings.ToLower(image)
	if i := strings.IndexByte(im, '@'); i >= 0 {
		im = im[:i]
	}
	repo, tag := im, ""
	if i := strings.LastIndexByte(im, ':'); i > strings.LastIndexByte(im, '/') {
		repo, tag = im[:i], im[i+1:]
	}
	name := repo[strings.LastIndexByte(repo, '/')+1:]
	switch name {
	case "nginx", "nginx-unprivileged", "openresty", "nginx-proxy":
		return "nginx"
	case "httpd", "apache", "apache2":
		return "apache"
	case "openlitespeed", "litespeed":
		return "litespeed"
	case "wordpress":
		// The official image runs Apache; its fpm and cli variants run none.
		if tag == "" || !(strings.Contains(tag, "fpm") || strings.Contains(tag, "cli")) {
			return "apache"
		}
	case "php":
		if strings.Contains(tag, "apache") {
			return "apache"
		}
	}
	return ""
}

func publishesWebPort(c monitor.DockerContainer) bool {
	for _, p := range c.Ports {
		if p.PublicPort == 80 || p.PublicPort == 443 || p.PublicPort == 8080 || p.PublicPort == 8443 {
			return true
		}
	}
	return false
}

// behindProxy: the container is routed to by a reverse proxy (Traefik or
// Caddy labels).
func behindProxy(labels map[string]string) bool {
	if len(proxysites.FromLabels(labels)) > 0 {
		return true
	}
	for k, v := range labels {
		if strings.EqualFold(k, "traefik.enable") && strings.EqualFold(v, "true") {
			return true
		}
	}
	return false
}

// detectDockerSources returns the container access logs no host file
// gives: proxies (Traefik's file or output, Caddy's output) and web
// servers that log to their output. filesFor: containers whose logs were
// already found as files (their own nginx -T, mounts or the
// infrafence.log-path label). It records the hints for the proxies whose
// log cannot be read.
func detectDockerSources(filesFor map[string]bool) []LogPathInfo {
	if !monitor.HasDockerSocket() {
		setDockerState(nil, map[string]string{})
		return nil
	}
	cs, err := monitor.ListDockerContainers()
	if err != nil {
		// The daemon is restarting: the last state stays.
		dockerStateMu.Lock()
		defer dockerStateMu.Unlock()
		return append([]LogPathInfo(nil), lastDockerSources...)
	}
	dockerStateMu.Lock()
	previous := map[string]LogPathInfo{}
	for _, i := range lastDockerSources {
		previous[i.Container] = i
	}
	dockerStateMu.Unlock()
	if len(cs) > 1000 {
		cs = cs[:1000]
	}
	routers := map[string]string{}
	var out []LogPathInfo
	var hints []WebLogHint
	var proxyIPs []string
	proxyLogRead := false
	for _, c := range cs {
		for k, v := range c.Labels {
			lk := strings.ToLower(k)
			if strings.HasPrefix(lk, "traefik.http.routers.") && strings.HasSuffix(lk, ".rule") {
				if hs := proxysites.TraefikHosts(v); len(hs) > 0 {
					routers[k[len("traefik.http.routers."):len(k)-len(".rule")]] = strings.ToLower(hs[0])
				}
			}
		}
		flavour := proxysites.Flavour(c.Image)
		if flavour == "" || monitorDisabled(c.Labels) {
			continue
		}
		proxyIPs = append(proxyIPs, containerIPs(c)...)
		name := containerName(c)
		if filesFor[name] {
			proxyLogRead = true
			continue
		}
		d, err := monitor.InspectContainer(c.ID)
		if err != nil {
			if p, ok := previous[name]; ok {
				out = append(out, p)
				proxyLogRead = true
			}
			continue
		}
		switch flavour {
		case "traefik":
			info, hint := traefikSource(name, c.Labels, d)
			if hint != nil {
				hints = append(hints, *hint)
			}
			if info != nil {
				out = append(out, *info)
				proxyLogRead = true
			}
		case "caddy":
			// Caddy logs requests (JSON, to its output by default) for the
			// sites with a log directive; its other output is skipped.
			out = append(out, LogPathInfo{Path: containerLogPrefix + name, Server: "caddy", Container: name, Tty: d.Tty})
			proxyLogRead = true
		}
	}
	sort.Strings(proxyIPs)

	n := 0
	for _, c := range cs {
		name := containerName(c)
		if filesFor[name] || monitorDisabled(c.Labels) || proxysites.Flavour(c.Image) != "" {
			continue
		}
		server := webServerOfImage(c.Image)
		if server == "" {
			continue
		}
		published, proxied := publishesWebPort(c), behindProxy(c.Labels)
		if !published && (!proxied || proxyLogRead) {
			continue // not reachable, or the proxy's own log has its requests
		}
		if n == maxContainerSources {
			log.Printf("[webwatcher] docker: more than %d web server containers, the others are not read", maxContainerSources)
			break
		}
		d, err := monitor.InspectContainer(c.ID)
		if err != nil {
			if p, ok := previous[name]; ok {
				n++
				out = append(out, p)
			}
			continue
		}
		n++
		var domains []string
		for _, dm := range proxysites.FromLabels(c.Labels) {
			domains = append(domains, dm.Domain)
		}
		out = append(out, LogPathInfo{Path: containerLogPrefix + name, Domains: domains, Server: server,
			Container: name, Tty: d.Tty, Proxies: proxyIPs})
	}
	setDockerState(hints, routers)
	dockerStateMu.Lock()
	lastDockerSources = append([]LogPathInfo(nil), out...)
	dockerStateMu.Unlock()
	return out
}

// traefikSource is a Traefik container's access log, or the hint saying
// why it cannot be read.
func traefikSource(name string, labels map[string]string, d *monitor.ContainerDetails) (*LogPathInfo, *WebLogHint) {
	mounts := mountMap(d.Mounts)
	cfg := traefikAccessLogOf(d, mounts)
	h := &WebLogHint{Server: "traefik", Container: name, Settings: traefikStdoutSettings}
	if strings.EqualFold(labels["coolify.proxy"], "true") || name == "coolify-proxy" {
		h.Platform, h.Settings = "coolify", coolifyTraefikSettings
	}
	if !cfg.Enabled {
		h.Reason = HintAccessLogOff
		return nil, h
	}
	if cfg.FilePath == "" || cfg.FilePath == "/dev/stdout" || cfg.FilePath == "/dev/stderr" {
		return &LogPathInfo{Path: containerLogPrefix + name, Server: "traefik", Container: name, Tty: d.Tty}, nil
	}
	h.Path = cfg.FilePath
	if strings.Contains(cfg.FilePath, "..") || resolveDockerMount(filepath.Clean(cfg.FilePath), mounts) == "" {
		h.Reason = HintLogNotOnHost
		return nil, h
	}
	host := hostPathInMount(cfg.FilePath, mounts)
	if host == "" {
		h.Reason, h.Settings = HintLogFileAbsent, nil
		return nil, h
	}
	return &LogPathInfo{Path: host, Server: "traefik", Container: name}, nil
}

// caddyfileOutputRe: `output file <path>` in a Caddyfile log block.
var caddyfileOutputRe = regexp.MustCompile(`(?m)^\s*output\s+file\s+("[^"]+"|\S+)`)

// detectCaddyfileLogs returns the access log files of a Caddy installed on
// the host (its Caddyfile's log { output file ... } blocks).
func detectCaddyfileLogs() []LogPathInfo {
	var out []LogPathInfo
	for _, cf := range []string{"/etc/caddy/Caddyfile"} {
		data, err := readBounded(cf, maxProxyConfig)
		if err != nil {
			continue
		}
		for _, m := range caddyfileOutputRe.FindAllStringSubmatch(string(data), -1) {
			p := strings.Trim(m[1], `"`)
			if !filepath.IsAbs(p) {
				continue
			}
			if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
				out = append(out, LogPathInfo{Path: p, Server: "caddy"})
			}
		}
	}
	return out
}

// errContainerOutputEnded: the container stopped or was recreated; the
// stream is opened again.
var errContainerOutputEnded = errors.New("container output ended")

// tailContainer follows a container's output, like tailWithContext a file.
func (w *WebWatcher) tailContainer(ctx context.Context, logPath, name string) error {
	w.mu.Lock()
	tty := w.sources[logPath].Tty
	w.mu.Unlock()
	err := monitor.FollowContainerLogs(ctx, name, tty, func(line string) {
		w.processLine(logPath, line)
	})
	if err == nil {
		err = errContainerOutputEnded
	}
	return err
}

// SetSources records where each log comes from (web server, container,
// proxies in front of it).
func (w *WebWatcher) SetSources(infos []LogPathInfo) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.setSourcesLocked(infos)
}

func (w *WebWatcher) setSourcesLocked(infos []LogPathInfo) {
	if w.sources == nil {
		w.sources = make(map[string]LogPathInfo)
	}
	for _, i := range infos {
		w.sources[i.Path] = i
	}
}

// Detection reports which access logs are read, and the hints for those
// that cannot be.
func (w *WebWatcher) Detection() *WebDetection {
	d := &WebDetection{State: "off", Hints: CurrentWebLogHints()}
	w.mu.Lock()
	paths := make([]string, 0, len(w.activePaths))
	for p := range w.activePaths {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		if len(d.Sources) == maxReportedSources {
			break
		}
		src := w.sources[p]
		s := WebLogSource{Server: src.Server, Container: src.Container}
		if !strings.HasPrefix(p, containerLogPrefix) {
			s.Path = p
		}
		if st := w.parseStats[p]; st != nil {
			s.Format, s.Requests = st.format, st.parsed
		}
		d.Sources = append(d.Sources, s)
	}
	w.mu.Unlock()
	if len(d.Sources) > 0 {
		d.State = "on"
	}
	return d
}

// clientIP is the client of a request. nginx, Apache and LiteSpeed log
// files in the combined format keep their address as is. For the others:
// behind a reverse proxy container, the rightmost X-Forwarded-For address
// of a request from the proxy (from nowhere else); a Cloudflare edge is
// replaced with CF-Connecting-IP, and the request is skipped without it.
func (w *WebWatcher) clientIP(logPath, line string, e *accessLogEntry) (string, bool) {
	src := w.sources[logPath]
	if e.format == formatCombined && src.Container == "" {
		return e.ip, true
	}
	if src.Container != "" && e.format == formatCombined {
		fixForwardedFor(e, line)
	}
	ip := normIP(e.ip)
	if ip == "" {
		return "", false
	}
	for _, p := range src.Proxies {
		if p == ip {
			ip = lastForwardedFor(e.forwardedFor)
			if ip == "" {
				return "", false
			}
			break
		}
	}
	if isCloudflareIP(ip) {
		cf := normIP(e.cfConnectingIP)
		if cf == "" {
			if !w.cfWarned[logPath] {
				w.cfWarned[logPath] = true
				log.Printf("[webwatcher] %s: requests come through Cloudflare without CF-Connecting-IP in the log; they are skipped (the edge is never banned). Traefik: add --accesslog.fields.headers.names.Cf-Connecting-Ip=keep", logPath)
			}
			return "", false
		}
		ip = cf
	}
	return ip, true
}

// serverOfLogPath guesses the web server of a well-known log path.
func serverOfLogPath(p string) string {
	l := strings.ToLower(p)
	switch {
	case strings.HasPrefix(l, containerLogPrefix):
		return ""
	case strings.Contains(l, "haproxy"):
		return "haproxy"
	case strings.Contains(l, "caddy"):
		return "caddy"
	case strings.Contains(l, "nginx"):
		return "nginx"
	case strings.Contains(l, "lsws") || strings.Contains(l, "litespeed"):
		return "litespeed"
	case strings.Contains(l, "apache") || strings.Contains(l, "httpd") || strings.Contains(l, "domlogs"):
		return "apache"
	}
	return ""
}

// describeSource says where a log comes from, for the startup log.
func describeSource(s LogPathInfo) string {
	server := s.Server
	if server == "" {
		server = "web server"
	}
	switch {
	case strings.HasPrefix(s.Path, containerLogPrefix):
		return fmt.Sprintf("%s access log from the output of container %s", server, s.Container)
	case s.Container != "":
		return fmt.Sprintf("%s access log file of container %s", server, s.Container)
	}
	return server + " access log file"
}

// ActivePaths returns the logs being read (container outputs as
// docker://<name>), sorted.
func (w *WebWatcher) ActivePaths() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	paths := make([]string, 0, len(w.activePaths))
	for p := range w.activePaths {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths
}
