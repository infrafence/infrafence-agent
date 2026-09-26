package watcher

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// OpenLiteSpeed keeps its own configuration format (LiteSpeed Enterprise
// reads Apache's, which detectApacheLogInfo and the cPanel domlogs cover).
// The server config lists virtual hosts; each vhost config may set its own
// access log, otherwise requests go to the server-level log.
const olsRoot = "/usr/local/lsws"

// detectOpenLiteSpeedLogInfo finds OpenLiteSpeed access logs with their domains.
func detectOpenLiteSpeedLogInfo() []LogPathInfo {
	return parseOpenLiteSpeedLogs(olsRoot, func(p string) (string, error) {
		b, err := os.ReadFile(p)
		return string(b), err
	})
}

type olsVhost struct {
	name, root, configFile string
}

// parseOpenLiteSpeedLogs reads httpd_config.conf (and each vhost's
// vhconf.conf) through read and returns the access logs that exist in the
// configuration, the server-level one included.
func parseOpenLiteSpeedLogs(serverRoot string, read func(string) (string, error)) []LogPathInfo {
	main, err := read(filepath.Join(serverRoot, "conf/httpd_config.conf"))
	if err != nil {
		return nil
	}

	var (
		vhosts    []*olsVhost
		domains   = map[string][]string{} // vhost name -> domains (from listener maps)
		serverLog string
		stack     []string // enclosing block keywords
		cur       *olsVhost
	)
	sc := bufio.NewScanner(strings.NewReader(main))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == "}" {
			if len(stack) > 0 {
				if stack[len(stack)-1] == "virtualhost" {
					cur = nil
				}
				stack = stack[:len(stack)-1]
			}
			continue
		}
		f := strings.Fields(line)
		key := strings.ToLower(f[0])
		opens := strings.HasSuffix(line, "{")
		if opens {
			switch {
			case key == "virtualhost" && len(stack) == 0 && len(f) >= 3:
				cur = &olsVhost{name: f[1]}
				vhosts = append(vhosts, cur)
			case key == "accesslog" && len(stack) == 0 && len(f) >= 3:
				serverLog = f[1]
			}
			stack = append(stack, key)
			continue
		}
		if len(f) < 2 {
			continue
		}
		val := strings.Join(f[1:], " ")
		switch {
		case cur != nil && key == "vhroot":
			cur.root = val
		case cur != nil && key == "configfile":
			cur.configFile = val
		case key == "map" && len(stack) > 0 && stack[len(stack)-1] == "listener":
			// map <vhost> dom1, dom2
			for _, d := range strings.Split(strings.Join(f[2:], " "), ",") {
				if d = strings.TrimSpace(d); d != "" && d != "*" {
					domains[f[1]] = appendUnique(domains[f[1]], d)
				}
			}
		}
	}

	var out []LogPathInfo
	seen := map[string]bool{}
	add := func(p string, doms []string) {
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, LogPathInfo{Path: p, Domains: doms})
	}

	for _, v := range vhosts {
		root := expandOLS(v.root, serverRoot, v.name, "")
		cfgPath := expandOLS(v.configFile, serverRoot, v.name, root)
		if cfgPath == "" {
			continue
		}
		cfg, err := read(cfgPath)
		if err != nil {
			continue
		}
		if p := vhostAccessLog(cfg); p != "" {
			add(expandOLS(p, serverRoot, v.name, root), domains[v.name])
		}
	}
	if serverLog != "" {
		add(expandOLS(serverLog, serverRoot, "", ""), nil)
	}
	return out
}

// vhostAccessLog returns the vhost's own access log path, or "" when the
// vhost has none or logs to the server log ("useServer 1").
func vhostAccessLog(cfg string) string {
	var path string
	depth, in := 0, false
	sc := bufio.NewScanner(strings.NewReader(cfg))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if line == "}" {
			depth--
			if depth == 0 {
				in = false
			}
			continue
		}
		if strings.HasSuffix(line, "{") {
			if depth == 0 && strings.EqualFold(f[0], "accesslog") && len(f) >= 3 {
				path, in = f[1], true
			}
			depth++
			continue
		}
		if in && depth == 1 && strings.EqualFold(f[0], "useServer") && len(f) >= 2 && f[1] == "1" {
			return ""
		}
	}
	return path
}

// expandOLS substitutes OpenLiteSpeed's path variables.
func expandOLS(p, serverRoot, vhName, vhRoot string) string {
	if p == "" {
		return ""
	}
	r := strings.NewReplacer("$SERVER_ROOT", serverRoot, "$VH_NAME", vhName, "$VH_ROOT", strings.TrimSuffix(vhRoot, "/"))
	p = filepath.Clean(r.Replace(p))
	if strings.Contains(p, "$") {
		return "" // an unknown variable: don't guess
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(serverRoot, p)
	}
	return p
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}
