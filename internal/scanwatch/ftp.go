package scanwatch

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// An FTP client opens a data connection to a new port of the server for
// every listing and transfer (passive mode): FileZilla browsing a site
// touches dozens of ports in a few minutes. Those ports are in the range the
// FTP server is configured with, read here (read-only) from the
// configuration of Pure-FTPd (also as cPanel writes it), ProFTPD and vsftpd.

// Control ports always treated as FTP: plain FTP and implicit FTPS. SFTP
// runs over SSH and opens no other ports.
var defaultFTPControl = []uint16{21, 990}

// Passive range assumed when an FTP server listens but no range is
// configured: the dynamic ports (cPanel's default). Pure-FTPd and ProFTPD
// without a range take ports from the kernel's ephemeral range, which is
// added to it when readable.
const (
	fallbackPassiveMin = 49152
	fallbackPassiveMax = 65534
)

// Passive ranges never reach below this: the well-known ports are not data
// ports in any sane configuration, and a scan of them must always count.
const minPassivePort = 1024

// Configuration files are small; anything bigger is not read further.
const maxConfigBytes = 1 << 20

type portRange struct{ min, max uint16 }

func (r portRange) String() string { return fmt.Sprintf("%d-%d", r.min, r.max) }

// FTPConfig is what the port scan check needs to know about the FTP server.
type FTPConfig struct {
	// Control ports of the FTP server (21, 990 and any configured one).
	Control map[uint16]bool
	// Passive ranges found in the configuration; none: not configured.
	Passive []portRange
	// Ephemeral is the kernel's local port range, for the fallback.
	Ephemeral portRange
	// Sources lists the configuration files the ranges and ports came from.
	Sources []string
}

// passiveRanges returns the passive ranges in effect: the configured ones,
// else the fallback when an FTP server is listening.
func (c FTPConfig) passiveRanges(listening bool) []portRange {
	if len(c.Passive) > 0 {
		return c.Passive
	}
	if !listening {
		return nil
	}
	r := portRange{fallbackPassiveMin, fallbackPassiveMax}
	if c.Ephemeral.min >= minPassivePort && c.Ephemeral.min < r.min && c.Ephemeral.max >= c.Ephemeral.min {
		r.min = c.Ephemeral.min
		if c.Ephemeral.max > r.max {
			r.max = c.Ephemeral.max
		}
	}
	return []portRange{r}
}

func inRanges(rs []portRange, p uint16) bool {
	for _, r := range rs {
		if p >= r.min && p <= r.max {
			return true
		}
	}
	return false
}

// Summary describes the configuration for the log.
func (c FTPConfig) Summary(listening bool) string {
	var ports []int
	for p := range c.Control {
		ports = append(ports, int(p))
	}
	sort.Ints(ports)
	ctl := make([]string, len(ports))
	for i, p := range ports {
		ctl[i] = strconv.Itoa(p)
	}
	var rs []string
	for _, r := range c.passiveRanges(listening) {
		rs = append(rs, r.String())
	}
	src := "default"
	if len(c.Passive) > 0 {
		src = strings.Join(c.Sources, ", ")
	}
	return fmt.Sprintf("control ports %s, passive ports %s (%s)", strings.Join(ctl, ","), strings.Join(rs, ","), src)
}

// LoadFTPConfig reads the FTP server configuration under root ("/" on a
// server). Missing files are skipped; nothing is ever written.
func LoadFTPConfig(root string) FTPConfig {
	c := FTPConfig{Control: map[uint16]bool{}}
	for _, p := range defaultFTPControl {
		c.Control[p] = true
	}
	at := func(p string) string { return filepath.Join(root, p) }
	add := func(src string, r portRange, ok bool) {
		if !ok {
			return
		}
		for _, have := range c.Passive {
			if have == r {
				return
			}
		}
		c.Passive = append(c.Passive, r)
		c.Sources = append(c.Sources, src)
	}

	// Pure-FTPd: "PassivePortRange 30000 50000", "Bind 0.0.0.0,2121"; cPanel
	// keeps the same keys as YAML ("PassivePortRange: 49152 65534").
	for _, p := range []string{"/etc/pure-ftpd.conf", "/etc/pure-ftpd/pure-ftpd.conf",
		"/var/cpanel/conf/pureftpd/main", "/var/cpanel/conf/pureftpd/local"} {
		kv := readKeyValues(at(p), false)
		if v, ok := kv["passiveportrange"]; ok {
			r, ok := parseRange(v)
			add(p, r, ok)
		}
		if v, ok := kv["bind"]; ok {
			addBindPort(c.Control, v)
		}
	}
	// Debian's Pure-FTPd wrapper: one file per option.
	if b, err := readSmall(at("/etc/pure-ftpd/conf/PassivePortRange")); err == nil {
		r, ok := parseRange(string(b))
		add("/etc/pure-ftpd/conf/PassivePortRange", r, ok)
	}
	if b, err := readSmall(at("/etc/pure-ftpd/conf/Bind")); err == nil {
		addBindPort(c.Control, string(b))
	}

	// ProFTPD: "PassivePorts 49152 65534", "Port 2121", with Include.
	for _, p := range []string{"/etc/proftpd.conf", "/etc/proftpd/proftpd.conf"} {
		for _, d := range proftpdDirectives(root, p, 0, map[string]bool{}) {
			switch d.key {
			case "passiveports":
				r, ok := parseRange(d.value)
				add(d.file, r, ok)
			case "port":
				addPort(c.Control, d.value)
			}
		}
	}

	// vsftpd: pasv_min_port=, pasv_max_port=, listen_port=.
	for _, p := range []string{"/etc/vsftpd.conf", "/etc/vsftpd/vsftpd.conf"} {
		kv := readKeyValues(at(p), true)
		lo, okLo := parsePort(kv["pasv_min_port"])
		hi, okHi := parsePort(kv["pasv_max_port"])
		if okLo && okHi && lo > 0 {
			r, ok := clampRange(lo, hi)
			add(p, r, ok)
		}
		if v, ok := kv["listen_port"]; ok {
			addPort(c.Control, v)
		}
	}

	if b, err := readSmall(at("/proc/sys/net/ipv4/ip_local_port_range")); err == nil {
		if r, ok := parseRange(string(b)); ok {
			c.Ephemeral = r
		}
	}
	return c
}

// readSmall reads a regular file, at most maxConfigBytes (never a FIFO or a
// device, which could block).
func readSmall(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	return io.ReadAll(io.LimitReader(f, maxConfigBytes))
}

// readKeyValues reads "Key value", "Key: value" or (equals) "key=value"
// lines; keys are lower-cased, comments skipped, the last value wins.
func readKeyValues(path string, equals bool) map[string]string {
	out := map[string]string{}
	b, err := readSmall(path)
	if err != nil {
		return out
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		var k, v string
		if equals {
			i := strings.IndexByte(line, '=')
			if i < 0 {
				continue
			}
			k, v = line[:i], line[i+1:]
		} else {
			i := strings.IndexAny(line, " \t:")
			if i < 0 {
				continue
			}
			k, v = line[:i], strings.TrimLeft(line[i:], " \t:")
		}
		if j := strings.IndexByte(v, '#'); j >= 0 {
			v = v[:j]
		}
		out[strings.ToLower(strings.TrimSpace(k))] = strings.Trim(strings.TrimSpace(v), `"'`)
	}
	return out
}

type directive struct{ file, key, value string }

// proftpdDirectives reads a ProFTPD configuration and the files it
// includes (a file, a directory or a pattern; a few levels deep).
func proftpdDirectives(root, path string, depth int, seen map[string]bool) []directive {
	if depth > 3 || seen[path] || len(seen) > 64 {
		return nil
	}
	seen[path] = true
	b, err := readSmall(filepath.Join(root, path))
	if err != nil {
		return nil
	}
	var out []directive
	sftp := 0 // depth inside <IfModule mod_sftp.c> (an SSH port, not FTP)
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		tag := strings.ToLower(f[0])
		switch {
		case tag == "<ifmodule" && len(f) > 1 && strings.Contains(strings.ToLower(f[1]), "sftp"):
			sftp++
			continue
		case sftp > 0 && strings.HasPrefix(tag, "<ifmodule"):
			sftp++
			continue
		case sftp > 0 && tag == "</ifmodule>":
			sftp--
			continue
		}
		if len(f) < 2 || sftp > 0 {
			continue
		}
		key := tag
		value := strings.Join(f[1:], " ")
		if key != "include" {
			out = append(out, directive{path, key, value})
			continue
		}
		inc := strings.Trim(f[1], `"'`)
		if !filepath.IsAbs(inc) {
			inc = filepath.Join(filepath.Dir(path), inc)
		}
		if fi, err := os.Stat(filepath.Join(root, inc)); err == nil && fi.IsDir() {
			inc = filepath.Join(inc, "*")
		}
		matches, _ := filepath.Glob(filepath.Join(root, inc))
		for _, m := range matches {
			if fi, err := os.Stat(m); err != nil || !fi.Mode().IsRegular() {
				continue
			}
			rel, err := filepath.Rel(root, m)
			if err != nil {
				continue
			}
			out = append(out, proftpdDirectives(root, "/"+rel, depth+1, seen)...)
		}
	}
	return out
}

func parsePort(s string) (uint16, bool) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
	if err != nil {
		return 0, false
	}
	return uint16(n), true
}

// parseRange reads "min max" (also "min:max" or "min-max").
func parseRange(s string) (portRange, bool) {
	f := strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == '\t' || r == '\n' || r == ':' || r == '-' })
	if len(f) != 2 {
		return portRange{}, false
	}
	lo, ok1 := parsePort(f[0])
	hi, ok2 := parsePort(f[1])
	if !ok1 || !ok2 {
		return portRange{}, false
	}
	return clampRange(lo, hi)
}

func clampRange(lo, hi uint16) (portRange, bool) {
	if lo < minPassivePort {
		lo = minPassivePort
	}
	if hi < lo {
		return portRange{}, false
	}
	return portRange{lo, hi}, true
}

// addPort adds a configured control port; 22 is SSH (SFTP), never FTP.
func addPort(m map[uint16]bool, s string) {
	if p, ok := parsePort(s); ok && p > 0 && p != 22 {
		m[p] = true
	}
}

// addBindPort reads Pure-FTPd's "Bind address,port" (or just ",port" or a
// port).
func addBindPort(m map[uint16]bool, s string) {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, ','); i >= 0 {
		s = s[i+1:]
	}
	addPort(m, s)
}
