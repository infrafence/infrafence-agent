package firewall

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

// ErrCSFMonitorMode is returned for a CSF change asked in monitor mode:
// nothing was changed.
var ErrCSFMonitorMode = errors.New("monitor mode: nothing changed")

// Variables for the tests.
var (
	csfConfigPath = "/etc/csf/csf.conf"
	csfRestart    = func() error { return exec.Command("csf", "-r").Run() }
)

// csfPortList is the only form a port list (TCP_IN, TCP_OUT, ...) takes:
// ports and port ranges (low:high), comma separated.
var csfPortList = regexp.MustCompile(`^(\d{1,5}(:\d{1,5})?(,\d{1,5}(:\d{1,5})?)*)?$`)

var csfPort = regexp.MustCompile(`^\d{1,5}$`)

// csfValueValid holds the keys the agent may change, each with the strict
// pattern its value must match.
var csfValueValid = map[string]*regexp.Regexp{
	"TCP_IN":  csfPortList,
	"TCP_OUT": csfPortList,
}

// csfEditPorts adds port to, or removes it from, the TCP_IN or TCP_OUT list
// in csf.conf, then restarts CSF to apply it. In monitor mode nothing
// changes.
func csfEditPorts(port, direction, action string, monitorMode bool) error {
	key := map[string]string{"in": "TCP_IN", "out": "TCP_OUT"}[direction]
	if key == "" {
		return fmt.Errorf("csf: invalid direction %q", direction)
	}
	if action != "add" && action != "remove" {
		return fmt.Errorf("csf: invalid action %q", action)
	}
	if !csfPort.MatchString(port) || !validPort(port) {
		return fmt.Errorf("csf: invalid port %q", port)
	}
	if monitorMode {
		return ErrCSFMonitorMode
	}

	data, err := os.ReadFile(csfConfigPath)
	if err != nil {
		return err
	}
	current, _, err := csfConfValue(string(data), key)
	if err != nil {
		return err
	}
	var ports []string
	present := false
	for _, p := range strings.Split(current, ",") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		if p == port {
			present = true
			if action == "remove" {
				continue
			}
		}
		ports = append(ports, p)
	}
	if (action == "add") == present {
		return nil // already as asked
	}
	if action == "add" {
		ports = append(ports, port)
	}

	if err := csfSetConfigValue(key, strings.Join(ports, ",")); err != nil {
		return err
	}
	return csfRestart()
}

func validPort(s string) bool {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n >= 1 && n <= 65535
}

// csfConfValue finds the one uncommented line setting key (KEY = "value")
// and returns its value and line index.
func csfConfValue(conf, key string) (string, int, error) {
	re := regexp.MustCompile(`^\s*` + regexp.QuoteMeta(key) + `\s*=\s*"([^"]*)"\s*$`)
	value, index := "", -1
	for i, line := range strings.Split(conf, "\n") {
		if m := re.FindStringSubmatch(line); m != nil {
			if index >= 0 {
				return "", -1, fmt.Errorf("csf.conf: %s is set twice", key)
			}
			value, index = m[1], i
		}
	}
	if index < 0 {
		return "", -1, fmt.Errorf("csf.conf: %s not found", key)
	}
	return value, index, nil
}

// csfSetConfigValue sets key in csf.conf to value, both checked against the
// strict pattern for the key: the line is changed in Go (no shell, no sed),
// and the file replaced atomically, keeping its owner and mode.
func csfSetConfigValue(key, value string) error {
	valid, ok := csfValueValid[key]
	if !ok {
		return fmt.Errorf("csf: %s is not a key the agent changes", key)
	}
	if !valid.MatchString(value) {
		return fmt.Errorf("csf: invalid value for %s: %q", key, value)
	}

	info, err := os.Lstat(csfConfigPath)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("csf: %s is not a regular file", csfConfigPath)
	}
	data, err := os.ReadFile(csfConfigPath)
	if err != nil {
		return err
	}
	// The value already there must match the pattern too: anything else is
	// not ours to rewrite.
	current, index, err := csfConfValue(string(data), key)
	if err != nil {
		return err
	}
	if !valid.MatchString(current) {
		return fmt.Errorf("csf: %s in csf.conf has an unexpected value %q: not changed", key, current)
	}
	lines := strings.Split(string(data), "\n")
	lines[index] = key + ` = "` + value + `"`

	return writeFileAtomic(csfConfigPath, []byte(strings.Join(lines, "\n")), info)
}

// writeFileAtomic replaces path with data through a temporary file in the
// same directory, with the mode and owner of the file it replaces (info).
func writeFileAtomic(path string, data []byte, info os.FileInfo) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // a no-op once renamed
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		tmp.Close()
		return err
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && os.Geteuid() == 0 {
		if err := tmp.Chown(int(st.Uid), int(st.Gid)); err != nil {
			tmp.Close()
			return err
		}
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
