// Package sshdconfig reads the sshd configuration files the way sshd does,
// to say which file and line set the value of a keyword. Read only.
//
// sshd keeps the first value it reads for most keywords, and an Include is
// read where it stands: on Debian, Ubuntu, RHEL 9 and Fedora sshd_config
// starts with "Include /etc/ssh/sshd_config.d/*.conf", so every drop-in
// (50-cloud-init.conf, for one) wins over the rest of sshd_config. Lines
// after a Match line apply only to some connections and are not the global
// value; they are skipped, as is everything after a Match in the same file.
package sshdconfig

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// MainFile is sshd's configuration file.
const MainFile = "/etc/ssh/sshd_config"

// FS is what Parse reads; tests replace it.
type FS interface {
	ReadFile(path string) ([]byte, error)
	Glob(pattern string) ([]string, error)
}

// Setting is the first global occurrence of a keyword.
type Setting struct {
	Value string // first argument, as written
	File  string
	Line  int
}

// Where is "file:line".
func (s Setting) Where() string { return s.File + ":" + strconv.Itoa(s.Line) }

// DropIn reports whether the setting comes from a file other than
// sshd_config (an Include).
func (s Setting) DropIn() bool { return s.File != MainFile }

// Config is the first global setting of each keyword (lower case).
type Config map[string]Setting

// Get returns the setting of keyword (any case).
func (c Config) Get(keyword string) (Setting, bool) {
	s, ok := c[strings.ToLower(keyword)]
	return s, ok
}

// maxDepth and maxFiles bound Include loops and huge globs.
const (
	maxDepth = 16
	maxFiles = 256
)

// Parse reads MainFile and its Include files in sshd's order. ok is false
// when MainFile cannot be read.
func Parse(fs FS) (Config, bool) {
	data, err := fs.ReadFile(MainFile)
	if err != nil {
		return nil, false
	}
	p := &parser{fs: fs, cfg: Config{}}
	p.file(MainFile, data, 0)
	return p.cfg, true
}

type parser struct {
	fs    FS
	cfg   Config
	files int
}

func (p *parser) file(path string, data []byte, depth int) {
	p.files++
	for i, raw := range strings.Split(string(data), "\n") {
		key, args := fields(raw)
		if key == "" {
			continue
		}
		switch key {
		case "match":
			// The rest of this file is conditional.
			return
		case "include":
			if depth >= maxDepth {
				continue
			}
			for _, pat := range args {
				if !filepath.IsAbs(pat) {
					pat = filepath.Join("/etc/ssh", pat)
				}
				matches, err := p.fs.Glob(pat)
				if err != nil {
					continue
				}
				// Glob returns the names sorted, as sshd reads them.
				for _, m := range matches {
					if p.files >= maxFiles {
						return
					}
					if b, err := p.fs.ReadFile(m); err == nil {
						p.file(m, b, depth+1)
					}
				}
			}
			continue
		}
		if len(args) == 0 {
			continue
		}
		if _, seen := p.cfg[key]; !seen {
			p.cfg[key] = Setting{Value: args[0], File: path, Line: i + 1}
		}
	}
}

// fields splits a configuration line into its keyword (lower case) and
// arguments: "Key value", "Key=value" and "Key = value" are all accepted,
// and "#" starts a comment line. Double-quoted arguments keep their spaces.
func fields(line string) (string, []string) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", nil
	}
	i := strings.IndexAny(line, " \t=")
	if i < 0 {
		return strings.ToLower(line), nil
	}
	key := strings.ToLower(line[:i])
	rest := strings.TrimLeft(line[i:], " \t")
	rest = strings.TrimPrefix(rest, "=")
	rest = strings.TrimSpace(rest)
	var args []string
	for rest != "" {
		if rest[0] == '"' {
			end := strings.IndexByte(rest[1:], '"')
			if end < 0 {
				args = append(args, rest[1:])
				break
			}
			args = append(args, rest[1:1+end])
			rest = strings.TrimSpace(rest[2+end:])
			continue
		}
		j := strings.IndexAny(rest, " \t")
		if j < 0 {
			args = append(args, rest)
			break
		}
		args = append(args, rest[:j])
		rest = strings.TrimSpace(rest[j:])
	}
	return key, args
}

// Same reports whether two values of keyword mean the same thing (sshd -T
// prints "prohibit-password" for "without-password", and lower case).
func Same(keyword, a, b string) bool {
	norm := func(v string) string {
		v = strings.ToLower(strings.TrimSpace(v))
		if strings.EqualFold(keyword, "PermitRootLogin") && v == "without-password" {
			return "prohibit-password"
		}
		return v
	}
	return norm(a) == norm(b)
}

// OS reads the real file system.
var OS FS = osFS{}

type osFS struct{}

// ReadFile reads a regular file, at most 1 MiB: an Include naming a FIFO
// or a device must not hang or fill memory.
func (osFS) ReadFile(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 1<<20))
}

func (osFS) Glob(pattern string) ([]string, error) { return filepath.Glob(pattern) }
