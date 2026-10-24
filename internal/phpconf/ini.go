// Package phpconf finds the PHP runtimes on a host and reads their
// effective configuration: the php.ini each one loads, the files of the
// directory it scans after it, the PHP-FPM pools and their per-pool
// overrides, and the per-site files the hosting panels write. It is read
// only: it never changes a file and never loads code into PHP. The checks
// (checks.go) and the change watcher (watch.go) are built on it; the fixes
// live in internal/remediation.
package phpconf

import (
	"strings"
)

// Directive is one setting and where its value comes from.
type Directive struct {
	Key   string // lower case, e.g. "display_errors"
	Value string // unquoted, as written
	File  string
	Line  int
	// Default: no file sets it, Value is PHP's built-in default.
	Default bool
	// Admin: a pool's php_admin_value/php_admin_flag (scripts can't
	// change it with ini_set).
	Admin bool
}

// defaults are PHP's built-in values for the directives we check, the ones
// in effect when no file sets them (not php.ini-production's).
var defaults = map[string]string{
	"allow_url_include":       "0",
	"allow_url_fopen":         "1",
	"display_errors":          "1",
	"log_errors":              "1",
	"expose_php":              "1",
	"cgi.fix_pathinfo":        "1",
	"disable_functions":       "",
	"open_basedir":            "",
	"session.cookie_httponly": "0",
	"session.cookie_secure":   "0",
	"session.save_path":       "",
	"upload_tmp_dir":          "",
	"sys_temp_dir":            "",
}

// systemOnly are directives a pool's php_value can't set (PHP_INI_SYSTEM):
// only php.ini, the scan directory and php_admin_value change them.
var systemOnly = map[string]bool{
	"allow_url_include": true,
	"allow_url_fopen":   true,
	"expose_php":        true,
	"cgi.fix_pathinfo":  true,
	"disable_functions": true,
}

// parseINI reads PHP's ini syntax: "key = value", ";" comments, quoted
// values. [PATH=...] and [HOST=...] sections only apply to some requests
// under CGI and are skipped, so they never count as the global value.
func parseINI(file, content string) []Directive {
	var out []Directive
	scoped := false
	for i, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || line[0] == ';' || line[0] == '#' {
			continue
		}
		if line[0] == '[' {
			sec := strings.ToUpper(strings.Trim(line, "[] \t"))
			scoped = strings.HasPrefix(sec, "PATH=") || strings.HasPrefix(sec, "HOST=")
			continue
		}
		if scoped {
			continue
		}
		k, v, ok := splitKV(line)
		if !ok {
			continue
		}
		out = append(out, Directive{Key: strings.ToLower(k), Value: v, File: file, Line: i + 1})
	}
	return out
}

// splitKV splits "key = value ; comment" and unquotes the value.
func splitKV(line string) (string, string, bool) {
	eq := strings.IndexByte(line, '=')
	if eq <= 0 {
		return "", "", false
	}
	k := strings.TrimSpace(line[:eq])
	v := strings.TrimSpace(line[eq+1:])
	if k == "" {
		return "", "", false
	}
	if len(v) > 0 && (v[0] == '"' || v[0] == '\'') {
		q := v[0]
		if end := strings.IndexByte(v[1:], q); end >= 0 {
			return k, v[1 : end+1], true
		}
		return k, strings.Trim(v, `"'`), true
	}
	if c := strings.IndexByte(v, ';'); c >= 0 {
		v = strings.TrimSpace(v[:c])
	}
	return k, v, true
}

// IsOn reports whether an ini boolean is on, as PHP reads it.
func IsOn(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "on", "yes", "true":
		return true
	}
	return false
}

// displaysErrors reports whether a display_errors value sends errors to
// the visitor ("stderr" sends them to the FPM or CGI log instead).
func displaysErrors(v string) bool {
	return IsOn(v) || strings.EqualFold(strings.TrimSpace(v), "stdout")
}

// lookup returns the last setting of key in ds, or PHP's default.
func lookup(ds []Directive, key string) Directive {
	for i := len(ds) - 1; i >= 0; i-- {
		if ds[i].Key == key {
			return ds[i]
		}
	}
	return Directive{Key: key, Value: defaults[key], Default: true}
}
