// Package uci reads OpenWrt's UCI configuration through the uci command
// (read-only: the agent never writes another package's configuration).
package uci

import (
	"bufio"
	"bytes"
	"os/exec"
	"strings"
)

// Show returns "package.section.option" -> value for a package, empty when
// uci or the package is missing. Lists keep their values space-separated.
func Show(pkg string) map[string]string {
	out, err := exec.Command("uci", "-q", "show", pkg).Output()
	if err != nil {
		return map[string]string{}
	}
	return Parse(out)
}

// Parse reads `uci show` output: key='value' lines.
func Parse(out []byte) map[string]string {
	m := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		m[k] = unquote(v)
	}
	return m
}

// unquote undoes uci's quoting: 'a b' 'c' -> "a b c"; 'it'\”s' -> "it's".
func unquote(v string) string {
	var b strings.Builder
	in := false
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c == '\'':
			in = !in
		case c == '\\' && !in && i+1 < len(v):
			i++
			b.WriteByte(v[i])
		case c == ' ' && !in:
			b.WriteByte(' ')
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// First returns the value of option in the first section of type typ
// (uci show prints anonymous sections as pkg.@typ[0] only with -X off; the
// named form is pkg.<name> with pkg.<name>=typ).
func First(m map[string]string, pkg, typ, option string) (string, bool) {
	if v, ok := m[pkg+".@"+typ+"[0]."+option]; ok {
		return v, true
	}
	// Named sections: find the first whose type is typ. uci prints sections
	// in order, but a map has none: pick the lowest cfgXXXX / name.
	best := ""
	for k, v := range m {
		if v != typ || strings.Count(k, ".") != 1 || !strings.HasPrefix(k, pkg+".") {
			continue
		}
		if best == "" || k < best {
			best = k
		}
	}
	if best == "" {
		return "", false
	}
	v, ok := m[best+"."+option]
	return v, ok
}
