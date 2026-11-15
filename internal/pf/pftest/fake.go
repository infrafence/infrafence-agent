// Package pftest is an in-memory pfctl for the appliance tests.
package pftest

import (
	"github.com/infrafence/infrafence-agent/internal/pf"

	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
)

// Fake is an in-memory pfctl for tests: the tables of a loaded ruleset,
// what a filter reload and a reboot do to them, and every call made.
type Fake struct {
	mu      sync.Mutex
	Enabled bool
	Limit   int
	tables  map[string]map[string]bool // nil value: declared, absent: not in ruleset
	Calls   []string
	Killed  []string
	// Fail makes every call whose joined args contain it fail.
	Fail  string
	unref map[string]bool
}

// Unreference keeps table t but no rule uses it any more (a persist table
// after a ruleset without it was loaded).
func (f *Fake) Unreference(t string, on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.unref == nil {
		f.unref = map[string]bool{}
	}
	f.unref[t] = on
}

// NewFake returns a fake with pf enabled and the agent's tables declared,
// as after os-infrafence's install and a filter reload.
func NewFake() *Fake {
	f := &Fake{Enabled: true, Limit: 1000000, tables: map[string]map[string]bool{}}
	for _, t := range pf.Tables {
		f.tables[t] = map[string]bool{}
	}
	return f
}

// Declare adds (true) or removes (false) table t from the ruleset.
func (f *Fake) Declare(t string, on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !on {
		delete(f.tables, t)
		return
	}
	if f.tables[t] == nil {
		f.tables[t] = map[string]bool{}
	}
}

// Reboot empties every table (kernel memory).
func (f *Fake) Reboot() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for t := range f.tables {
		f.tables[t] = map[string]bool{}
	}
}

// Entries returns table t's entries, sorted.
func (f *Fake) Entries(t string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for e := range f.tables[t] {
		out = append(out, e)
	}
	sort.Strings(out)
	return out
}

// Run is the Runner.
func (f *Fake) Run(stdin string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	joined := strings.Join(args, " ")
	f.Calls = append(f.Calls, joined)
	if f.Fail != "" && strings.Contains(joined, f.Fail) {
		return "pfctl: fake failure", errors.New("exit status 1")
	}
	switch {
	case joined == "-si":
		if f.Enabled {
			return "Status: Enabled for 0 days 00:10:00           Debug: Urgent\n", nil
		}
		return "Status: Disabled for 0 days 00:10:00          Debug: Urgent\n", nil
	case joined == "-vsT":
		var names []string
		for t := range f.tables {
			flags := "-pa-r--"
			if f.unref[t] {
				flags = "-pa----"
			}
			names = append(names, flags+"\t"+t)
		}
		sort.Strings(names)
		return strings.Join(names, "\n") + "\n", nil
	case joined == "-sm":
		return fmt.Sprintf("states        hard limit   400000\nsrc-nodes     hard limit   400000\nfrags         hard limit     5000\ntable-entries hard limit  %d\n", f.Limit), nil
	case len(args) == 2 && args[0] == "-k":
		f.Killed = append(f.Killed, args[1])
		return "killed 0 states from 1 sources and 0 destinations\n", nil
	case len(args) >= 4 && args[0] == "-t" && args[2] == "-T":
		t, op := args[1], args[3]
		tab, ok := f.tables[t]
		in := stdin
		if len(args) == 6 && args[4] == "-f" && args[5] != "-" {
			data, err := readFile(args[5])
			if err != nil {
				return "", err
			}
			in = data
		}
		entries := strings.Fields(in)
		switch op {
		case "show":
			if !ok {
				return "pfctl: Table does not exist.\n", errors.New("exit status 1")
			}
			var out []string
			for e := range tab {
				out = append(out, "   "+e)
			}
			sort.Strings(out)
			return strings.Join(out, "\n") + "\n", nil
		case "replace", "add":
			if !ok {
				// pfctl would create an unreferenced table; the agent must
				// never get here (Ensure checks first).
				tab = map[string]bool{}
				f.tables[t] = tab
			}
			if op == "replace" {
				for e := range tab {
					delete(tab, e)
				}
			}
			for _, e := range entries {
				tab[e] = true
			}
			return fmt.Sprintf("%d addresses added.\n", len(entries)), nil
		case "delete":
			for _, e := range entries {
				delete(tab, e)
			}
			return fmt.Sprintf("%d addresses deleted.\n", len(entries)), nil
		case "flush":
			for e := range tab {
				delete(tab, e)
			}
			return "0 addresses deleted.\n", nil
		}
	}
	return "pfctl: unknown fake command " + joined, errors.New("exit status 1")
}

func readFile(p string) (string, error) {
	if p == "/dev/null" {
		return "", nil
	}
	fh, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer fh.Close()
	b, err := io.ReadAll(fh)
	return string(b), err
}
