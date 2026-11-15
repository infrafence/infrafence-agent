// Package pf is the firewall backend of the appliance build (OPNsense): the
// agent's bans, threat feed and blocked countries are pf tables.
//
// The tables are declared by OPNsense itself, from the "External
// (advanced)" aliases the os-infrafence plugin creates, and referenced by
// the block rules the plugin registers. OPNsense never fills or flushes an
// external alias, so a filter reload keeps the contents; a reboot empties
// them and the agent refills them from its state. The agent only ever
// changes the contents of its own three tables: never the ruleset, never
// another table, never config.xml.
package pf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// The tables, named as the plugin's aliases.
const (
	TableBans   = "infrafence_bans"   // local and network bans
	TableThreat = "infrafence_threat" // threat feed networks
	TableGeo    = "infrafence_geo"    // blocked countries
)

// Tables are all the tables the agent manages.
var Tables = []string{TableBans, TableThreat, TableGeo}

// Runner runs pfctl with args, stdin as its standard input.
type Runner func(stdin string, args ...string) (string, error)

// ExecRunner runs the pfctl binary at path, each call bounded to 60 s.
func ExecRunner(path string) Runner {
	return func(stdin string, args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, path, args...)
		if stdin != "" {
			cmd.Stdin = strings.NewReader(stdin)
		}
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out
		err := cmd.Run()
		return out.String(), err
	}
}

// Ctl wraps the pfctl calls the agent makes.
type Ctl struct{ run Runner }

// NewCtl returns a Ctl that runs pfctl through run.
func NewCtl(run Runner) *Ctl { return &Ctl{run: run} }

func ours(t string) error {
	for _, n := range Tables {
		if n == t {
			return nil
		}
	}
	return fmt.Errorf("pf: %q is not an InfraFence table", t)
}

// Enabled reports whether pf is enabled (pfctl -si: "Status: Enabled").
func (c *Ctl) Enabled() (bool, error) {
	out, err := c.run("", "-si")
	if err != nil {
		return false, fmt.Errorf("pfctl -si: %v: %s", err, firstLine(out))
	}
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); len(f) >= 2 && f[0] == "Status:" {
			return f[1] == "Enabled", nil
		}
	}
	return false, errors.New("pfctl -si: no status line")
}

// Present returns the tables pf has, true for those a loaded rule
// references (pfctl -vsT flags "cpairhC": r = referenced). A persist table
// outlives the rules that used it: present but unreferenced blocks nothing.
func (c *Ctl) Present() (map[string]bool, error) {
	out, err := c.run("", "-vsT")
	if err != nil {
		return nil, fmt.Errorf("pfctl -vsT: %v: %s", err, firstLine(out))
	}
	m := map[string]bool{}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		switch {
		case len(f) >= 2 && len(f[0]) == 7 && strings.Trim(f[0], "-cpairhC") == "":
			m[f[1]] = f[0][4] == 'r'
		case len(f) == 1:
			m[f[0]] = true // no flags printed: assume referenced
		}
	}
	return m, nil
}

// Replace sets table t to exactly entries, atomically (-T replace).
func (c *Ctl) Replace(t string, entries []string) error {
	if err := ours(t); err != nil {
		return err
	}
	in := strings.Join(entries, "\n")
	if in != "" {
		in += "\n"
	}
	// An empty replace must still read stdin: "-f /dev/null" empties it.
	file := "-"
	if in == "" {
		file = "/dev/null"
	}
	if out, err := c.run(in, "-t", t, "-T", "replace", "-f", file); err != nil {
		return fmt.Errorf("pfctl -t %s -T replace: %v: %s", t, err, firstLine(out))
	}
	return nil
}

// Add adds entries to table t.
func (c *Ctl) Add(t string, entries ...string) error {
	if err := ours(t); err != nil {
		return err
	}
	if len(entries) == 0 {
		return nil
	}
	if out, err := c.run(strings.Join(entries, "\n")+"\n", "-t", t, "-T", "add", "-f", "-"); err != nil {
		return fmt.Errorf("pfctl -t %s -T add: %v: %s", t, err, firstLine(out))
	}
	return nil
}

// Delete removes entries from table t.
func (c *Ctl) Delete(t string, entries ...string) error {
	if err := ours(t); err != nil {
		return err
	}
	if len(entries) == 0 {
		return nil
	}
	if out, err := c.run(strings.Join(entries, "\n")+"\n", "-t", t, "-T", "delete", "-f", "-"); err != nil {
		return fmt.Errorf("pfctl -t %s -T delete: %v: %s", t, err, firstLine(out))
	}
	return nil
}

// Show lists table t (negated entries keep their "!").
func (c *Ctl) Show(t string) ([]string, error) {
	if err := ours(t); err != nil {
		return nil, err
	}
	out, err := c.run("", "-t", t, "-T", "show")
	if err != nil {
		return nil, fmt.Errorf("pfctl -t %s -T show: %v: %s", t, err, firstLine(out))
	}
	var list []string
	for _, l := range strings.Split(out, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			list = append(list, l)
		}
	}
	return list, nil
}

// TableLimit is pf's "table-entries" hard limit (Firewall › Settings ›
// Advanced › Firewall Maximum Table Entries), shared by every table; 0 when
// unknown.
func (c *Ctl) TableLimit() int {
	out, err := c.run("", "-sm")
	if err != nil {
		return 0
	}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		// "table-entries  hard limit  1000000"
		if len(f) >= 4 && f[0] == "table-entries" {
			n, _ := strconv.Atoi(f[len(f)-1])
			return n
		}
	}
	return 0
}

// KillStates drops the states from host (the conntrack -D analogue), so a
// banned address loses the connections it already has.
func (c *Ctl) KillStates(host string) {
	_, _ = c.run("", "-k", host)
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
