package firewall

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// fake6 emulates the parts of ip6tables the IPv6 mirror uses: -S, -I, -D
// (by rule or number), -F, -X and ip6tables-restore --noflush.
type fake6 struct {
	chains map[string][]string
}

func withFake6(t *testing.T, present bool) *fake6 {
	t.Helper()
	f := &fake6{chains: map[string][]string{"INPUT": {"-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"}}}
	oldRun, oldStdin, oldHas := run, runStdin, hasIp6tables
	hasIp6tables = func() bool { return present }
	run = func(name string, args ...string) (string, error) {
		if name != "ip6tables" {
			return "", fmt.Errorf("unexpected %s", name)
		}
		return f.run(args)
	}
	runStdin = func(stdin, name string, args ...string) (string, error) {
		if name != "ip6tables-restore" {
			return "", fmt.Errorf("unexpected %s", name)
		}
		var chain string
		for _, l := range strings.Split(stdin, "\n") {
			switch {
			case strings.HasPrefix(l, ":"):
				chain = strings.Fields(l[1:])[0]
				f.chains[chain] = nil
			case strings.HasPrefix(l, "-A "):
				f.chains[chain] = append(f.chains[chain], l)
			}
		}
		return "", nil
	}
	fw.Lock()
	saved := struct {
		closedPorts            []int
		allow                  []string
		v6Desired, v6FailedKey string
		v6Applied              []string
		v6InForce              bool
	}{fw.closedPorts, fw.allow, fw.v6Desired, fw.v6FailedKey, fw.v6Applied, fw.v6InForce}
	fw.v6Desired, fw.v6Applied, fw.v6FailedKey, fw.v6InForce = "", nil, "", false
	fw.Unlock()
	t.Cleanup(func() {
		run, runStdin, hasIp6tables = oldRun, oldStdin, oldHas
		fw.Lock()
		fw.closedPorts, fw.allow = saved.closedPorts, saved.allow
		fw.v6Desired, fw.v6Applied, fw.v6FailedKey, fw.v6InForce = saved.v6Desired, saved.v6Applied, saved.v6FailedKey, saved.v6InForce
		fw.Unlock()
	})
	return f
}

func (f *fake6) run(args []string) (string, error) {
	op, chain := args[0], args[1]
	lines, ok := f.chains[chain]
	switch op {
	case "-S":
		if !ok {
			return "", fmt.Errorf("no chain %s", chain)
		}
		return strings.Join(append([]string{"-N " + chain}, lines...), "\n"), nil
	case "-I":
		pos, _ := strconv.Atoi(args[2])
		rule := "-A " + chain + " " + strings.Join(args[3:], " ")
		lines = append(lines[:pos-1], append([]string{rule}, lines[pos-1:]...)...)
		f.chains[chain] = lines
		return "", nil
	case "-D":
		if n, err := strconv.Atoi(args[2]); err == nil && len(args) == 3 {
			f.chains[chain] = append(lines[:n-1], lines[n:]...)
			return "", nil
		}
		rule := "-A " + chain + " " + strings.Join(args[2:], " ")
		for i, l := range lines {
			if l == rule {
				f.chains[chain] = append(lines[:i], lines[i+1:]...)
				return "", nil
			}
		}
		return "", fmt.Errorf("no such rule")
	case "-F":
		if !ok {
			return "", fmt.Errorf("no chain")
		}
		f.chains[chain] = nil
		return "", nil
	case "-X":
		delete(f.chains, chain)
		return "", nil
	}
	return "", fmt.Errorf("unsupported %v", args)
}

func TestPorts6Mirror(t *testing.T) {
	f := withFake6(t, true)
	fw.Lock()
	fw.closedPorts = []int{6379}
	fw.allow = []string{"2001:db8:aa::/48", "198.51.100.4"}
	fw.ensurePorts6()
	fw.Unlock()

	chain := strings.Join(f.chains[portsChainName], "\n")
	for _, want := range []string{
		"-A INFRAFENCE-PORTS -i lo -j RETURN",
		"-A INFRAFENCE-PORTS -s fc00::/7 -j RETURN",
		"-A INFRAFENCE-PORTS -s 2001:db8:aa::/48 -j RETURN",
		"-A INFRAFENCE-PORTS -p tcp -m conntrack --ctstate NEW --ctorigdstport 6379 -j DROP",
	} {
		if !strings.Contains(chain, want) {
			t.Errorf("missing %q in\n%s", want, chain)
		}
	}
	if strings.Contains(chain, "198.51.100.4") {
		t.Errorf("IPv4 allow entry in the IPv6 chain:\n%s", chain)
	}
	// The jump goes ahead of the ACCEPT.
	if in := f.chains["INPUT"]; in[0] != jumpLine("INPUT", ports6Comment, portsChainName) {
		t.Fatalf("INPUT: %v", in)
	}
	if closed, ok := Ports6InForce(); !ok || len(closed) != 1 || closed[0] != 6379 {
		t.Fatalf("in force: %v %v", closed, ok)
	}

	// Another tool flushes the chain: the next run puts it back.
	f.chains[portsChainName] = nil
	fw.Lock()
	repaired := fw.ensurePorts6()
	fw.Unlock()
	if len(f.chains[portsChainName]) == 0 || len(repaired) == 0 {
		t.Fatalf("not repaired: %v %v", f.chains[portsChainName], repaired)
	}

	done := removePorts6()
	if _, ok := f.chains[portsChainName]; ok || len(f.chains["INPUT"]) != 1 || len(done) != 2 {
		t.Fatalf("after uninstall: %v (%v)", f.chains, done)
	}
}

func TestPorts6Missing(t *testing.T) {
	withFake6(t, false)
	fw.Lock()
	fw.closedPorts = []int{6379}
	fw.ensurePorts6()
	fw.Unlock()
	if _, ok := Ports6InForce(); ok {
		t.Fatal("ports reported closed over IPv6 without ip6tables")
	}
}
