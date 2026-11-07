package firewall

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

// withSaved fakes the saved rulesets on disk (path -> contents).
func withSaved(t *testing.T, files map[string]string) {
	t.Helper()
	old := readSaved
	readSaved = func(p string) ([]byte, error) {
		if s, ok := files[p]; ok {
			return []byte(s), nil
		}
		return nil, os.ErrNotExist
	}
	t.Cleanup(func() { readSaved = old })
}

// What iptables-save printed while the agent ran (netfilter-persistent save).
const savedV4 = `*filter
:INPUT ACCEPT [0:0]
:INFRAFENCE - [0:0]
:INFRAFENCE-EGRESS - [0:0]
-A INPUT -m comment --comment infrafence -j INFRAFENCE
-A INPUT -s 198.51.100.77/32 -p tcp -m tcp --dport 2222 -j DROP
-A INFRAFENCE -m set --match-set infrafence-allow src -j RETURN
-A INFRAFENCE -m set --match-set infrafence-bans src -j DROP
-A INFRAFENCE -m set --match-set infrafence-geo-cn src -j DROP
-A INFRAFENCE-EGRESS -m set --match-set infrafence-egress dst -j DROP
-A INPUT -m set --match-set customer-list src -j DROP
COMMIT
`

func TestSavedSets(t *testing.T) {
	withSaved(t, map[string]string{
		"/etc/iptables/rules.v4": savedV4,
		// HestiaCP's copy of the same ruleset: no duplicates.
		"/etc/iptables.rules": savedV4,
		// A future IPv6 set; a name in both files keeps the IPv4 family.
		"/etc/iptables/rules.v6": "-A INPUT -m set --match-set infrafence-v6 src -j DROP\n-A X -m set --match-set infrafence-bans src -j DROP\n",
	})
	var got []string
	for _, b := range savedSets() {
		got = append(got, strings.Join(b.args(), " "))
	}
	want := []string{
		"create infrafence-allow hash:net family inet maxelem 131072 -exist",
		"create infrafence-bans hash:ip family inet maxelem 65536 -exist",
		"create infrafence-egress hash:ip family inet maxelem 65536 -exist",
		"create infrafence-geo-cn hash:net family inet maxelem 131072 -exist",
		"create infrafence-v6 hash:net family inet6 maxelem 131072 -exist",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("savedSets:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// Only missing sets are created; one that exists is left as it is; a
// failure is returned with the sets that were created.
func TestCreateBootSets(t *testing.T) {
	withSaved(t, map[string]string{"/etc/sysconfig/iptables": savedV4})
	fakeBins(t, map[string]string{"ipset": "exit 0"}) // LookPath only
	var cmds []string
	old := run
	run = func(name string, args ...string) (string, error) {
		c := name + " " + strings.Join(args, " ")
		cmds = append(cmds, c)
		switch {
		case c == "ipset list -n infrafence-bans":
			return "infrafence-bans", nil
		case strings.HasPrefix(c, "ipset list -n "):
			return "The set with the given name does not exist", errors.New("exit status 1")
		case strings.HasPrefix(c, "ipset create infrafence-geo-cn "):
			return "Kernel error", errors.New("exit status 1")
		}
		return "", nil
	}
	t.Cleanup(func() { run = old })

	created, err := CreateBootSets()
	if want := []string{"infrafence-allow", "infrafence-egress"}; !reflect.DeepEqual(created, want) {
		t.Errorf("created %v, want %v", created, want)
	}
	if err == nil || !strings.Contains(err.Error(), "infrafence-geo-cn") {
		t.Errorf("err = %v, want the geo set's failure", err)
	}
	for _, c := range cmds {
		if strings.HasPrefix(c, "ipset create infrafence-bans") || strings.Contains(c, "customer-list") ||
			(!strings.HasPrefix(c, "ipset create ") && !strings.HasPrefix(c, "ipset list -n ")) {
			t.Errorf("unexpected command %q", c)
		}
	}
}

// No saved ruleset with the agent's sets: nothing runs, not even without ipset.
func TestCreateBootSetsNothingSaved(t *testing.T) {
	withSaved(t, map[string]string{"/etc/iptables/rules.v4": "*filter\n-A INPUT -j ACCEPT\nCOMMIT\n"})
	old := run
	run = func(name string, args ...string) (string, error) {
		t.Errorf("ran %s %v", name, args)
		return "", nil
	}
	t.Cleanup(func() { run = old })
	if created, err := CreateBootSets(); created != nil || err != nil {
		t.Errorf("CreateBootSets = %v, %v", created, err)
	}
}

func TestSavedRulesetsWithAgent(t *testing.T) {
	withSaved(t, map[string]string{
		"/etc/iptables/rules.v4": savedV4,
		// The IPv6 closed-port chain has no set, but would come back at boot.
		"/etc/iptables/rules.v6":  ":INFRAFENCE-PORTS - [0:0]\n-A INPUT -m comment --comment infrafence-ports -j INFRAFENCE-PORTS\n",
		"/etc/sysconfig/iptables": "*filter\n-A INPUT -j ACCEPT\nCOMMIT\n",
	})
	var got []string
	for _, f := range SavedRulesetsWithAgent() {
		got = append(got, f.Path+": "+f.Save)
	}
	want := []string{"/etc/iptables/rules.v4: netfilter-persistent save", "/etc/iptables/rules.v6: netfilter-persistent save"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
