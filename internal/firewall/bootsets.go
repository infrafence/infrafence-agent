package firewall

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Saved rulesets. A ruleset saved while the agent runs ("netfilter-persistent
// save", "service iptables save", HestiaCP's v-update-firewall, which saves
// after every firewall change) holds the agent's chains, and their rules
// match the agent's ipsets. At boot the saved ruleset is restored before the
// agent starts, when those sets don't exist yet: iptables-restore refuses
// the whole file ("Set infrafence-allow doesn't exist") and the host comes
// up without any of its saved rules. CreateBootSets runs first at boot
// (infrafence-ipsets.service, "infrafence-agent boot-sets"): it creates
// every set a saved ruleset references, empty, with the type and family the
// agent gives it, so the restore succeeds; the agent fills them once it
// runs.

// SavedRuleset is a file a firewall service restores at boot.
type SavedRuleset struct {
	Path string
	IPv6 bool
	// Save is the command that saves the running ruleset to Path again.
	Save string
}

// SavedRulesets are the files iptables-persistent, iptables-services,
// HestiaCP and Arch's iptables.service restore at boot.
var SavedRulesets = []SavedRuleset{
	{"/etc/iptables/rules.v4", false, "netfilter-persistent save"},
	{"/etc/iptables/rules.v6", true, "netfilter-persistent save"},
	{"/etc/sysconfig/iptables", false, "service iptables save, or /usr/libexec/iptables/iptables.init save (on HestiaCP: v-update-firewall)"},
	{"/etc/sysconfig/ip6tables", true, "service ip6tables save, or /usr/libexec/iptables/ip6tables.init save"},
	{"/etc/iptables.rules", false, "v-update-firewall (HestiaCP)"},
	{"/etc/iptables/iptables.rules", false, "iptables-save -f /etc/iptables/iptables.rules"},
	{"/etc/iptables/ip6tables.rules", true, "ip6tables-save -f /etc/iptables/ip6tables.rules"},
}

// readSaved is replaced in tests.
var readSaved = os.ReadFile

// matchSet finds the agent's sets in iptables-save output (a set name is
// at most 31 characters).
var matchSet = regexp.MustCompile(`--match-set\s+(infrafence-[A-Za-z0-9_.:-]{1,20})(\s|$)`)

// bootSet is a set to create at boot.
type bootSet struct {
	name, typ, family string
	maxelem           int
}

func (b bootSet) args() []string {
	return []string{"create", b.name, b.typ, "family", b.family, "maxelem", strconv.Itoa(b.maxelem), "-exist"}
}

// bootSetFor gives a set the type and size the agent creates it with: the
// ban and egress sets are hash:ip (createIpsetHashIP), every other one
// hash:net (createIpsetHashNet; replaceNetSet swaps in a larger one when
// it needs more room), all of family inet like every set the agent makes.
func bootSetFor(name string) bootSet {
	b := bootSet{name: name, typ: "hash:net", family: "inet", maxelem: netSetMax(0)}
	if name == banSetName || name == egressSetName {
		b.typ, b.maxelem = "hash:ip", 65536
	}
	return b
}

// savedSets returns the agent's sets the saved IPv4 rulesets reference,
// by name. The agent's IPv6 rules use no set (an inet set would not load
// in ip6tables-restore anyway), so IPv6 files are not read for sets.
func savedSets() []bootSet {
	found := map[string]bootSet{}
	for _, f := range SavedRulesets {
		if f.IPv6 {
			continue
		}
		data, err := readSaved(f.Path)
		if err != nil {
			continue
		}
		for _, l := range strings.Split(string(data), "\n") {
			if !strings.HasPrefix(l, "-A ") {
				continue
			}
			for _, m := range matchSet.FindAllStringSubmatch(l, -1) {
				found[m[1]] = bootSetFor(m[1])
			}
		}
	}
	out := make([]bootSet, 0, len(found))
	for _, b := range found {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// CreateBootSets creates, empty, every agent set a saved ruleset
// references and that doesn't exist yet. It never touches a rule or a set
// that exists.
func CreateBootSets() (created []string, err error) {
	sets := savedSets()
	if len(sets) == 0 {
		return nil, nil
	}
	if _, err := exec.LookPath("ipset"); err != nil {
		return nil, fmt.Errorf("the saved rulesets match InfraFence's ipsets, but ipset is not installed")
	}
	var failed []string
	for _, b := range sets {
		if _, e := run("ipset", "list", "-n", b.name); e == nil {
			continue // exists: left as it is
		}
		if out, e := run("ipset", b.args()...); e != nil {
			failed = append(failed, fmt.Sprintf("%s: %s (%v)", b.name, out, e))
			continue
		}
		created = append(created, b.name)
	}
	if len(failed) > 0 {
		err = fmt.Errorf("ipset create %s", strings.Join(failed, "; "))
	}
	return created, err
}

// SavedRulesetsWithAgent returns the saved rulesets that hold any of the
// agent's chains or sets. After an uninstall they must be saved again:
// restored at boot, they would fail (no sets) or bring the agent's rules
// back.
func SavedRulesetsWithAgent() []SavedRuleset {
	var out []SavedRuleset
	for _, f := range SavedRulesets {
		data, err := readSaved(f.Path)
		if err != nil {
			continue
		}
		s := string(data)
		if strings.Contains(s, chainName) || strings.Contains(s, "--match-set infrafence-") {
			out = append(out, f)
		}
	}
	return out
}
