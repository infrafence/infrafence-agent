package fw

import (
	"bufio"
	"bytes"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// IPT is the iptables + ipset backend, for fw3 (OpenWrt 21.02 and older,
// many GL.iNet 4.x firmwares). It needs ipset and kmod-ipt-ipset (the SET
// target and set match). Chains INFRAFENCE_IN/FWD/OUT are jumped to first
// from INPUT/FORWARD/OUTPUT; fw3 may flush them on reload, which the
// watchdog and the firewall include repair.
type IPT struct {
	Run Runner
	Now func() time.Time
	// IPv6: ip6tables is installed.
	IPv6 bool
}

func NewIPT(ipv6 bool) *IPT { return &IPT{Run: execRunner, Now: time.Now, IPv6: ipv6} }

func (*IPT) Name() string { return "iptables" }

// ipset's timeout is at most 2147483 s (about 24 days).
func (*IPT) MaxTimeout() time.Duration { return 2147483 * time.Second }

const iptPrefix = "infrafence-"

var iptSetNames = [numKinds][2]string{
	{iptPrefix + "ban4", iptPrefix + "ban6"},
	{iptPrefix + "feed4", iptPrefix + "feed6"},
	{iptPrefix + "c2v4", iptPrefix + "c2v6"},
}

const (
	hitSet4 = iptPrefix + "hit4"
	hitSet6 = iptPrefix + "hit6"
)

var iptChains = []struct{ chain, hook string }{
	{"INFRAFENCE_IN", "INPUT"},
	{"INFRAFENCE_FWD", "FORWARD"},
	{"INFRAFENCE_OUT", "OUTPUT"},
}

func (t *IPT) families() []int {
	if t.IPv6 {
		return []int{0, 1}
	}
	return []int{0}
}

func (t *IPT) setDecl(name string, family int, kind Kind, caps Caps) string {
	fam := "inet"
	if family == 1 {
		fam = "inet6"
	}
	max := caps.Bans
	if kind == KindC2 {
		max = caps.C2
	}
	if max <= 0 {
		max = 65536
	}
	timeout := " timeout 0"
	if kind == KindFeed {
		timeout = ""
	}
	return fmt.Sprintf("create %s hash:net family %s hashsize 1024 maxelem %d%s", name, fam, max+max/4+16, timeout)
}

func ipsetElement(e Element, now time.Time) string {
	s := e.Prefix.String()
	if t := timeoutSecs(e.Expires, now); t > 0 {
		s += fmt.Sprintf(" timeout %d", t)
	}
	return s
}

func (t *IPT) ipt(family int) string {
	if family == 1 {
		return "ip6tables"
	}
	return "iptables"
}

// Build loads every set into a fresh temporary set and swaps it in (the
// live set never goes empty), then rewrites the chains.
func (t *IPT) Build(mode Mode, sets [numKinds][]Element, caps Caps) error {
	now := t.Now()
	existing := map[string]bool{}
	if out, err := t.Run("", "ipset", "-n", "list"); err == nil {
		for _, l := range strings.Fields(string(out)) {
			existing[l] = true
		}
	}
	var b strings.Builder
	for _, fam := range t.families() {
		for k := Kind(0); k < numKinds; k++ {
			name := iptSetNames[k][fam]
			tmp := name + "-n"
			if existing[tmp] { // left by an interrupted Build
				b.WriteString("destroy " + tmp + "\n")
			}
			b.WriteString(t.setDecl(tmp, fam, k, caps) + "\n")
			for _, e := range sets[k] {
				if e.Prefix.Addr().Is4() == (fam == 0) {
					fmt.Fprintf(&b, "add %s %s\n", tmp, ipsetElement(e, now))
				}
			}
			if existing[name] {
				fmt.Fprintf(&b, "swap %s %s\ndestroy %s\n", tmp, name, tmp)
			} else {
				fmt.Fprintf(&b, "rename %s %s\n", tmp, name)
			}
		}
		hit := hitSet4
		famName := "inet"
		if fam == 1 {
			hit, famName = hitSet6, "inet6"
		}
		if !existing[hit] {
			fmt.Fprintf(&b, "create %s hash:net,net family %s hashsize 1024 maxelem 4096 timeout %d\n", hit, famName, int(hitTimeout.Seconds()))
		}
	}
	if _, err := t.Run(b.String(), "ipset", "-exist", "restore"); err != nil {
		return err
	}
	for _, fam := range t.families() {
		if err := t.chains(fam, mode); err != nil {
			return err
		}
	}
	return nil
}

// chains (re)writes our chains in one iptables-restore --noflush (the
// chains named in it are flushed and refilled; nothing else is touched),
// then makes sure each is jumped to first.
func (t *IPT) chains(fam int, mode Mode) error {
	ban, feed, c2 := iptSetNames[KindBan][fam], iptSetNames[KindFeed][fam], iptSetNames[KindC2][fam]
	hit := hitSet4
	if fam == 1 {
		hit = hitSet6
	}
	drop := ""
	if mode == Full {
		drop = " -j DROP"
	}
	var b strings.Builder
	b.WriteString("*filter\n")
	for _, c := range iptChains {
		fmt.Fprintf(&b, ":%s - [0:0]\n", c.chain)
	}
	for _, c := range []string{"INFRAFENCE_IN", "INFRAFENCE_FWD"} {
		fmt.Fprintf(&b, "-A %s -m set --match-set %s src%s\n", c, ban, drop)
		fmt.Fprintf(&b, "-A %s -m set --match-set %s src%s\n", c, feed, drop)
	}
	for _, c := range []string{"INFRAFENCE_FWD", "INFRAFENCE_OUT"} {
		fmt.Fprintf(&b, "-A %s -m set --match-set %s dst -j SET --add-set %s src,dst --exist --timeout %d\n", c, c2, hit, int(hitTimeout.Seconds()))
		fmt.Fprintf(&b, "-A %s -m set --match-set %s dst%s\n", c, c2, drop)
	}
	b.WriteString("COMMIT\n")
	if _, err := t.Run(b.String(), t.ipt(fam)+"-restore", "-w", "--noflush"); err != nil {
		return err
	}
	for _, c := range iptChains {
		if _, err := t.Run("", t.ipt(fam), "-w", "-C", c.hook, "-j", c.chain); err == nil {
			continue
		}
		if _, err := t.Run("", t.ipt(fam), "-w", "-I", c.hook, "1", "-j", c.chain); err != nil {
			return err
		}
	}
	return nil
}

func (t *IPT) Change(kind Kind, add []Element, del []netip.Prefix) error {
	now := t.Now()
	var b strings.Builder
	for _, p := range del {
		fam := 0
		if !p.Addr().Is4() {
			if !t.IPv6 {
				continue
			}
			fam = 1
		}
		fmt.Fprintf(&b, "del %s %s\n", iptSetNames[kind][fam], p)
	}
	for _, e := range add {
		fam := 0
		if !e.Prefix.Addr().Is4() {
			if !t.IPv6 {
				continue
			}
			fam = 1
		}
		fmt.Fprintf(&b, "add %s %s\n", iptSetNames[kind][fam], ipsetElement(e, now))
	}
	if b.Len() == 0 {
		return nil
	}
	_, err := t.Run(b.String(), "ipset", "-exist", "restore")
	return err
}

// Present checks the sets exist and every jump is in place.
func (t *IPT) Present() (bool, error) {
	for _, fam := range t.families() {
		if _, err := t.Run("", "ipset", "-n", "list", iptSetNames[KindBan][fam]); err != nil {
			return false, nil
		}
		for _, c := range iptChains {
			if _, err := t.Run("", t.ipt(fam), "-w", "-C", c.hook, "-j", c.chain); err != nil {
				return false, nil
			}
		}
		// fw3 may flush our chains and leave the jumps: count the rules.
		out, err := t.Run("", t.ipt(fam), "-w", "-S", "INFRAFENCE_FWD")
		if err != nil || bytes.Count(out, []byte("\n-A ")) < 3 {
			return false, nil
		}
	}
	return true, nil
}

func (t *IPT) Hits() ([]Hit, error) {
	var out []Hit
	sets := []string{hitSet4}
	if t.IPv6 {
		sets = append(sets, hitSet6)
	}
	for _, set := range sets {
		raw, err := t.Run("", "ipset", "save", set)
		if err != nil {
			return out, err
		}
		out = append(out, parseIPSetHits(raw)...)
	}
	return out, nil
}

// parseIPSetHits reads "add infrafence-hit4 10.0.0.5,9.9.9.9 timeout 3550"
// lines; hash:net,net prints /32 and /128 prefixes without the suffix.
func parseIPSetHits(raw []byte) []Hit {
	var out []Hit
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 3 || fs[0] != "add" {
			continue
		}
		a, b, ok := strings.Cut(fs[2], ",")
		if !ok {
			continue
		}
		src, err1 := netip.ParseAddr(strings.Split(a, "/")[0])
		dst, err2 := netip.ParseAddr(strings.Split(b, "/")[0])
		if err1 == nil && err2 == nil {
			out = append(out, Hit{Src: src, Dst: dst})
		}
	}
	return out
}

func (t *IPT) Teardown() error {
	var errs []string
	for _, fam := range t.families() {
		for _, c := range iptChains {
			for i := 0; i < 8; i++ { // every copy of the jump
				if _, err := t.Run("", t.ipt(fam), "-w", "-D", c.hook, "-j", c.chain); err != nil {
					break
				}
			}
			_, _ = t.Run("", t.ipt(fam), "-w", "-F", c.chain)
			_, _ = t.Run("", t.ipt(fam), "-w", "-X", c.chain)
		}
	}
	var b strings.Builder
	for _, fam := range []int{0, 1} {
		for k := Kind(0); k < numKinds; k++ {
			fmt.Fprintf(&b, "destroy %s\n", iptSetNames[k][fam])
		}
	}
	b.WriteString("destroy " + hitSet4 + "\ndestroy " + hitSet6 + "\n")
	for _, l := range strings.Split(strings.TrimSpace(b.String()), "\n") {
		name := strings.Fields(l)[1]
		if _, err := t.Run("", "ipset", "-n", "list", name); err != nil {
			continue
		}
		if _, err := t.Run("", "ipset", "destroy", name); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("teardown: %s", strings.Join(errs, "; "))
	}
	return nil
}
