package fw

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

type fakeBackend struct {
	builds   int
	changes  []string
	failNext bool
	present  bool
	max      time.Duration
	sets     [numKinds][]Element
	mode     Mode
}

func (f *fakeBackend) Name() string { return "fake" }
func (f *fakeBackend) Build(m Mode, s [numKinds][]Element, c Caps) error {
	f.builds++
	f.sets = s
	f.mode = m
	f.present = true
	return nil
}
func (f *fakeBackend) Change(k Kind, add []Element, del []netip.Prefix) error {
	if f.failNext {
		f.failNext = false
		return errors.New("element does not exist")
	}
	var b strings.Builder
	b.WriteString(k.name() + ":")
	for _, p := range del {
		b.WriteString(" -" + p.String())
	}
	for _, e := range add {
		b.WriteString(" +" + e.Prefix.String())
	}
	f.changes = append(f.changes, b.String())
	return nil
}
func (f *fakeBackend) Present() (bool, error)    { return f.present, nil }
func (f *fakeBackend) Hits() ([]Hit, error)      { return nil, nil }
func (f *fakeBackend) Teardown() error           { f.present = false; return nil }
func (f *fakeBackend) MaxTimeout() time.Duration { return f.max }

func el(s string, exp time.Time) Element {
	return Element{Prefix: netip.MustParsePrefix(s), Expires: exp}
}

func TestNormalize(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	got, dropped := normalize([]Element{
		el("203.0.113.0/24", time.Time{}),
		el("203.0.113.7/32", now.Add(time.Hour)),     // inside the /24: dropped
		el("198.51.100.1/32", now.Add(-time.Second)), // expired
		el("198.51.100.2/32", now.Add(time.Hour)),
		el("198.51.100.2/32", now.Add(2*time.Hour)), // duplicate: longest kept
		el("2001:db8::/32", time.Time{}),
		el("2001:db8:1::1/128", time.Time{}),
	}, now, 0)
	if dropped != 0 || len(got) != 3 {
		t.Fatalf("normalize = %v (%d dropped)", got, dropped)
	}
	if e := got[netip.MustParsePrefix("198.51.100.2/32")]; !e.Equal(now.Add(2 * time.Hour)) {
		t.Errorf("duplicate expiry = %v", e)
	}
	_, dropped = normalize([]Element{el("203.0.113.1/32", time.Time{}), el("203.0.113.2/32", time.Time{}), el("203.0.113.3/32", time.Time{})}, now, 2)
	if dropped != 1 {
		t.Errorf("cap: dropped %d", dropped)
	}
}

func TestManagerDiffAndRebuild(t *testing.T) {
	be := &fakeBackend{}
	m := NewManager(be, Caps{Bans: 100, C2: 100})
	now := time.Unix(1_000_000, 0)
	m.now = func() time.Time { return now }
	if err := m.SetMode(Learning); err != nil || be.builds != 1 {
		t.Fatalf("SetMode: %v builds=%d", err, be.builds)
	}
	if err := m.Set(KindBan, []Element{el("203.0.113.7/32", time.Time{}), el("203.0.113.8/32", now.Add(time.Hour))}); err != nil {
		t.Fatal(err)
	}
	if err := m.Set(KindBan, []Element{el("203.0.113.8/32", now.Add(time.Hour)), el("198.51.100.0/24", time.Time{})}); err != nil {
		t.Fatal(err)
	}
	want := []string{"ban: +203.0.113.7/32 +203.0.113.8/32", "ban: -203.0.113.7/32 +198.51.100.0/24"}
	if strings.Join(be.changes, "|") != strings.Join(want, "|") {
		t.Errorf("changes = %q", be.changes)
	}
	// Same set again: nothing to do.
	m.Set(KindBan, []Element{el("203.0.113.8/32", now.Add(time.Hour)), el("198.51.100.0/24", time.Time{})})
	if len(be.changes) != 2 {
		t.Errorf("no-op Set changed: %q", be.changes)
	}
	// A failing change rebuilds everything.
	be.failNext = true
	m.Set(KindBan, []Element{el("198.51.100.0/24", time.Time{})})
	if be.builds != 2 || len(be.sets[KindBan]) != 1 {
		t.Errorf("rebuild: builds=%d sets=%v", be.builds, be.sets[KindBan])
	}
	// Full mode rebuilds once.
	m.SetMode(Full)
	m.SetMode(Full)
	if be.builds != 3 || be.mode != Full {
		t.Errorf("mode: builds=%d mode=%v", be.builds, be.mode)
	}
	// The watchdog rebuilds when the rules vanished, and says so.
	be.present = false
	reset, err := m.Ensure()
	if err != nil || !reset || be.builds != 4 {
		t.Errorf("Ensure: %v %v builds=%d", reset, err, be.builds)
	}
	reset, _ = m.Ensure()
	if reset {
		t.Error("Ensure reset twice")
	}
}

func TestManagerCappedTimeout(t *testing.T) {
	be := &fakeBackend{max: 24 * time.Hour}
	m := NewManager(be, Caps{})
	now := time.Unix(1_000_000, 0)
	m.now = func() time.Time { return now }
	m.SetMode(Full)
	m.Set(KindBan, []Element{el("203.0.113.7/32", now.Add(30*24*time.Hour))})
	if len(be.changes) != 1 {
		t.Fatalf("changes = %q", be.changes)
	}
	if a := m.applied[KindBan][netip.MustParsePrefix("203.0.113.7/32")]; !a.kernel.Equal(now.Add(24 * time.Hour)) {
		t.Errorf("kernel expiry = %v", a.kernel)
	}
	// A day later the kernel dropped it: loaded again.
	now = now.Add(24*time.Hour + time.Minute)
	m.Set(KindBan, []Element{el("203.0.113.7/32", now.Add(29*24*time.Hour-time.Minute))})
	if len(be.changes) != 2 || !strings.Contains(be.changes[1], "+203.0.113.7/32") || strings.Contains(be.changes[1], "-") {
		t.Errorf("changes = %q", be.changes)
	}
}

func TestNFTRuleset(t *testing.T) {
	var scripts []string
	n := &NFT{Run: func(stdin, name string, args ...string) ([]byte, error) {
		scripts = append(scripts, stdin)
		return nil, nil
	}, Now: func() time.Time { return time.Unix(1_000_000, 0) }}
	var sets [numKinds][]Element
	sets[KindBan] = []Element{el("203.0.113.7/32", time.Unix(1_003_600, 0)), el("2001:db8::/32", time.Time{})}
	sets[KindC2] = []Element{el("192.0.2.66/32", time.Time{})}
	if err := n.Build(Learning, sets, Caps{Bans: 10, C2: 10}); err != nil {
		t.Fatal(err)
	}
	s := scripts[0]
	for _, want := range []string{
		"add table inet infrafence\ndelete table inet infrafence\ntable inet infrafence {",
		"priority filter - 5",
		"add element inet infrafence ban4 { 203.0.113.7 timeout 3600s }",
		"add element inet infrafence ban6 { 2001:db8::/32 }",
		"add element inet infrafence c2v4 { 192.0.2.66 }",
		"update @hits4 { ip saddr . ip daddr } counter\n",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("ruleset lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "drop") {
		t.Error("learning ruleset drops")
	}
	n.Build(Full, sets, Caps{})
	if !strings.Contains(scripts[1], "ip saddr @ban4 counter drop") || strings.Contains(scripts[1], "fw4") {
		t.Errorf("full ruleset:\n%s", scripts[1])
	}
	n.Change(KindBan, []Element{el("198.51.100.1/32", time.Time{})}, []netip.Prefix{netip.MustParsePrefix("203.0.113.7/32")})
	if scripts[2] != "delete element inet infrafence ban4 { 203.0.113.7 }\nadd element inet infrafence ban4 { 198.51.100.1 }\n" {
		t.Errorf("change = %q", scripts[2])
	}
}

func TestParseNFTHits(t *testing.T) {
	raw := `{"nftables": [{"metainfo": {"version": "1.1.1"}}, {"set": {"family": "inet", "name": "hits4", "table": "infrafence", "type": ["ipv4_addr", "ipv4_addr"], "flags": ["timeout", "dynamic"], "timeout": 3600, "size": 4096,
	"elem": [{"elem": {"val": {"concat": ["10.0.2.15", "9.9.9.9"]}, "timeout": 3600, "expires": 3590, "counter": {"packets": 3, "bytes": 180}}}, {"concat": ["192.168.1.20", "203.0.113.5"]}, {"concat": ["bad"]}]}}]}`
	h, err := parseNFTHits([]byte(raw))
	if err != nil || len(h) != 2 {
		t.Fatalf("hits = %v, %v", h, err)
	}
	if h[0].Src.String() != "10.0.2.15" || h[0].Dst.String() != "9.9.9.9" || h[0].Packets != 3 {
		t.Errorf("hit 0 = %+v", h[0])
	}
	if _, err := parseNFTHits([]byte("not json")); err == nil {
		t.Error("bad json accepted")
	}
}

func TestNFTPresent(t *testing.T) {
	out := "table inet fw4 {\n\tchain input {\n\t}\n}\ntable inet infrafence {\n\tchain input {\n\t\ttype filter hook input priority filter - 5; policy accept;\n\t}\n\tchain forward {\n\t}\n\tchain output {\n\t}\n}\n"
	n := &NFT{Run: func(stdin, name string, args ...string) ([]byte, error) { return []byte(out), nil }}
	if ok, _ := n.Present(); !ok {
		t.Error("present: false")
	}
	out = "table inet fw4 {\n\tchain input {\n\t}\n\tchain forward {\n\t}\n\tchain output {\n\t}\n}\n"
	if ok, _ := n.Present(); ok {
		t.Error("fw4 chains counted as ours")
	}
}

func TestIPT(t *testing.T) {
	var calls []string
	ip := &IPT{IPv6: true, Now: func() time.Time { return time.Unix(1_000_000, 0) }, Run: func(stdin, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " ")+"\n"+stdin)
		if name == "ipset" && len(args) == 2 && args[1] == "list" {
			return []byte("infrafence-ban4\n"), nil
		}
		if len(args) > 1 && args[1] == "-C" {
			return nil, errors.New("no rule")
		}
		return nil, nil
	}}
	var sets [numKinds][]Element
	sets[KindBan] = []Element{el("203.0.113.7/32", time.Unix(1_003_600, 0)), el("2001:db8::/32", time.Time{})}
	if err := ip.Build(Full, sets, Caps{Bans: 100}); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(calls, "\n")
	for _, want := range []string{
		"create infrafence-ban4-n hash:net family inet",
		"add infrafence-ban4-n 203.0.113.7/32 timeout 3600",
		"swap infrafence-ban4-n infrafence-ban4\ndestroy infrafence-ban4-n",
		"rename infrafence-ban6-n infrafence-ban6",
		"add infrafence-ban6-n 2001:db8::/32",
		"-A INFRAFENCE_FWD -m set --match-set infrafence-c2v4 dst -j SET --add-set infrafence-hit4 src,dst --exist --timeout 3600",
		"-A INFRAFENCE_IN -m set --match-set infrafence-ban4 src -j DROP",
		"iptables -w -I INPUT 1 -j INFRAFENCE_IN",
		"ip6tables -w -I FORWARD 1 -j INFRAFENCE_FWD",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in:\n%s", want, all)
		}
	}
	h := parseIPSetHits([]byte("create infrafence-hit4 hash:net,net family inet hashsize 1024 maxelem 4096 timeout 3600\nadd infrafence-hit4 10.0.2.15,9.9.9.9 timeout 3550\n"))
	if len(h) != 1 || h[0].Src.String() != "10.0.2.15" || h[0].Dst.String() != "9.9.9.9" {
		t.Errorf("hits = %v", h)
	}
}
