package fw

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Table is the nftables table the agent owns. fw4 only flushes and
// rebuilds "table inet fw4", so this one survives `fw4 reload`.
const Table = "infrafence"

// hitTimeout is how long the kernel keeps a (device, C2) pair.
const hitTimeout = time.Hour

// NFT is the nftables backend (OpenWrt 22.03+ with fw4, or plain nftables).
type NFT struct {
	Run Runner
	Now func() time.Time
}

func NewNFT() *NFT { return &NFT{Run: execRunner, Now: time.Now} }

func (*NFT) Name() string              { return "nftables" }
func (*NFT) MaxTimeout() time.Duration { return 0 }

var nftSetNames = [numKinds][2]string{{"ban4", "ban6"}, {"feed4", "feed6"}, {"c2v4", "c2v6"}}

// ruleset is the whole table. "add table; delete table; table {...}" in one
// `nft -f` transaction replaces it atomically (and works whether it existed
// or not). Priority filter - 5: before fw4's own chains.
func (n *NFT) ruleset(mode Mode, caps Caps) string {
	drop := ""
	if mode == Full {
		drop = " drop"
	}
	size := func(c int) string {
		if c <= 0 {
			return ""
		}
		// Interval sets may store a range as two kernel elements; room for
		// that and for what is added before old entries go.
		return fmt.Sprintf(" size %d;", 2*c+64)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "add table inet %s\ndelete table inet %s\ntable inet %s {\n", Table, Table, Table)
	fmt.Fprintf(&b, "\tset ban4 { type ipv4_addr; flags interval, timeout;%s }\n", size(caps.Bans))
	fmt.Fprintf(&b, "\tset ban6 { type ipv6_addr; flags interval, timeout;%s }\n", size(caps.Bans))
	fmt.Fprintf(&b, "\tset feed4 { type ipv4_addr; flags interval;%s }\n", size(caps.Bans))
	fmt.Fprintf(&b, "\tset feed6 { type ipv6_addr; flags interval;%s }\n", size(caps.Bans))
	fmt.Fprintf(&b, "\tset c2v4 { type ipv4_addr; flags interval, timeout;%s }\n", size(caps.C2))
	fmt.Fprintf(&b, "\tset c2v6 { type ipv6_addr; flags interval, timeout;%s }\n", size(caps.C2))
	// Filled by the kernel: which LAN device reached which C2 address, with
	// a packet counter. Bounded; entries expire after an hour.
	fmt.Fprintf(&b, "\tset hits4 { type ipv4_addr . ipv4_addr; flags dynamic, timeout; timeout %ds; size 4096; counter; }\n", int(hitTimeout.Seconds()))
	fmt.Fprintf(&b, "\tset hits6 { type ipv6_addr . ipv6_addr; flags dynamic, timeout; timeout %ds; size 4096; counter; }\n", int(hitTimeout.Seconds()))
	inbound := "\t\tip saddr @ban4 counter" + drop + "\n" +
		"\t\tip6 saddr @ban6 counter" + drop + "\n" +
		"\t\tip saddr @feed4 counter" + drop + "\n" +
		"\t\tip6 saddr @feed6 counter" + drop + "\n"
	c2 := "\t\tip daddr @c2v4 update @hits4 { ip saddr . ip daddr } counter" + drop + "\n" +
		"\t\tip6 daddr @c2v6 update @hits6 { ip6 saddr . ip6 daddr } counter" + drop + "\n"
	b.WriteString("\tchain input {\n\t\ttype filter hook input priority filter - 5; policy accept;\n" + inbound + "\t}\n")
	b.WriteString("\tchain forward {\n\t\ttype filter hook forward priority filter - 5; policy accept;\n" + inbound + c2 + "\t}\n")
	b.WriteString("\tchain output {\n\t\ttype filter hook output priority filter - 5; policy accept;\n" + c2 + "\t}\n")
	b.WriteString("}\n")
	return b.String()
}

func nftElement(e Element, now time.Time) string {
	s := e.Prefix.String()
	if e.Prefix.Bits() == e.Prefix.Addr().BitLen() {
		s = e.Prefix.Addr().String()
	}
	if t := timeoutSecs(e.Expires, now); t > 0 {
		s += fmt.Sprintf(" timeout %ds", t)
	}
	return s
}

// elementLines writes "add element" statements, a few hundred elements per
// statement (one huge statement costs nft a lot of memory to parse).
func elementLines(b *strings.Builder, verb, set string, items []string) {
	const chunk = 500
	for i := 0; i < len(items); i += chunk {
		j := min(i+chunk, len(items))
		fmt.Fprintf(b, "%s element inet %s %s { %s }\n", verb, Table, set, strings.Join(items[i:j], ", "))
	}
}

func split(els []Element, now time.Time) (v4, v6 []string) {
	for _, e := range els {
		if e.Prefix.Addr().Is4() {
			v4 = append(v4, nftElement(e, now))
		} else {
			v6 = append(v6, nftElement(e, now))
		}
	}
	return
}

func (n *NFT) Build(mode Mode, sets [numKinds][]Element, caps Caps) error {
	now := n.Now()
	var b strings.Builder
	b.WriteString(n.ruleset(mode, caps))
	for k := Kind(0); k < numKinds; k++ {
		v4, v6 := split(sets[k], now)
		elementLines(&b, "add", nftSetNames[k][0], v4)
		elementLines(&b, "add", nftSetNames[k][1], v6)
	}
	_, err := n.Run(b.String(), "nft", "-f", "-")
	return err
}

func (n *NFT) Change(kind Kind, add []Element, del []netip.Prefix) error {
	now := n.Now()
	var b strings.Builder
	var d4, d6 []string
	for _, p := range del {
		s := p.String()
		if p.Bits() == p.Addr().BitLen() {
			s = p.Addr().String()
		}
		if p.Addr().Is4() {
			d4 = append(d4, s)
		} else {
			d6 = append(d6, s)
		}
	}
	elementLines(&b, "delete", nftSetNames[kind][0], d4)
	elementLines(&b, "delete", nftSetNames[kind][1], d6)
	a4, a6 := split(add, now)
	elementLines(&b, "add", nftSetNames[kind][0], a4)
	elementLines(&b, "add", nftSetNames[kind][1], a6)
	if b.Len() == 0 {
		return nil
	}
	_, err := n.Run(b.String(), "nft", "-f", "-")
	return err
}

// Present checks the table and its three chains exist.
func (n *NFT) Present() (bool, error) {
	out, err := n.Run("", "nft", "list", "chains", "inet")
	if err != nil {
		// No inet chains at all (flushed ruleset) is not an error of nft
		// on every version: treat a failure as "not present".
		return false, nil
	}
	s := string(out)
	cur := ""
	found := 0
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "table inet ") {
			cur = strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(l, "table inet ")), " {")
			continue
		}
		if cur == Table && strings.HasPrefix(l, "chain ") {
			switch strings.Fields(l)[1] {
			case "input", "forward", "output":
				found++
			}
		}
	}
	return found == 3, nil
}

// Hits lists the (device, C2) pairs the kernel recorded.
func (n *NFT) Hits() ([]Hit, error) {
	var out []Hit
	for _, set := range []string{"hits4", "hits6"} {
		raw, err := n.Run("", "nft", "-j", "list", "set", "inet", Table, set)
		if err != nil {
			return out, err
		}
		h, err := parseNFTHits(raw)
		if err != nil {
			return out, err
		}
		out = append(out, h...)
	}
	return out, nil
}

// parseNFTHits reads `nft -j list set` output. Elements are either a bare
// concat ({"concat": [...]}) or {"elem": {"val": {"concat": [...]},
// "counter": {...}}} depending on the nft version and set flags.
func parseNFTHits(raw []byte) ([]Hit, error) {
	var doc struct {
		Nftables []struct {
			Set *struct {
				Elem []json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("nft json: %w", err)
	}
	type concat struct {
		Concat []string `json:"concat"`
	}
	var out []Hit
	for _, o := range doc.Nftables {
		if o.Set == nil {
			continue
		}
		for _, el := range o.Set.Elem {
			var wrapped struct {
				Elem *struct {
					Val     concat `json:"val"`
					Counter *struct {
						Packets uint64 `json:"packets"`
					} `json:"counter"`
				} `json:"elem"`
			}
			var pair []string
			var packets uint64
			if json.Unmarshal(el, &wrapped) == nil && wrapped.Elem != nil {
				pair = wrapped.Elem.Val.Concat
				if wrapped.Elem.Counter != nil {
					packets = wrapped.Elem.Counter.Packets
				}
			} else {
				var c concat
				if json.Unmarshal(el, &c) == nil {
					pair = c.Concat
				}
			}
			if len(pair) != 2 {
				continue
			}
			src, err1 := netip.ParseAddr(pair[0])
			dst, err2 := netip.ParseAddr(pair[1])
			if err1 != nil || err2 != nil {
				continue
			}
			out = append(out, Hit{Src: src, Dst: dst, Packets: packets})
		}
	}
	return out, nil
}

func (n *NFT) Teardown() error {
	// "add" first so the delete succeeds even when it is already gone.
	_, err := n.Run(fmt.Sprintf("add table inet %s\ndelete table inet %s\n", Table, Table), "nft", "-f", "-")
	return err
}
