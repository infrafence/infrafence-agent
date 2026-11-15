// Package fw enforces bans and C2 blocking on a router's firewall, in rules
// and sets of its own: table inet infrafence on nftables (fw4), or the
// INFRAFENCE_* chains and infrafence-* ipsets on iptables (fw3). It never
// edits the firewall's own table or chains, so `fw4 reload` and
// `firewall restart` leave it alone and removing it leaves the router as
// it was.
//
// Four kinds of entries, one set each per address family:
//
//	ban   addresses the organization banned (dashboard bans and block rules), with expiry
//	feed  InfraFence network threat feed (attackers), no expiry
//	c2    command-and-control / malware hosts LAN devices must not reach
//	hits  (LAN device, C2 address) pairs the kernel saw, polled by the agent
//
// In Learning mode the same rules count instead of dropping.
package fw

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

// Mode is Learning (count and report) or Full (drop).
type Mode int

const (
	Learning Mode = iota
	Full
)

func (m Mode) String() string {
	if m == Full {
		return "full"
	}
	return "learning"
}

// Kind is one of the entry sets.
type Kind int

const (
	KindBan Kind = iota
	KindFeed
	KindC2
	numKinds
)

func (k Kind) name() string { return [...]string{"ban", "feed", "c2"}[k] }

// Hit is a LAN device (or the router itself) talking to a C2 address.
type Hit struct {
	Src, Dst netip.Addr
	Packets  uint64 // 0 when the backend does not count per pair
}

// Element is one entry of a set: a prefix and its expiry (zero: none).
type Element struct {
	Prefix  netip.Prefix
	Expires time.Time
}

// Backend is a firewall implementation.
type Backend interface {
	Name() string
	// Build (re)creates the rules and loads every element, atomically
	// where the backend can.
	Build(mode Mode, sets [numKinds][]Element, caps Caps) error
	// Change adds and removes elements of one set.
	Change(kind Kind, add []Element, del []netip.Prefix) error
	// Present says whether the rules are in place (false after someone
	// flushed the ruleset).
	Present() (bool, error)
	Hits() ([]Hit, error)
	Teardown() error
	// MaxTimeout is the longest element timeout the backend supports
	// (0: no limit). Longer bans are loaded with it and loaded again when
	// the kernel drops them.
	MaxTimeout() time.Duration
}

// Caps bound the sets (kernel memory).
type Caps struct {
	Bans int // ban + feed entries per family
	C2   int
}

// Runner runs a command with stdin; replaced in tests.
type Runner func(stdin, name string, args ...string) ([]byte, error)

func execRunner(stdin, name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err != nil {
		msg := strings.TrimSpace(out.String())
		if len(msg) > 400 {
			msg = msg[:400] + "..."
		}
		return out.Bytes(), fmt.Errorf("%s: %v: %s", name, err, msg)
	}
	return out.Bytes(), nil
}

// Manager keeps the wanted state and brings the backend to it.
type Manager struct {
	be  Backend
	now func() time.Time

	mu      sync.Mutex
	mode    Mode
	caps    Caps
	want    [numKinds]map[netip.Prefix]time.Time
	applied [numKinds]map[netip.Prefix]applied
	built   bool
	dropped [numKinds]int // entries over the cap at the last Set
}

func NewManager(be Backend, caps Caps) *Manager {
	m := &Manager{be: be, now: time.Now, caps: caps}
	for k := range m.want {
		m.want[k] = map[netip.Prefix]time.Time{}
		m.applied[k] = map[netip.Prefix]applied{}
	}
	return m
}

// applied is an element as loaded: the expiry wanted and the one the kernel
// enforces (earlier when the backend caps timeouts).
type applied struct {
	want, kernel time.Time
}

// kernelExpiry is when the kernel drops an element wanted until e.
func (m *Manager) kernelExpiry(e, now time.Time) time.Time {
	if max := m.be.MaxTimeout(); max > 0 && !e.IsZero() && e.Sub(now) > max {
		return now.Add(max)
	}
	return e
}

func (m *Manager) Backend() string { return m.be.Name() }

// Mode is the mode in force.
func (m *Manager) Mode() Mode {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mode
}

// Counts are the entries applied per kind.
func (m *Manager) Counts() (bans, feed, c2 int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.applied[KindBan]), len(m.applied[KindFeed]), len(m.applied[KindC2])
}

// Dropped is how many entries of a kind were left out by the cap.
func (m *Manager) Dropped(k Kind) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dropped[k]
}

// SetMode switches mode; the rules are rebuilt (one transaction on nft).
func (m *Manager) SetMode(mode Mode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.built && mode == m.mode {
		return nil
	}
	m.mode = mode
	return m.buildLocked()
}

// SetCaps changes the caps; takes effect at the next Set and Build.
func (m *Manager) SetCaps(c Caps) {
	m.mu.Lock()
	m.caps = c
	m.mu.Unlock()
}

// Set replaces the wanted entries of one kind and applies the difference.
// Entries must already have passed the guard.
func (m *Manager) Set(kind Kind, els []Element) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	limit := m.caps.Bans
	if kind == KindC2 {
		limit = m.caps.C2
	}
	want, dropped := normalize(els, now, limit)
	m.dropped[kind] = dropped
	m.want[kind] = want
	if !m.built {
		return m.buildLocked()
	}
	return m.syncLocked(kind, now)
}

// Add adds entries of one kind to the wanted state without removing others
// (C2 addresses learned from DNS answers).
func (m *Manager) Add(kind Kind, els []Element) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	all := make([]Element, 0, len(m.want[kind])+len(els))
	for p, e := range m.want[kind] {
		all = append(all, Element{Prefix: p, Expires: e})
	}
	all = append(all, els...)
	limit := m.caps.Bans
	if kind == KindC2 {
		limit = m.caps.C2
	}
	m.want[kind], _ = normalize(all, now, limit)
	if !m.built {
		return m.buildLocked()
	}
	return m.syncLocked(kind, now)
}

// syncLocked applies want[kind] - applied[kind] as one change; on failure
// (an element the kernel already expired, a set someone emptied) the whole
// ruleset is rebuilt.
func (m *Manager) syncLocked(kind Kind, now time.Time) error {
	var add []Element
	var del []netip.Prefix
	for p, a := range m.applied[kind] {
		if !a.kernel.IsZero() && !a.kernel.After(now.Add(5*time.Second)) {
			// The kernel expires it on its own (or just did): deleting it
			// could fail the whole transaction. Still wanted (a ban longer
			// than the backend's longest timeout): loaded again below.
			delete(m.applied[kind], p)
			continue
		}
		if we, ok := m.want[kind][p]; !ok || !we.Equal(a.want) {
			del = append(del, p)
		}
	}
	var addWant []time.Time
	for p, e := range m.want[kind] {
		if a, ok := m.applied[kind][p]; !ok || !a.want.Equal(e) {
			add = append(add, Element{Prefix: p, Expires: e})
		}
	}
	if len(add) == 0 && len(del) == 0 {
		return nil
	}
	sortElements(add)
	addWant = make([]time.Time, len(add))
	for i := range add {
		addWant[i] = add[i].Expires
		add[i].Expires = m.kernelExpiry(add[i].Expires, now)
	}
	sort.Slice(del, func(i, j int) bool { return del[i].String() < del[j].String() })
	if err := m.be.Change(kind, add, del); err != nil {
		if berr := m.buildLocked(); berr != nil {
			return fmt.Errorf("%v; rebuild: %w", err, berr)
		}
		return nil
	}
	for _, p := range del {
		delete(m.applied[kind], p)
	}
	for i, e := range add {
		m.applied[kind][e.Prefix] = applied{want: addWant[i], kernel: e.Expires}
	}
	return nil
}

func (m *Manager) buildLocked() error {
	now := m.now()
	var sets [numKinds][]Element
	for k := range m.want {
		for p, e := range m.want[k] {
			if !e.IsZero() && !e.After(now) {
				delete(m.want[k], p)
				continue
			}
			sets[k] = append(sets[k], Element{Prefix: p, Expires: m.kernelExpiry(e, now)})
		}
		sortElements(sets[k])
	}
	if err := m.be.Build(m.mode, sets, m.caps); err != nil {
		m.built = false
		return err
	}
	m.built = true
	for k := range sets {
		m.applied[k] = make(map[netip.Prefix]applied, len(sets[k]))
		for _, e := range sets[k] {
			m.applied[k][e.Prefix] = applied{want: m.want[k][e.Prefix], kernel: e.Expires}
		}
	}
	return nil
}

// Ensure checks the rules are in place and rebuilds them when they are not
// (someone ran `nft flush ruleset`, fw3 flushed the chains). It returns
// true when it had to rebuild.
func (m *Manager) Ensure() (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	wasBuilt := m.built
	ok, err := m.be.Present()
	if err == nil && ok && m.built {
		return false, nil
	}
	if berr := m.buildLocked(); berr != nil {
		return false, errors.Join(err, berr)
	}
	return wasBuilt, nil
}

func (m *Manager) Hits() ([]Hit, error) { return m.be.Hits() }

// Teardown removes everything the agent added to the firewall.
func (m *Manager) Teardown() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.built = false
	for k := range m.applied {
		m.applied[k] = map[netip.Prefix]applied{}
	}
	return m.be.Teardown()
}

// normalize drops expired entries and entries inside another entry of the
// same set (interval sets refuse overlaps), keeps the longest expiry of
// duplicates, and keeps at most limit entries per family (the widest
// first). It returns how many entries the limit left out.
func normalize(els []Element, now time.Time, limit int) (map[netip.Prefix]time.Time, int) {
	best := map[netip.Prefix]time.Time{}
	for _, e := range els {
		if !e.Prefix.IsValid() || !e.Expires.IsZero() && !e.Expires.After(now) {
			continue
		}
		p := e.Prefix.Masked()
		if old, ok := best[p]; ok && (old.IsZero() || !e.Expires.IsZero() && old.After(e.Expires)) {
			continue
		}
		best[p] = e.Expires
	}
	list := make([]Element, 0, len(best))
	for p, e := range best {
		list = append(list, Element{Prefix: p, Expires: e})
	}
	// Widest first, so a contained prefix finds its container already kept.
	sort.Slice(list, func(i, j int) bool {
		a, b := list[i].Prefix, list[j].Prefix
		if a.Bits() != b.Bits() {
			return a.Bits() < b.Bits()
		}
		return a.Addr().Less(b.Addr())
	})
	var kept4, kept6 []netip.Prefix
	out := map[netip.Prefix]time.Time{}
	dropped := 0
	for _, e := range list {
		kept := &kept6
		if e.Prefix.Addr().Is4() {
			kept = &kept4
		}
		inside := false
		for _, k := range *kept {
			if k.Bits() < e.Prefix.Bits() && k.Contains(e.Prefix.Addr()) {
				inside = true
				break
			}
		}
		if inside {
			continue
		}
		if limit > 0 && len(*kept) >= limit {
			dropped++
			continue
		}
		*kept = append(*kept, e.Prefix)
		out[e.Prefix] = e.Expires
	}
	return out, dropped
}

func sortElements(els []Element) {
	sort.Slice(els, func(i, j int) bool { return els[i].Prefix.String() < els[j].Prefix.String() })
}

// timeoutSecs is the remaining lifetime of an element in whole seconds (at
// least 1), or 0 for none.
func timeoutSecs(e time.Time, now time.Time) int64 {
	if e.IsZero() {
		return 0
	}
	s := int64(e.Sub(now).Seconds())
	if s < 1 {
		s = 1
	}
	return s
}
