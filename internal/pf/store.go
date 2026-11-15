package pf

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ErrNoTables: the plugin's aliases are not in the loaded ruleset (plugin
// removed or disabled, filter not reloaded yet). The agent then blocks
// nothing and reports it: it never creates tables or rules itself.
var ErrNoTables = errors.New("no loaded rule uses the InfraFence pf tables (os-infrafence missing or disabled): detect-only")

// Guard says which addresses must never be blocked on this firewall.
type Guard interface {
	// Why returns why ip must not be banned, "" when it may.
	Why(ip net.IP) string
	// Nets are the protected networks, added negated ("!net") to every
	// table: even a wrong entry can never block them.
	Nets() []string
	// Overlaps returns why network n covers a protected address ("" when
	// it does not).
	Overlaps(n *net.IPNet) string
}

// alwaysNegated are added "!net" to every table whatever the guard says:
// a wrong feed or ban can never block the firewall's own networks.
var alwaysNegated = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"fc00::/7", "fe80::/10", "::1"}

// Ban is one banned address.
type Ban struct {
	IP      string    `json:"ip"`
	Expires time.Time `json:"expires,omitzero"` // zero: until removed
	Reason  string    `json:"reason,omitempty"`
	// Source: "local" (detected here, not yet listed by the dashboard) or
	// "dashboard" (listed by the last sync: network, org or manual ban).
	Source string    `json:"source"`
	Added  time.Time `json:"added"`
}

// Store keeps the desired contents of the tables and writes them to pf.
// All methods are safe for concurrent use.
type Store struct {
	mu      sync.Mutex
	ctl     *Ctl
	guard   Guard
	state   string
	bans    map[string]Ban
	allow   []*net.IPNet
	allowS  []string
	sets    map[string][]string // threat, geo: desired positive entries
	monitor bool
	ready   bool // tables present in the ruleset
	limit   int
	lastErr string
	now     func() time.Time
}

// NewStore returns a store writing through ctl, keeping its bans in state
// (a JSON file, 0600; "" keeps nothing).
func NewStore(ctl *Ctl, guard Guard, state string) *Store {
	return &Store{ctl: ctl, guard: guard, state: state, bans: map[string]Ban{}, sets: map[string][]string{}, now: time.Now}
}

// Load reads the saved bans (after a reboot pf starts with empty tables):
// expired ones are dropped. Returns how many were restored.
func (s *Store) Load() int {
	if s.state == "" {
		return 0
	}
	data, err := os.ReadFile(s.state)
	if err != nil {
		return 0
	}
	var saved struct {
		Bans []Ban `json:"bans"`
	}
	if json.Unmarshal(data, &saved) != nil {
		log.Printf("[pf] %s unreadable, starting without saved bans", s.state)
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	n := 0
	for _, b := range saved.Bans {
		key, ok := normalize(b.IP)
		if !ok || (!b.Expires.IsZero() && !b.Expires.After(now)) {
			continue
		}
		if s.refusalLocked(key) != "" {
			continue // saved before a fix, or the guard changed since
		}
		b.IP = key
		s.bans[key] = b
		n++
	}
	return n
}

func (s *Store) saveLocked() {
	if s.state == "" {
		return
	}
	list := make([]Ban, 0, len(s.bans))
	for _, b := range s.bans {
		list = append(list, b)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].IP < list[j].IP })
	data, err := json.Marshal(map[string]any{"bans": list})
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(s.state), 0o700); err != nil {
		log.Printf("[pf] state: %v", err)
		return
	}
	tmp := s.state + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		log.Printf("[pf] state: %v", err)
		return
	}
	if err := os.Rename(tmp, s.state); err != nil {
		log.Printf("[pf] state: %v", err)
	}
}

// normalize returns the table form of an address or network: a host as
// the bare address, a network masked ("10.0.0.0/8"). ok is false for
// anything else.
func normalize(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || strings.ContainsAny(s, " \t\n!") {
		return "", false
	}
	if strings.Contains(s, "/") {
		ip, n, err := net.ParseCIDR(s)
		if err != nil {
			return "", false
		}
		ones, bits := n.Mask.Size()
		if ones == bits {
			return ip.String(), true
		}
		return n.String(), true
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return "", false
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip.String(), true
}

func hostIP(key string) net.IP {
	if i := strings.IndexByte(key, '/'); i >= 0 {
		key = key[:i]
	}
	return net.ParseIP(key)
}

// Reserved is why an address can never be banned on a firewall whatever
// the configuration says: own, private, link-local, multicast and other
// special-use ranges ("" for a public address).
func Reserved(ip net.IP) string {
	switch {
	case ip == nil:
		return "invalid address"
	case ip.IsUnspecified(), ip.IsLoopback():
		return "loopback or unspecified address"
	case ip.IsPrivate():
		return "private (internal) address"
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast(), ip.IsMulticast(), ip.IsInterfaceLocalMulticast():
		return "link-local or multicast address"
	}
	for _, n := range reservedNets {
		if n.Contains(ip) {
			return "reserved address range"
		}
	}
	return ""
}

// overlapNets: what no network entry may overlap (reserved plus private).
func overlapNets() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4",
		"fc00::/7", "fe80::/10", "ff00::/8", "::/128", "::1/128"} {
		_, n, _ := net.ParseCIDR(c)
		out = append(out, n)
	}
	return append(out, reservedNets...)
}

var reservedNets = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15",
		"240.0.0.0/4", "255.255.255.255/32", "64:ff9b::/96", "100::/64"} {
		_, n, _ := net.ParseCIDR(c)
		out = append(out, n)
	}
	return out
}()

// refusal is why ip may not be banned ("" when it may). Caller holds mu.
func (s *Store) refusalLocked(key string) string {
	ip := hostIP(key)
	if why := Reserved(ip); why != "" {
		return why
	}
	if strings.Contains(key, "/") {
		// A network ban never covers a protected or allow-listed address.
		if why := s.networkRefusal(key, 16, 32); why != "" {
			if why == "network too large" {
				return "network too large to ban"
			}
			return why
		}
		_, n, _ := net.ParseCIDR(key)
		for _, a := range s.allow {
			if n.Contains(a.IP) || a.Contains(n.IP) {
				return "overlaps the allow list"
			}
		}
	}
	for _, a := range s.allow {
		if a.Contains(ip) {
			return "allow-listed"
		}
	}
	if s.guard != nil {
		if why := s.guard.Why(ip); why != "" {
			return why
		}
	}
	return ""
}

func overlaps(a, b *net.IPNet) bool { return a.Contains(b.IP) || b.Contains(a.IP) }

// networkRefusal is why network entry key (a CIDR) may not go into a
// table: too large, or covering private, reserved or protected space.
func (s *Store) networkRefusal(key string, maxV4, maxV6 int) string {
	_, n, err := net.ParseCIDR(key)
	if err != nil {
		return "invalid network"
	}
	if ones, bits := n.Mask.Size(); (bits == 32 && ones < maxV4) || (bits == 128 && ones < maxV6) {
		return "network too large"
	}
	for _, r := range overlapNets() {
		if overlaps(n, r) {
			return "network covers private or reserved addresses"
		}
	}
	if s.guard != nil {
		if why := s.guard.Overlaps(n); why != "" {
			return "network covers " + why
		}
	}
	return ""
}

// Why returns why ip may not be banned here ("" when it may).
func (s *Store) Why(ip string) string {
	key, ok := normalize(ip)
	if !ok {
		return "invalid address"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refusalLocked(key)
}

// Ban bans ip until expires (zero: until removed). added is false when ip
// was already banned (the expiry may be extended) or refused, with why.
// In Learning (monitor) mode nothing is banned: why is "learning".
func (s *Store) Ban(ip string, expires time.Time, reason, source string) (added bool, why string, err error) {
	key, ok := normalize(ip)
	if !ok {
		return false, "invalid address", nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if why := s.refusalLocked(key); why != "" {
		return false, why, nil
	}
	if s.monitor {
		return false, "learning", nil
	}
	if b, ok := s.bans[key]; ok {
		if !b.Expires.IsZero() && (expires.IsZero() || expires.After(b.Expires)) {
			b.Expires = expires
			s.bans[key] = b
			s.saveLocked()
		}
		return false, "", nil
	}
	// pf's table-entries limit is shared with OPNsense's own aliases: the
	// agent's tables keep to half of it.
	if s.limit > 0 && s.entriesLocked()+1 > s.limit/2 {
		return false, "", fmt.Errorf("pf table-entries limit (%d) almost reached: not banning %s", s.limit, key)
	}
	s.bans[key] = Ban{IP: key, Expires: expires, Reason: reason, Source: source, Added: s.now()}
	s.saveLocked()
	if s.ready {
		if err := s.ctl.Add(TableBans, key); err != nil {
			s.lastErr = err.Error()
			return true, "", err
		}
		s.ctl.KillStates(key)
	}
	return true, "", nil
}

// Unban removes ip. Reports whether it was banned.
func (s *Store) Unban(ip string) (bool, error) {
	key, ok := normalize(ip)
	if !ok {
		return false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.bans[key]; !ok {
		return false, nil
	}
	delete(s.bans, key)
	s.saveLocked()
	if s.ready && !s.monitor {
		if err := s.ctl.Delete(TableBans, key); err != nil {
			s.lastErr = err.Error()
			return true, err
		}
	}
	return true, nil
}

// IsBanned reports whether ip is in the bans.
func (s *Store) IsBanned(ip string) bool {
	key, ok := normalize(ip)
	if !ok {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok = s.bans[key]
	return ok
}

// Bans lists the bans.
func (s *Store) Bans() []Ban {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := make([]Ban, 0, len(s.bans))
	for _, b := range s.bans {
		list = append(list, b)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].IP < list[j].IP })
	return list
}

// SyncBans applies the dashboard's ban list: listed bans are added (or
// take over a local one), dashboard bans no longer listed are removed.
// Local bans not listed yet stay until they expire (the dashboard lists
// them once the report reached it). Returns the counts added and removed.
func (s *Store) SyncBans(list []Ban) (added, removed int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	want := map[string]Ban{}
	for _, b := range list {
		key, ok := normalize(b.IP)
		if !ok || s.refusalLocked(key) != "" {
			continue
		}
		b.IP, b.Source = key, "dashboard"
		want[key] = b
	}
	now := s.now()
	for key, b := range s.bans {
		if b.Source == "dashboard" {
			if _, ok := want[key]; !ok {
				delete(s.bans, key)
				removed++
			}
		}
	}
	for key, b := range want {
		if !b.Expires.IsZero() && !b.Expires.After(now) {
			continue
		}
		cur, ok := s.bans[key]
		if !ok {
			added++
			b.Added = now
		} else {
			b.Added = cur.Added
			if b.Reason == "" {
				b.Reason = cur.Reason
			}
		}
		s.bans[key] = b
	}
	s.saveLocked()
	if s.ready {
		if err := s.writeLocked(TableBans); err != nil {
			s.lastErr = err.Error()
		}
	}
	return added, removed
}

// Expire removes the bans expired at now and returns them.
func (s *Store) Expire(now time.Time) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var gone []string
	for key, b := range s.bans {
		if !b.Expires.IsZero() && !b.Expires.After(now) {
			delete(s.bans, key)
			gone = append(gone, key)
		}
	}
	if len(gone) == 0 {
		return nil
	}
	sort.Strings(gone)
	s.saveLocked()
	if s.ready && !s.monitor {
		if err := s.ctl.Delete(TableBans, gone...); err != nil {
			s.lastErr = err.Error()
		}
	}
	return gone
}

// SetAllowList sets the dashboard's allow list (addresses and networks):
// they leave the bans and are excluded from every table.
func (s *Store) SetAllowList(entries []string) {
	var nets []*net.IPNet
	var keys []string
	for _, e := range entries {
		key, ok := normalize(e)
		if !ok {
			continue
		}
		cidr := key
		if !strings.Contains(cidr, "/") {
			if strings.Contains(cidr, ":") {
				cidr += "/128"
			} else {
				cidr += "/32"
			}
		}
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		nets = append(nets, n)
		keys = append(keys, key)
	}
	sort.Strings(keys)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.allow, s.allowS = nets, keys
	changed := false
	for key := range s.bans {
		if s.refusalLocked(key) != "" {
			delete(s.bans, key)
			changed = true
		}
	}
	if changed {
		s.saveLocked()
	}
	if s.ready {
		for _, t := range Tables {
			if err := s.writeLocked(t); err != nil {
				s.lastErr = err.Error()
			}
		}
	}
}

// maxSetEntries bounds the threat and country tables.
const maxSetEntries = 250000

// SetSet sets the threat feed or country table's networks.
func (s *Store) SetSet(table string, entries []string) error {
	if table != TableThreat && table != TableGeo {
		return fmt.Errorf("pf: SetSet(%q)", table)
	}
	seen := map[string]bool{}
	var list []string
	for _, e := range entries {
		key, ok := normalize(e)
		if !ok || seen[key] {
			continue
		}
		// A threat or country network never covers private, reserved or
		// protected space (a /1 "feed entry" would block the LAN).
		if Reserved(hostIP(key)) != "" {
			continue
		}
		if strings.Contains(key, "/") && s.networkRefusal(key, 8, 19) != "" {
			continue
		}
		if s.guard != nil && !strings.Contains(key, "/") && s.guard.Why(hostIP(key)) != "" {
			continue
		}
		seen[key] = true
		list = append(list, key)
	}
	sort.Strings(list)
	s.mu.Lock()
	defer s.mu.Unlock()
	// pf's table-entries limit is shared with OPNsense's own aliases: the
	// agent keeps to a quarter of it per set (a default without a limit).
	max := maxSetEntries
	if s.limit > 0 && s.limit/4 < max {
		max = s.limit / 4
	}
	if len(list) > max {
		log.Printf("[pf] %s: %d entries, only the first %d loaded (pf table-entries limit %d)", table, len(list), max, s.limit)
		s.lastErr = fmt.Sprintf("%s truncated to %d entries", table, max)
		list = list[:max]
	}
	s.sets[table] = list
	if !s.ready {
		return nil
	}
	return s.writeLocked(table)
}

// SetMonitor switches Learning mode: on empties every table (nothing is
// blocked, bans are still recorded by the dashboard), off fills them again.
func (s *Store) SetMonitor(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.monitor == on {
		return
	}
	s.monitor = on
	if s.ready {
		for _, t := range Tables {
			if err := s.writeLocked(t); err != nil {
				s.lastErr = err.Error()
			}
		}
	}
}

// Monitor reports Learning mode.
func (s *Store) Monitor() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.monitor
}

// desiredLocked is what table t must contain: the protected and
// allow-listed networks negated, then the entries (none in Learning mode).
func (s *Store) desiredLocked(t string) []string {
	out := append([]string(nil), negatedAlways()...)
	if s.guard != nil {
		for _, n := range s.guard.Nets() {
			if key, ok := normalize(n); ok {
				out = append(out, "!"+key)
			}
		}
	}
	for _, a := range s.allowS {
		out = append(out, "!"+a)
	}
	if s.monitor {
		return dedupe(out)
	}
	switch t {
	case TableBans:
		for key := range s.bans {
			out = append(out, key)
		}
	default:
		out = append(out, s.sets[t]...)
	}
	return dedupe(out)
}

func negatedAlways() []string {
	out := make([]string, len(alwaysNegated))
	for i, n := range alwaysNegated {
		out[i] = "!" + n
	}
	return out
}

func dedupe(in []string) []string {
	sort.Strings(in)
	out := in[:0]
	for i, v := range in {
		if i == 0 || v != in[i-1] {
			out = append(out, v)
		}
	}
	return out
}

func (s *Store) entriesLocked() int {
	n := 0
	for _, t := range Tables {
		n += len(s.desiredLocked(t))
	}
	return n
}

func (s *Store) writeLocked(t string) error {
	return s.ctl.Replace(t, s.desiredLocked(t))
}

// Ensure is the guard tick, also run at start: it checks that the tables
// are loaded and that their contents match, refilling those that drifted
// (after a reboot, or a manual flush). Returns the tables refilled, or
// ErrNoTables (detect-only until they are back).
func (s *Store) Ensure() (repaired []string, err error) {
	present, err := s.ctl.Present()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.ready = false
		s.lastErr = err.Error()
		return nil, err
	}
	for _, t := range Tables {
		if referenced, ok := present[t]; !ok || !referenced {
			if s.ready {
				log.Printf("[pf] table %s is not used by any loaded rule: detect-only until os-infrafence's rules are loaded again", t)
			}
			s.ready = false
			s.lastErr = ErrNoTables.Error()
			return nil, ErrNoTables
		}
	}
	s.ready = true
	s.limit = s.ctl.TableLimit()
	for _, t := range Tables {
		want := s.desiredLocked(t)
		have, err := s.ctl.Show(t)
		if err != nil {
			s.lastErr = err.Error()
			return repaired, err
		}
		if !sameEntries(have, want) {
			if err := s.ctl.Replace(t, want); err != nil {
				s.lastErr = err.Error()
				return repaired, err
			}
			repaired = append(repaired, t)
		}
	}
	s.lastErr = ""
	return repaired, nil
}

func sameEntries(have, want []string) bool {
	if len(have) != len(want) {
		return false
	}
	h := make([]string, len(have))
	for i, e := range have {
		neg := strings.HasPrefix(e, "!")
		k, ok := normalize(strings.TrimPrefix(e, "!"))
		if !ok {
			return false
		}
		if neg {
			k = "!" + k
		}
		h[i] = k
	}
	sort.Strings(h)
	for i := range h {
		if h[i] != want[i] {
			return false
		}
	}
	return true
}

// Status is the store's state for the heartbeat and the GUI.
type Status struct {
	Ready      bool           `json:"ready"`
	Monitor    bool           `json:"monitor"`
	ActiveBans int            `json:"active_bans"`
	Entries    map[string]int `json:"entries"` // per table, as desired
	Limit      int            `json:"limit"`
	LastError  string         `json:"last_error,omitempty"`
}

// Status returns the current state.
func (s *Store) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{Ready: s.ready, Monitor: s.monitor, ActiveBans: len(s.bans), Limit: s.limit, LastError: s.lastErr, Entries: map[string]int{}}
	for _, t := range Tables {
		st.Entries[t] = len(s.desiredLocked(t))
	}
	return st
}

// Flush empties the agent's tables (uninstall, protection switched off).
func (s *Store) Flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range Tables {
		_ = s.ctl.Replace(t, nil)
	}
	s.ready = false
}
