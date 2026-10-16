package firewall

import (
	"log"
	"net"
	"sort"
	"time"
)

// Every ban the agent enforces (its own detections and the dashboard's)
// carries when it was added and when it expires, so bans expire on this
// server on time whether or not the dashboard can be reached (ExpireBans),
// and the ban set never fills up silently: past the capacity the oldest
// bans make room, and OnBansEvicted is told.

// banEntry is one ban in fw.bans.
type banEntry struct {
	added   time.Time
	expires time.Time // zero: no expiry known (a permanent dashboard ban)
}

// Ban is a ban as the agent holds it.
type Ban struct {
	IP      string    `json:"ip"`
	Added   time.Time `json:"added"`
	Expires time.Time `json:"expires,omitzero"`
}

// Ban capacity: the infrafence-bans ipset holds 65536 entries (maxelem);
// the cap stays below it so an add never fails on a full set. Without
// ipset every ban is one rule in the chain.
const (
	ipsetBanCap    = 65000
	iptablesBanCap = 500
)

// Hooks, set once at startup before any ban is made. They are called
// without the firewall lock held, from the goroutine that changed the bans.
var (
	// OnBansEvicted receives the bans removed to make room, oldest first.
	OnBansEvicted func(evicted []string, capacity int)
	// OnBansChanged is called after bans were added, removed or changed.
	OnBansChanged func()
)

// Replaced in tests.
var (
	banNow = time.Now
	banCap = func() int {
		if HasIpset() {
			return ipsetBanCap
		}
		return iptablesBanCap
	}
)

// BanCapacity is the most bans the agent keeps at once.
func BanCapacity() int { return banCap() }

func bansChanged() {
	if OnBansChanged != nil {
		OnBansChanged()
	}
}

// makeRoomLocked removes bans so that n new ones fit, never one of keep:
// the oldest of the bans that expire first, and bans without expiry (the
// dashboard's permanent ones) only when no other is left, so a flood of
// short local bans cannot push them out. Callers hold fw and remove the
// evicted bans from the kernel.
func (s *fwState) makeRoomLocked(n int, keep map[string]bool) []string {
	over := len(s.bans) + n - banCap()
	if over <= 0 {
		return nil
	}
	ips := make([]string, 0, len(s.bans))
	for ip := range s.bans {
		if !keep[ip] {
			ips = append(ips, ip)
		}
	}
	sort.Slice(ips, func(i, j int) bool {
		x, y := s.bans[ips[i]], s.bans[ips[j]]
		if px, py := x.expires.IsZero(), y.expires.IsZero(); px != py {
			return py // the permanent one last
		}
		a, b := x.added, y.added
		if !a.Equal(b) {
			return a.Before(b)
		}
		return ips[i] < ips[j]
	})
	if over > len(ips) {
		over = len(ips)
	}
	evicted := ips[:over]
	for _, ip := range evicted {
		delete(s.bans, ip)
	}
	return evicted
}

// dropFromKernel removes bans no longer in fw.bans from the ipset, or
// rebuilds the chain without them. Call without the fw lock. Replaced in
// tests.
var dropFromKernel = func(ips []string) {
	if len(ips) == 0 {
		return
	}
	if HasIpset() {
		// Under the lock, leaving out an address banned again meanwhile:
		// its new ban must stay in the set.
		fw.Lock()
		defer fw.Unlock()
		gone := ips[:0:0]
		for _, ip := range ips {
			if _, again := fw.bans[ip]; !again {
				gone = append(gone, ip)
			}
		}
		if err := ipsetBatchDel(banSetName, gone); err != nil {
			log.Printf("[firewall] %v", err)
		}
		return
	}
	if _, err := Ensure(); err != nil {
		log.Printf("[firewall] remove bans: %v", err)
	}
}

// evicted reports and logs bans removed for room.
func evicted(ips []string) {
	if len(ips) == 0 {
		return
	}
	dropFromKernel(ips)
	c := banCap()
	if OnBansEvicted != nil {
		OnBansEvicted(ips, c) // logs, rate-limited
		return
	}
	log.Printf("[firewall] WARNING: ban capacity (%d) reached: removed the %d oldest ban(s) to make room", c, len(ips))
}

// ExpireBans removes the bans whose expiry is at or before now, from the
// ipset or the chain, and returns them. It runs on a local timer, so bans
// expire while the dashboard is unreachable or refuses the agent.
func ExpireBans(now time.Time) []string {
	fw.Lock()
	var gone []string
	for ip, b := range fw.bans {
		if !b.expires.IsZero() && !b.expires.After(now) {
			gone = append(gone, ip)
		}
	}
	for _, ip := range gone {
		delete(fw.bans, ip)
	}
	fw.Unlock()
	if len(gone) == 0 {
		return nil
	}
	sort.Strings(gone)
	dropFromKernel(gone)
	log.Printf("[firewall] %d ban(s) expired: %v", len(gone), short(gone))
	bansChanged()
	return gone
}

// NextBanExpiry returns the earliest ban expiry (zero: none).
func NextBanExpiry() time.Time {
	fw.Lock()
	defer fw.Unlock()
	var next time.Time
	for _, b := range fw.bans {
		if !b.expires.IsZero() && (next.IsZero() || b.expires.Before(next)) {
			next = b.expires
		}
	}
	return next
}

// Bans returns every ban the agent holds, sorted by address.
func Bans() []Ban {
	fw.Lock()
	out := make([]Ban, 0, len(fw.bans))
	for ip, b := range fw.bans {
		out = append(out, Ban{IP: ip, Added: b.added, Expires: b.expires})
	}
	fw.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

// RestoreBans loads bans saved before a restart, before Init: the first
// setup puts them back (in the chain without ipset, in the set with it).
// Expired bans and addresses that must never be banned are left out, and
// so is anything past the capacity (the newest are kept).
func RestoreBans(bans []Ban) int {
	now := banNow()
	var ok []Ban
	for _, b := range bans {
		p := net.ParseIP(b.IP)
		if p == nil || isSafeIP(p) || (!b.Expires.IsZero() && !b.Expires.After(now)) || !enforceable(p) {
			continue
		}
		if b.Added.IsZero() || b.Added.After(now) {
			b.Added = now
		}
		b.IP = p.String()
		ok = append(ok, b)
	}
	if c := banCap(); len(ok) > c {
		sort.Slice(ok, func(i, j int) bool { return ok[i].Added.After(ok[j].Added) })
		ok = ok[:c]
	}
	fw.Lock()
	for _, b := range ok {
		if _, known := fw.bans[b.IP]; !known {
			fw.bans[b.IP] = banEntry{added: b.Added, expires: b.Expires}
		}
	}
	fw.restored = len(ok) > 0
	fw.Unlock()
	return len(ok)
}

// SetBanExpiry sets when an existing ban expires (zero: never). It reports
// whether ip is banned.
func SetBanExpiry(ip string, expires time.Time) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}
	fw.Lock()
	b, ok := fw.bans[p.String()]
	if ok && !b.expires.Equal(expires) {
		b.expires = expires
		fw.bans[p.String()] = b
	}
	fw.Unlock()
	if ok {
		bansChanged()
	}
	return ok
}

// enforceable: without ipset only IPv4 bans can be put in the chain; an
// IPv6 one would take room and evict a real ban while blocking nothing.
func enforceable(ip net.IP) bool { return ip.To4() != nil || HasIpset() }

func short(ips []string) []string {
	if len(ips) > 10 {
		return append(append([]string{}, ips[:10]...), "...")
	}
	return ips
}
