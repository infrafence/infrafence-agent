package firewall

import (
	"reflect"
	"sync"
	"testing"
	"time"
)

// fakeBans isolates the ban ledger: iptables mode, no command run, a clock
// the test moves, the given capacity; it records what is removed from the
// kernel, evicted and changed.
type fakeBans struct {
	mu      sync.Mutex
	now     time.Time
	dropped []string
	evicted []string
	changes int
}

func (f *fakeBans) tick(d time.Duration) { f.mu.Lock(); f.now = f.now.Add(d); f.mu.Unlock() }

func withFakeBans(t *testing.T, capacity int) *fakeBans {
	t.Helper()
	resetBans(t)
	f := &fakeBans{now: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	checkIpset()
	oldIpset, oldRun, oldStdin := ipsetAvailable, run, runStdin
	oldNow, oldCap, oldDrop := banNow, banCap, dropFromKernel
	oldEvicted, oldChanged := OnBansEvicted, OnBansChanged
	ipsetAvailable = false
	run = func(string, ...string) (string, error) { return "", nil }
	runStdin = func(string, string, ...string) (string, error) { return "", nil }
	banNow = func() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.now }
	banCap = func() int { return capacity }
	dropFromKernel = func(ips []string) { f.mu.Lock(); f.dropped = append(f.dropped, ips...); f.mu.Unlock() }
	OnBansEvicted = func(ips []string, c int) {
		if c != capacity {
			t.Errorf("evicted with capacity %d, want %d", c, capacity)
		}
		f.mu.Lock()
		f.evicted = append(f.evicted, ips...)
		f.mu.Unlock()
	}
	OnBansChanged = func() { f.mu.Lock(); f.changes++; f.mu.Unlock() }
	t.Cleanup(func() {
		ipsetAvailable, run, runStdin = oldIpset, oldRun, oldStdin
		banNow, banCap, dropFromKernel = oldNow, oldCap, oldDrop
		OnBansEvicted, OnBansChanged = oldEvicted, oldChanged
	})
	return f
}

func ips(bans []Ban) []string {
	var out []string
	for _, b := range bans {
		out = append(out, b.IP)
	}
	return out
}

// Bans expire on the local timer, without a sync: the expired ones leave
// the firewall, the others (and the ones without expiry) stay.
func TestExpireBansLocally(t *testing.T) {
	f := withFakeBans(t, 100)
	now := f.now
	for ip, exp := range map[string]time.Time{
		"203.0.113.1": now.Add(time.Minute),
		"203.0.113.2": now.Add(time.Hour),
		"203.0.113.3": {},
	} {
		if _, err := BanIPOnceUntil(ip, exp); err != nil {
			t.Fatal(err)
		}
	}
	if got := NextBanExpiry(); !got.Equal(now.Add(time.Minute)) {
		t.Fatalf("next expiry %s", got)
	}
	if gone := ExpireBans(now); gone != nil {
		t.Fatalf("expired too early: %v", gone)
	}
	gone := ExpireBans(now.Add(time.Minute))
	if !reflect.DeepEqual(gone, []string{"203.0.113.1"}) || !reflect.DeepEqual(f.dropped, gone) {
		t.Fatalf("expired %v, dropped %v", gone, f.dropped)
	}
	ExpireBans(now.Add(365 * 24 * time.Hour))
	if got := ips(Bans()); !reflect.DeepEqual(got, []string{"203.0.113.3"}) {
		t.Fatalf("left %v, want only the ban without expiry", got)
	}
	if IsBanned("203.0.113.2") || !IsBanned("203.0.113.3") {
		t.Fatal("IsBanned does not follow the expiry")
	}
}

// At capacity a new ban removes the oldest one, from the kernel too, and
// the eviction is reported (no silent failure of the add).
func TestBanCapEvictsOldestFirst(t *testing.T) {
	f := withFakeBans(t, 3)
	for _, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		if added, err := BanIPOnce(ip); !added || err != nil {
			t.Fatalf("%s: %v %v", ip, added, err)
		}
		f.tick(time.Second)
	}
	if len(f.evicted) != 0 {
		t.Fatalf("evicted below capacity: %v", f.evicted)
	}
	if added, _ := BanIPOnce("203.0.113.4"); !added {
		t.Fatal("ban at capacity refused")
	}
	if !reflect.DeepEqual(f.evicted, []string{"203.0.113.1"}) || !reflect.DeepEqual(f.dropped, f.evicted) {
		t.Fatalf("evicted %v dropped %v, want the oldest", f.evicted, f.dropped)
	}
	if got := ips(Bans()); !reflect.DeepEqual(got, []string{"203.0.113.2", "203.0.113.3", "203.0.113.4"}) {
		t.Fatalf("bans %v", got)
	}
	// An address already banned takes no room.
	BanIPOnce("203.0.113.4")
	if len(f.evicted) != 1 {
		t.Fatalf("re-banning evicted: %v", f.evicted)
	}
}

// The dashboard's list keeps its expiry, makes room by evicting the oldest
// bans outside it, and is cut at capacity.
func TestApplyBansCapAndDashboardExpiry(t *testing.T) {
	f := withFakeBans(t, 3)
	BanIPOnceUntil("198.51.100.1", f.now.Add(24*time.Hour)) // local, oldest
	f.tick(time.Second)
	BanIPOnceUntil("198.51.100.2", f.now.Add(24*time.Hour)) // local, also in the list
	f.tick(time.Second)
	exp := f.now.Add(7 * 24 * time.Hour)
	ApplyBans([]Ban{
		{IP: "198.51.100.2", Expires: exp},
		{IP: "198.51.100.3"},
		{IP: "127.0.0.1"}, // never banned
		{IP: "198.51.100.4", Expires: exp},
	})
	if !reflect.DeepEqual(f.evicted, []string{"198.51.100.1"}) {
		t.Fatalf("evicted %v, want the oldest ban outside the list", f.evicted)
	}
	byIP := map[string]Ban{}
	for _, b := range Bans() {
		byIP[b.IP] = b
	}
	if len(byIP) != 3 || !byIP["198.51.100.2"].Expires.Equal(exp) || !byIP["198.51.100.3"].Expires.IsZero() {
		t.Fatalf("bans %+v: want the dashboard's expiry", byIP)
	}
	// More than the capacity: the first ones are applied, nothing else.
	f.evicted = nil
	ApplyBans([]Ban{{IP: "192.0.2.1"}, {IP: "192.0.2.2"}, {IP: "192.0.2.3"}, {IP: "192.0.2.4"}})
	if got := ips(Bans()); !reflect.DeepEqual(got, []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}) {
		t.Fatalf("bans %v", got)
	}
}

// Saved bans come back before the first setup, without the expired ones,
// the addresses that must never be banned, or more than the capacity (the
// newest are kept).
func TestRestoreBans(t *testing.T) {
	f := withFakeBans(t, 2)
	now := f.now
	n := RestoreBans([]Ban{
		{IP: "203.0.113.1", Added: now.Add(-3 * time.Hour), Expires: now.Add(time.Hour)},
		{IP: "203.0.113.2", Added: now.Add(-2 * time.Hour), Expires: now.Add(-time.Second)}, // expired
		{IP: "10.1.2.3", Added: now.Add(-time.Hour)},                                        // private
		{IP: "bogus"},
		{IP: "203.0.113.4", Added: now.Add(-time.Hour)},
		{IP: "203.0.113.5", Added: now.Add(-30 * time.Minute)},
	})
	if n != 2 {
		t.Fatalf("restored %d, want 2", n)
	}
	if got := ips(Bans()); !reflect.DeepEqual(got, []string{"203.0.113.4", "203.0.113.5"}) {
		t.Fatalf("restored %v, want the two newest valid ones", got)
	}
	fw.Lock()
	restored := fw.restored
	fw.restored = false
	fw.Unlock()
	if !restored {
		t.Fatal("restored bans not marked for the ipset")
	}
}

func TestSetBanExpiryAndUnban(t *testing.T) {
	f := withFakeBans(t, 10)
	BanIPOnceUntil("203.0.113.7", f.now.Add(time.Hour))
	if !SetBanExpiry("203.0.113.7", time.Time{}) || SetBanExpiry("203.0.113.8", time.Time{}) {
		t.Fatal("SetBanExpiry")
	}
	if !NextBanExpiry().IsZero() {
		t.Fatal("permanent ban still expires")
	}
	before := f.changes
	UnbanIP("203.0.113.7")
	if IsBanned("203.0.113.7") || f.changes != before+1 {
		t.Fatal("unban not recorded")
	}
}

// Without ipset an IPv6 ban can't be enforced: it is refused before it
// takes room (it would evict a real ban and block nothing).
func TestIPv6WithoutIpsetTakesNoRoom(t *testing.T) {
	f := withFakeBans(t, 1)
	BanIPOnce("203.0.113.1")
	if added, err := BanIPOnce("2001:db8::7"); added || err == nil {
		t.Fatalf("IPv6 ban without ipset: added=%v err=%v", added, err)
	}
	ApplyBans([]Ban{{IP: "2001:db8::8"}})
	if len(f.evicted) != 0 || !IsBanned("203.0.113.1") || IsBanned("2001:db8::8") {
		t.Fatalf("evicted %v, bans %v", f.evicted, Bans())
	}
}

// Bans without expiry (permanent dashboard bans) are evicted only after
// every ban that expires, even newer ones.
func TestEvictionSparesPermanentBans(t *testing.T) {
	f := withFakeBans(t, 2)
	BanIPOnce("203.0.113.1") // permanent, oldest
	f.tick(time.Second)
	BanIPOnceUntil("203.0.113.2", f.now.Add(time.Hour))
	f.tick(time.Second)
	BanIPOnceUntil("203.0.113.3", f.now.Add(time.Hour))
	if !reflect.DeepEqual(f.evicted, []string{"203.0.113.2"}) || !IsBanned("203.0.113.1") {
		t.Fatalf("evicted %v, want the oldest expiring ban", f.evicted)
	}
}
