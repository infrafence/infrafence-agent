package firewall

import (
	"sync"
	"sync/atomic"
	"testing"
)

func resetBans(t *testing.T) {
	t.Helper()
	fw.Lock()
	saved := fw.bans
	fw.bans = map[string]bool{}
	fw.Unlock()
	t.Cleanup(func() {
		fw.Lock()
		fw.bans = saved
		fw.Unlock()
	})
}

// Two watchers detecting the same IP at once must report it once.
func TestClaimBanIsAtomic(t *testing.T) {
	resetBans(t)
	var claimed atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if claimBan("203.0.113.9") {
				claimed.Add(1)
			}
		}()
	}
	wg.Wait()
	if n := claimed.Load(); n != 1 {
		t.Fatalf("claimed %d times, want 1", n)
	}
}

// An IP banned by the dashboard (applied at sync) is already banned: a local
// detection must not report it again. After the ban expires and is cleaned
// up, a new detection is a new ban.
func TestClaimAfterSyncAndExpiry(t *testing.T) {
	resetBans(t)
	fw.Lock()
	fw.bans["198.51.100.4"] = true // from ApplyBans
	fw.Unlock()
	if claimBan("198.51.100.4") {
		t.Fatal("an IP banned by the dashboard was claimed as a new ban")
	}
	fw.Lock()
	delete(fw.bans, "198.51.100.4") // CleanupStaleBans after expiry
	fw.Unlock()
	if !claimBan("198.51.100.4") {
		t.Fatal("a new detection after expiry must be a new ban")
	}
}

func TestBanIPOnceRefusesInvalidAndSafeIPs(t *testing.T) {
	resetBans(t)
	for _, ip := range []string{"not-an-ip", "127.0.0.1", "10.0.0.5"} {
		added, err := BanIPOnce(ip)
		if added || err == nil {
			t.Errorf("%s: added=%v err=%v, want refusal", ip, added, err)
		}
	}
	fw.Lock()
	n := len(fw.bans)
	fw.Unlock()
	if n != 0 {
		t.Errorf("refused IPs were recorded as banned: %d", n)
	}
}
