package monitor

import (
	"fmt"
	"sync"
	"time"

	"testing"

	"github.com/infrafence/infrafence-agent/internal/api"
)

// TestThreatFeedIndex_ConcurrentAccess exercises the real production access
// pattern: Update() runs from the sync goroutine (applyThreatFeed in main.go,
// triggered by every WS sync, the 5-min fallback ticker, and startup cache
// load) while Lookup() runs concurrently from the security-monitors ticker
// goroutine (EgressDetector/DNSDetector.Scan()). Run with -race.
func TestThreatFeedIndex_ConcurrentAccess(t *testing.T) {
	idx := NewThreatFeedIndex()

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Writers: simulate repeated threat feed syncs.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				idx.Update([]api.ThreatEntry{
					{IP: strPtr(fmt.Sprintf("203.0.113.%d", n))},
					{CIDR: strPtr("198.51.100.0/24")},
				})
			}
		}(i)
	}

	// Readers: simulate concurrent Scan() calls from EgressDetector/DNSDetector.
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				idx.Lookup(mustParseIP("203.0.113.1"))
				idx.Lookup(mustParseIP("198.51.100.5"))
			}
		}()
	}

	time.Sleep(150 * time.Millisecond)
	close(stop)
	wg.Wait()
}
