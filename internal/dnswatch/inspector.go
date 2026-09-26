package dnswatch

import (
	"context"
	"log"
	"net"
	"sync"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
)

// Packets analyzed per second at most; beyond that they are skipped, so a
// busy DNS server can't make the agent expensive.
const maxPacketsPerSecond = 3000

// Inspector runs the capture and the analyzer and can be switched on and
// off at runtime (dashboard setting).
type Inspector struct {
	report     func([]api.EventRequest)
	threat     func(net.IP) (bool, string)
	configured func() map[string]bool

	mu      sync.Mutex
	cancel  context.CancelFunc
	running bool
}

// NewInspector: configured is re-read at most once a minute.
func NewInspector(report func([]api.EventRequest), threat func(net.IP) (bool, string), configured func() map[string]bool) *Inspector {
	return &Inspector{report: report, threat: threat, configured: cached(configured, time.Minute)}
}

// Running reports whether packets are being inspected; the /proc-based DNS
// monitor then leaves resolver checks to the inspector.
func (i *Inspector) Running() bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.running
}

// SetEnabled starts or stops the inspection.
func (i *Inspector) SetEnabled(on bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if on == (i.cancel != nil) {
		return
	}
	if !on {
		i.cancel()
		i.cancel = nil
		i.running = false
		log.Printf("[dns-inspect] stopped (disabled in dashboard settings)")
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	i.cancel = cancel
	go i.run(ctx)
}

func (i *Inspector) setRunning(v bool) {
	i.mu.Lock()
	i.running = v
	i.mu.Unlock()
}

func (i *Inspector) run(ctx context.Context) {
	owners := newOwnerFinder()
	a := NewAnalyzer(Sources{Configured: i.configured, Threat: i.threat, Owner: owners.Lookup})
	second, count, skipped := time.Now(), 0, 0
	err := capture(ctx, func() {
		i.setRunning(true)
		log.Printf("[dns-inspect] inspecting DNS traffic (UDP 53, read-only)")
	}, func(p Packet) {
		now := time.Now()
		if now.Sub(second) >= time.Second {
			if skipped > 0 {
				log.Printf("[dns-inspect] %d DNS packets skipped in the last second (limit %d/s)", skipped, maxPacketsPerSecond)
			}
			second, count, skipped = now, 0, 0
		}
		if count >= maxPacketsPerSecond {
			skipped++
			return
		}
		count++
		if ev := a.Handle(p); len(ev) > 0 {
			go i.report(ev)
		}
	})
	i.setRunning(false)
	if err != nil && ctx.Err() == nil {
		log.Printf("[dns-inspect] not available: %v — the /proc-based DNS monitor stays active", err)
	}
}

func cached(f func() map[string]bool, ttl time.Duration) func() map[string]bool {
	var (
		mu  sync.Mutex
		at  time.Time
		val map[string]bool
	)
	return func() map[string]bool {
		if f == nil {
			return nil
		}
		mu.Lock()
		defer mu.Unlock()
		if val == nil || time.Since(at) > ttl {
			val, at = f(), time.Now()
		}
		return val
	}
}
