package scanwatch

import (
	"context"
	"log"
	"net"
	"sync"
	"time"
)

// Connection attempts analyzed per second at most; beyond that they are
// skipped (a SYN flood is the flood monitor's job), so the agent stays cheap
// under attack.
const maxPacketsPerSecond = 5000

// Watcher runs the capture and the analyzer; it can be switched on and off
// at runtime (dashboard setting).
type Watcher struct {
	skip   func(net.IP) bool
	onScan func(Scan)

	mu      sync.Mutex
	cancel  context.CancelFunc
	running bool
}

// New: skip excludes addresses (private, own, whitelisted); onScan receives
// each detected scan.
func New(skip func(net.IP) bool, onScan func(Scan)) *Watcher {
	return &Watcher{skip: skip, onScan: onScan}
}

// Running reports whether packets are being watched; the old /proc-based
// detector is then not needed.
func (w *Watcher) Running() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.running
}

// SetEnabled starts or stops the watching.
func (w *Watcher) SetEnabled(on bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if on == (w.cancel != nil) {
		return
	}
	if !on {
		w.cancel()
		w.cancel = nil
		w.running = false
		log.Printf("[portscan] stopped (disabled in dashboard settings)")
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	w.cancel = cancel
	go w.run(ctx)
}

func (w *Watcher) setRunning(v bool) {
	w.mu.Lock()
	w.running = v
	w.mu.Unlock()
}

func (w *Watcher) run(ctx context.Context) {
	a := NewAnalyzer(w.skip)
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				a.Prune(now)
			}
		}
	}()

	second, count, skipped := time.Now(), 0, 0
	err := capture(ctx, func() {
		w.setRunning(true)
		log.Printf("[portscan] watching incoming connection attempts (TCP SYN, read-only)")
	}, func(src net.IP, port uint16) {
		now := time.Now()
		if now.Sub(second) >= time.Second {
			if skipped > 0 {
				log.Printf("[portscan] %d connection attempts skipped in the last second (limit %d/s)", skipped, maxPacketsPerSecond)
			}
			second, count, skipped = now, 0, 0
		}
		if count >= maxPacketsPerSecond {
			skipped++
			return
		}
		count++
		for _, s := range a.Observe(src, port, now) {
			w.onScan(s)
		}
	})
	w.setRunning(false)
	if err != nil && ctx.Err() == nil {
		log.Printf("[portscan] packet capture unavailable (%v) — using the connection-table check", err)
	}
}
