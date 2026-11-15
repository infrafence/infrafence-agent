package opnsense

import (
	"sort"
	"strconv"
	"sync"
	"time"
)

// maxKeys bounds the per-source and per-port maps of a summary window: a
// flood of spoofed sources counts in "other" instead of growing memory.
const maxKeys = 20000

// KeyCount is one row of a top list.
type KeyCount struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// BlockSummary is the fw_blocks summary: what the firewall blocked on its
// external interfaces since the last one. Never one event per packet.
type BlockSummary struct {
	From            string     `json:"from"`
	To              string     `json:"to"`
	Blocked         int        `json:"blocked"`
	DistinctSources int        `json:"distinct_sources"`
	TopSources      []KeyCount `json:"top_sources"`
	TopPorts        []KeyCount `json:"top_ports"` // "tcp/3389", "udp/5060", "icmp"
	Truncated       bool       `json:"truncated,omitempty"`
}

// Aggregator counts blocked inbound packets.
type Aggregator struct {
	mu      sync.Mutex
	devices map[string]bool // external interface devices; empty: all
	start   time.Time
	total   int
	bySrc   map[string]int
	byPort  map[string]int
	trunc   bool
}

// NewAggregator counts blocks on devices (nil or empty: any interface).
func NewAggregator(devices []string, now time.Time) *Aggregator {
	a := &Aggregator{start: now, bySrc: map[string]int{}, byPort: map[string]int{}}
	a.SetDevices(devices)
	return a
}

// SetDevices changes the external interface devices.
func (a *Aggregator) SetDevices(devices []string) {
	m := map[string]bool{}
	for _, d := range devices {
		if d != "" {
			m[d] = true
		}
	}
	a.mu.Lock()
	a.devices = m
	a.mu.Unlock()
}

// Add counts r when it is an inbound block on an external interface and
// reports whether it did.
func (a *Aggregator) Add(r FilterRecord) bool {
	if (r.Action != "block" && r.Action != "reject") || r.Dir != "in" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.devices) > 0 && !a.devices[r.Interface] {
		return false
	}
	a.total++
	if _, ok := a.bySrc[r.Src]; ok || len(a.bySrc) < maxKeys {
		a.bySrc[r.Src]++
	} else {
		a.trunc = true
	}
	port := r.Proto
	if r.DstPort > 0 {
		port += "/" + strconv.Itoa(r.DstPort)
	}
	if _, ok := a.byPort[port]; ok || len(a.byPort) < maxKeys {
		a.byPort[port]++
	} else {
		a.trunc = true
	}
	return true
}

// Take returns the summary since the last Take and starts a new window
// (ok false when nothing was blocked).
func (a *Aggregator) Take(now time.Time) (BlockSummary, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := BlockSummary{From: a.start.UTC().Format(time.RFC3339), To: now.UTC().Format(time.RFC3339), Blocked: a.total,
		DistinctSources: len(a.bySrc), TopSources: top(a.bySrc, 10), TopPorts: top(a.byPort, 10), Truncated: a.trunc}
	ok := a.total > 0
	a.start, a.total, a.bySrc, a.byPort, a.trunc = now, 0, map[string]int{}, map[string]int{}, false
	return s, ok
}

func top(m map[string]int, n int) []KeyCount {
	out := make([]KeyCount, 0, len(m))
	for k, v := range m {
		out = append(out, KeyCount{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// Counter counts failed logins per address in a sliding window.
type Counter struct {
	mu        sync.Mutex
	threshold int
	window    time.Duration
	seen      map[string][]time.Time
	fired     map[string]time.Time
}

// NewCounter fires at threshold failures within window.
func NewCounter(threshold int, window time.Duration) *Counter {
	c := &Counter{seen: map[string][]time.Time{}, fired: map[string]time.Time{}}
	c.Set(threshold, window)
	return c
}

// Set changes the threshold and window (from the sync config).
func (c *Counter) Set(threshold int, window time.Duration) {
	if threshold < 2 {
		threshold = 5
	}
	if window <= 0 {
		window = 10 * time.Minute
	}
	c.mu.Lock()
	c.threshold, c.window = threshold, window
	c.mu.Unlock()
}

// Fail records one failure of key at now; it returns the count when it
// crosses the threshold (once per window per key), 0 otherwise.
func (c *Counter) Fail(key string, now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t, ok := c.fired[key]; ok && now.Sub(t) < c.window {
		return 0
	}
	var recent []time.Time
	for _, t := range c.seen[key] {
		if now.Sub(t) <= c.window {
			recent = append(recent, t)
		}
	}
	recent = append(recent, now)
	if _, tracked := c.seen[key]; !tracked && len(c.seen) >= maxKeys {
		c.pruneLocked(now)
		// Still full: drop the key seen longest ago rather than stop
		// counting (a flood must not blind the detection).
		for len(c.seen) >= maxKeys {
			oldest, at := "", time.Time{}
			for k, ts := range c.seen {
				if len(ts) == 0 {
					oldest = k
					break
				}
				if last := ts[len(ts)-1]; oldest == "" || last.Before(at) {
					oldest, at = k, last
				}
			}
			if oldest == "" {
				break
			}
			delete(c.seen, oldest)
		}
	}
	if len(c.fired) >= maxKeys {
		c.pruneLocked(now)
	}
	if len(recent) >= c.threshold {
		delete(c.seen, key)
		c.fired[key] = now
		return len(recent)
	}
	c.seen[key] = recent
	return 0
}

// Failures returns the failures of key within the window.
func (c *Counter) Failures(key string, now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, t := range c.seen[key] {
		if now.Sub(t) <= c.window {
			n++
		}
	}
	return n
}

// Prune drops idle keys; call periodically.
func (c *Counter) Prune(now time.Time) {
	c.mu.Lock()
	c.pruneLocked(now)
	c.mu.Unlock()
}

func (c *Counter) pruneLocked(now time.Time) {
	for k, ts := range c.seen {
		if len(ts) == 0 || now.Sub(ts[len(ts)-1]) > c.window {
			delete(c.seen, k)
		}
	}
	for k, t := range c.fired {
		if now.Sub(t) >= c.window {
			delete(c.fired, k)
		}
	}
}
