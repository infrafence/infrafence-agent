// Package scanwatch detects port scans from the connection attempts (TCP
// SYN packets) the server receives, read-only.
//
// The previous detector looked at /proc/net/tcp once a minute for
// half-open connections to listening ports. Scans mostly hit closed ports,
// which leave no trace there, and a half-open connection lasts
// milliseconds: on a server with a handful of open ports it could never
// count 15. Here every SYN is seen as it arrives — to open or closed ports —
// through a kernel filter, as the DNS inspection does.
package scanwatch

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// Distinct destination ports from one address within Window that make a
	// port scan. Normal clients use one or two (80/443, 22).
	Threshold = 15
	Window    = 60 * time.Second
	// One report per address per Cooldown.
	Cooldown = 10 * time.Minute
	// Addresses tracked at most; beyond that the oldest are dropped.
	maxTracked = 20000
)

// Scan is a detected port scan.
type Scan struct {
	IP     string
	Ports  int      // distinct destination ports in the window
	Sample []uint16 // up to 20, sorted
}

// Details for the event.
func (s Scan) Details() map[string]string {
	sample := make([]string, len(s.Sample))
	for i, p := range s.Sample {
		sample[i] = strconv.Itoa(int(p))
	}
	return map[string]string{
		"ports_scanned": strconv.Itoa(s.Ports),
		"ports_sample":  strings.Join(sample, ","),
		"window":        fmt.Sprintf("%ds", int(Window.Seconds())),
		"detection":     "syn",
	}
}

type tracked struct {
	ports    map[uint16]time.Time
	lastSeen time.Time
}

// Analyzer counts the distinct ports each source tries.
type Analyzer struct {
	mu       sync.Mutex
	sources  map[string]*tracked
	reported map[string]time.Time
	// Skip is true for addresses that must never be reported (private,
	// this server's own, whitelisted).
	Skip func(ip net.IP) bool
}

// NewAnalyzer returns an empty analyzer.
func NewAnalyzer(skip func(net.IP) bool) *Analyzer {
	return &Analyzer{sources: map[string]*tracked{}, reported: map[string]time.Time{}, Skip: skip}
}

// Observe records a connection attempt from src to dstPort and returns a
// Scan the moment src crosses the threshold.
func (a *Analyzer) Observe(src net.IP, dstPort uint16, now time.Time) (Scan, bool) {
	if src == nil || (a.Skip != nil && a.Skip(src)) {
		return Scan{}, false
	}
	key := src.String()
	a.mu.Lock()
	defer a.mu.Unlock()

	if t, ok := a.reported[key]; ok {
		if now.Sub(t) < Cooldown {
			return Scan{}, false
		}
		delete(a.reported, key)
	}
	tr := a.sources[key]
	if tr == nil {
		if len(a.sources) >= maxTracked {
			a.pruneLocked(now, true)
		}
		tr = &tracked{ports: map[uint16]time.Time{}}
		a.sources[key] = tr
	}
	tr.lastSeen = now
	tr.ports[dstPort] = now
	if len(tr.ports) < Threshold {
		return Scan{}, false
	}
	// Only ports seen within the window count.
	var ports []uint16
	for p, t := range tr.ports {
		if now.Sub(t) <= Window {
			ports = append(ports, p)
		} else {
			delete(tr.ports, p)
		}
	}
	if len(ports) < Threshold {
		return Scan{}, false
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	sample := ports
	if len(sample) > 20 {
		sample = append([]uint16(nil), ports[:20]...)
	}
	a.reported[key] = now
	delete(a.sources, key)
	return Scan{IP: key, Ports: len(ports), Sample: sample}, true
}

// Prune forgets sources idle for longer than the window; call periodically.
func (a *Analyzer) Prune(now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pruneLocked(now, false)
}

func (a *Analyzer) pruneLocked(now time.Time, full bool) {
	for k, tr := range a.sources {
		if now.Sub(tr.lastSeen) > Window {
			delete(a.sources, k)
		}
	}
	for k, t := range a.reported {
		if now.Sub(t) > Cooldown {
			delete(a.reported, k)
		}
	}
	if full && len(a.sources) >= maxTracked {
		// Still full after pruning: a flood of sources. Start over rather
		// than grow without bound.
		a.sources = map[string]*tracked{}
	}
}
