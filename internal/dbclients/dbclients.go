// Package dbclients remembers the public addresses that use the database,
// cache and admin service ports of this server, and on how many days: an
// address seen as a client of a port on several days of the last week is a
// regular client (an application server, a backup job, a replica, a
// developer's office). Closing such a port to the internet would cut it off,
// so the agent refuses to close it while a regular client is not on the
// allow list.
//
// What is kept per port, address and day (UTC) is the first and last time
// the address was seen with an established connection and the number of
// samples it was seen in (one sample a minute): no ports of the client, no
// process, no traffic. For at most WindowDays days, maxPerPortDay addresses
// per port and day and maxPerPort addresses per port, in a 0600 file.
package dbclients

import (
	"encoding/json"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"
)

const (
	// WindowDays is the window a regular client is counted in.
	WindowDays = 7
	// MinDays: a regular client is seen on at least this many different
	// days of the window.
	MinDays = 3
	// maxPerPortDay bounds the addresses kept per port and day; more are
	// not counted that day (logged once).
	maxPerPortDay = 200
	// maxPerPort bounds the addresses kept per port over the window.
	maxPerPort = 1000
	maxPorts   = 64
	saveEvery  = 10 * time.Minute
	maxFile    = 16 << 20
)

// Entry is one address on one port on one day.
type Entry struct {
	First   int64 `json:"first"` // unix seconds
	Last    int64 `json:"last"`
	Samples int   `json:"samples"`
	// sent is the number of samples the dashboard has (not saved: after a
	// restart everything is sent once more).
	sent int
}

// Client is a regular client of a port.
type Client struct {
	IP    string
	Days  int
	First time.Time
	Last  time.Time
}

// Report is one entry to send to the dashboard.
type Report struct {
	Port      int    `json:"port"`
	IP        string `json:"ip"`
	Day       string `json:"day"` // YYYY-MM-DD, UTC
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
	Samples   int    `json:"samples"`
	day       int64
}

// Log is the per-port, per-address, per-day record.
type Log struct {
	mu    sync.Mutex
	path  string
	ports map[int]map[string]map[int64]*Entry // port -> address -> day -> entry
	full  map[int]int64                       // port -> day the per-day bound was logged
	dirty bool
	saved time.Time

	// Now and DayLength are replaced in tests (a test build shortens the
	// day so the distro test sees several "days" in minutes).
	Now       func() time.Time
	DayLength time.Duration
}

// New returns a log saved at path ("" keeps it in memory), loaded from it
// when the file exists.
func New(path string) *Log {
	l := &Log{path: path, ports: map[int]map[string]map[int64]*Entry{}, full: map[int]int64{}, Now: time.Now, DayLength: 24 * time.Hour}
	l.load()
	return l
}

func (l *Log) day(t time.Time) int64 {
	d := int64(l.DayLength / time.Second)
	if d <= 0 {
		d = 86400
	}
	return t.UTC().Unix() / d
}

// Observe counts one sample: for each port, the public addresses connected
// to it now. Saves the log when due.
func (l *Log) Observe(seen map[int][]string) {
	if l == nil {
		return
	}
	now := l.Now()
	today := l.day(now)
	l.mu.Lock()
	defer l.mu.Unlock()
	for port, ips := range seen {
		if port < 1 || port > 65535 {
			continue
		}
		byIP := l.ports[port]
		if byIP == nil {
			if len(l.ports) >= maxPorts {
				continue
			}
			byIP = map[string]map[int64]*Entry{}
			l.ports[port] = byIP
		}
		counted := map[string]bool{}
		for _, raw := range ips {
			ip := normIP(raw)
			if ip == "" || counted[ip] {
				continue
			}
			counted[ip] = true
			days := byIP[ip]
			e := days[today]
			if e == nil {
				// An address already seen on another day is always counted: a
				// flood of new addresses must not keep a known client from
				// becoming regular. New addresses are bounded per day, and per
				// port a new one replaces the least seen one-day address.
				full := days == nil && (l.countDayLocked(port, today) >= maxPerPortDay ||
					len(byIP) >= maxPerPort && !l.evictLocked(port, today))
				if full {
					if l.full[port] != today {
						l.full[port] = today
						log.Printf("[dbclients] port %d: more than %d client addresses today, the others are not counted", port, maxPerPortDay)
					}
					continue
				}
				if days == nil {
					days = map[int64]*Entry{}
					byIP[ip] = days
				}
				e = &Entry{First: now.Unix()}
				days[today] = e
			}
			e.Last = now.Unix()
			e.Samples++
			l.dirty = true
		}
	}
	l.pruneLocked(today)
	if l.dirty && l.path != "" && now.Sub(l.saved) >= saveEvery {
		l.saveLocked()
	}
}

// evictLocked drops, to make room on port, the address seen on a single
// day (not today) with the fewest samples. It reports whether one was
// dropped.
func (l *Log) evictLocked(port int, today int64) bool {
	victim, least := "", 0
	for ip, days := range l.ports[port] {
		if len(days) != 1 || days[today] != nil {
			continue
		}
		for _, e := range days {
			if victim == "" || e.Samples < least || e.Samples == least && ip < victim {
				victim, least = ip, e.Samples
			}
		}
	}
	if victim == "" {
		return false
	}
	delete(l.ports[port], victim)
	return true
}

func (l *Log) countDayLocked(port int, day int64) int {
	n := 0
	for _, days := range l.ports[port] {
		if days[day] != nil {
			n++
		}
	}
	return n
}

// pruneLocked drops the days out of the window (and days in the future: a
// clock set back).
func (l *Log) pruneLocked(today int64) {
	for port, byIP := range l.ports {
		for ip, days := range byIP {
			for d := range days {
				if d <= today-WindowDays || d > today+1 {
					delete(days, d)
					l.dirty = true
				}
			}
			if len(days) == 0 {
				delete(byIP, ip)
			}
		}
		if len(byIP) == 0 {
			delete(l.ports, port)
		}
	}
}

// Regular returns the regular clients of port: the addresses seen on at
// least MinDays different days of the last WindowDays days, today included.
func (l *Log) Regular(port int) []Client {
	if l == nil {
		return nil
	}
	today := l.day(l.Now())
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []Client
	for ip, days := range l.ports[port] {
		c := Client{IP: ip}
		for d, e := range days {
			if d <= today-WindowDays || d > today || e.Samples <= 0 {
				continue
			}
			c.Days++
			if f := time.Unix(e.First, 0); c.First.IsZero() || f.Before(c.First) {
				c.First = f
			}
			if t := time.Unix(e.Last, 0); t.After(c.Last) {
				c.Last = t
			}
		}
		if c.Days >= MinDays {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

// Pending returns up to max entries the dashboard does not have yet (new
// samples since the last MarkSent), oldest day first.
func (l *Log) Pending(max int) []Report {
	if l == nil || max <= 0 {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []Report
	for port, byIP := range l.ports {
		for ip, days := range byIP {
			for d, e := range days {
				if e.Samples == e.sent {
					continue
				}
				out = append(out, Report{
					Port: port, IP: ip, day: d, Samples: e.Samples,
					Day:       time.Unix(e.First, 0).UTC().Format("2006-01-02"),
					FirstSeen: time.Unix(e.First, 0).UTC().Format(time.RFC3339),
					LastSeen:  time.Unix(e.Last, 0).UTC().Format(time.RFC3339),
				})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.day != b.day {
			return a.day < b.day
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.IP < b.IP
	})
	if len(out) > max {
		out = out[:max]
	}
	return out
}

// MarkSent records that the dashboard has these entries.
func (l *Log) MarkSent(sent []Report) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, r := range sent {
		if e := l.ports[r.Port][r.IP][r.day]; e != nil && r.Samples > e.sent {
			e.sent = r.Samples
		}
	}
}

// Save writes the log now (at shutdown, in tests).
func (l *Log) Save() {
	if l == nil || l.path == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.saveLocked()
}

// fileFormat: port -> address -> day -> entry (days in the log's unit).
type fileFormat struct {
	Ports map[string]map[string]map[string]Entry `json:"ports"`
}

func (l *Log) saveLocked() {
	out := fileFormat{Ports: map[string]map[string]map[string]Entry{}}
	for port, byIP := range l.ports {
		m := map[string]map[string]Entry{}
		for ip, days := range byIP {
			dm := map[string]Entry{}
			for d, e := range days {
				dm[strconv.FormatInt(d, 10)] = *e
			}
			m[ip] = dm
		}
		out.Ports[strconv.Itoa(port)] = m
	}
	data, err := json.Marshal(out)
	if err != nil {
		return
	}
	l.saved = l.Now()
	if err := writeFileAtomic(l.path, data); err != nil {
		log.Printf("[dbclients] save %s: %v", l.path, err)
		return
	}
	l.dirty = false
}

func (l *Log) load() {
	if l.path == "" {
		return
	}
	f, err := os.Open(l.path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[dbclients] read %s: %v", l.path, err)
		}
		return
	}
	data, err := io.ReadAll(io.LimitReader(f, maxFile))
	f.Close()
	if err != nil {
		return
	}
	var in fileFormat
	if err := json.Unmarshal(data, &in); err != nil {
		log.Printf("[dbclients] %s is not valid, ignored: %v", l.path, err)
		return
	}
	for ps, byIP := range in.Ports {
		port, err := strconv.Atoi(ps)
		if err != nil || port < 1 || port > 65535 || len(l.ports) >= maxPorts {
			continue
		}
		for raw, days := range byIP {
			ip := normIP(raw)
			if ip == "" {
				continue
			}
			for ds, e := range days {
				d, err := strconv.ParseInt(ds, 10, 64)
				if err != nil || e.Samples <= 0 || e.First <= 0 || e.Last < e.First {
					continue
				}
				if l.ports[port] == nil {
					l.ports[port] = map[string]map[int64]*Entry{}
				}
				if len(l.ports[port]) >= maxPerPort && l.ports[port][ip] == nil {
					continue
				}
				if l.ports[port][ip] == nil {
					l.ports[port][ip] = map[int64]*Entry{}
				}
				e := e
				e.sent = 0
				l.ports[port][ip][d] = &e
			}
		}
	}
	l.pruneLocked(l.day(l.Now()))
	l.saved = l.Now()
}

// normIP returns ip in canonical form when it is a public address, else "".
func normIP(s string) string {
	ip := net.ParseIP(s)
	if ip == nil || !public(ip) {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// public: not private, loopback, link-local, multicast, unspecified,
// carrier-grade NAT or "this network" (as netstate.IsPublic).
func public(ip net.IP) bool {
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && v4[1]&0xC0 == 64 || v4[0] == 0 {
			return false
		}
	}
	return true
}

func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".db-clients-*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Chmod(0o600)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}
