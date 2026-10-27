package monitor

import (
	"encoding/json"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DestinationLog remembers the addresses this server connects to by itself
// and on how many days: an address it has talked to on several days of the
// last week is a service it depends on (a customer's API, a payment
// gateway, a mirror). When such an address shows up on a threat list the
// agent does not block egress to it on its own: the egress_threat_match
// says regular_destination and the block waits for a person's approval.
//
// A connection counts once per day it is seen: an established or
// TIME_WAIT socket (/proc/net/tcp) from a local port nothing listens on, or
// a tracked flow (conntrack) that this host or one of its containers
// started. Only public IPv4 addresses are kept; what is stored is the
// address and a count per day (no ports, no process), for at most
// destWindowDays days and maxDestinations addresses, in a 0600 file.
type DestinationLog struct {
	mu    sync.Mutex
	path  string
	days  map[string]map[int64]int // address -> day (Unix days, UTC) -> connections
	seen  map[string]int64         // connection key -> day it was counted
	dirty bool
	saved time.Time

	// Replaced in tests.
	now       func() time.Time
	conntrack func() string
	local     func() map[string]bool
}

const (
	destWindowDays = 7
	// A destination is regular with at least destMinConns connections on
	// at least destMinDays different days of the window.
	destMinDays     = 3
	destMinConns    = 5
	maxDestinations = 5000
	maxSeenConns    = 50000
	destSaveEvery   = 10 * time.Minute
	// maxConntrackRead bounds what one scan reads of the conntrack table.
	maxConntrackRead = 16 << 20
)

// NewDestinationLog returns a log saved at path ("" keeps it in memory),
// loaded from it when the file exists.
func NewDestinationLog(path string) *DestinationLog {
	l := &DestinationLog{
		path: path, days: map[string]map[int64]int{}, seen: map[string]int64{},
		now: time.Now, conntrack: readConntrack, local: localAddrs,
	}
	l.load()
	return l
}

func day(t time.Time) int64 { return t.UTC().Unix() / 86400 }

// Observe counts the outbound connections of one scan: conns from
// /proc/net/tcp, plus the conntrack table. Saves the log when due.
func (l *DestinationLog) Observe(conns []TCPConn) {
	if l == nil {
		return
	}
	today := day(l.now())
	listening := map[uint16]bool{}
	for _, c := range conns {
		if c.State == tcpListen {
			listening[c.LocalPort] = true
		}
	}
	keys := map[string]string{} // connection key -> remote address
	for _, c := range conns {
		if (c.State != TCPEstablished && c.State != TCPTimeWait) || listening[c.LocalPort] || !publicIPv4(c.RemoteIP) {
			continue
		}
		ip := c.RemoteIP.To4().String()
		keys["s "+strconv.Itoa(int(c.LocalPort))+" "+ip+":"+strconv.Itoa(int(c.RemotePort))] = ip
	}
	if ct := l.conntrack(); ct != "" {
		for k, ip := range conntrackOutbound(ct, l.local()) {
			keys[k] = ip
		}
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	seen := make(map[string]int64, len(keys))
	for k, ip := range keys {
		if len(seen) >= maxSeenConns {
			break
		}
		if l.seen[k] != today {
			d := l.days[ip]
			if d == nil {
				d = map[int64]int{}
				l.days[ip] = d
			}
			d[today]++
			l.dirty = true
		}
		seen[k] = today
	}
	l.seen = seen
	l.pruneLocked(today)
	if l.dirty && l.path != "" && l.now().Sub(l.saved) >= destSaveEvery {
		l.saveLocked()
	}
}

// pruneLocked drops the days out of the window and, past maxDestinations,
// the addresses seen longest ago.
func (l *DestinationLog) pruneLocked(today int64) {
	last := map[string]int64{}
	for ip, d := range l.days {
		for dd := range d {
			if dd <= today-destWindowDays || dd > today+1 {
				delete(d, dd)
				l.dirty = true
				continue
			}
			if dd > last[ip] {
				last[ip] = dd
			}
		}
		if len(d) == 0 {
			delete(l.days, ip)
		}
	}
	if n := len(l.days) - maxDestinations; n > 0 {
		ips := make([]string, 0, len(l.days))
		for ip := range l.days {
			ips = append(ips, ip)
		}
		sort.Slice(ips, func(i, j int) bool {
			if last[ips[i]] != last[ips[j]] {
				return last[ips[i]] < last[ips[j]]
			}
			return ips[i] < ips[j]
		})
		for _, ip := range ips[:n] {
			delete(l.days, ip)
		}
		l.dirty = true
	}
}

// Regular reports whether this server connected to ip regularly over the
// last destWindowDays days, with the connections and days counted.
func (l *DestinationLog) Regular(ip string) (regular bool, conns, days int) {
	if l == nil {
		return false, 0, 0
	}
	p := net.ParseIP(strings.TrimSpace(ip)).To4()
	if p == nil {
		return false, 0, 0
	}
	today := day(l.now())
	l.mu.Lock()
	defer l.mu.Unlock()
	for dd, n := range l.days[p.String()] {
		if dd > today-destWindowDays && dd <= today && n > 0 {
			conns += n
			days++
		}
	}
	return days >= destMinDays && conns >= destMinConns, conns, days
}

// Save writes the log now (at shutdown, in tests).
func (l *DestinationLog) Save() {
	if l == nil || l.path == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.saveLocked()
}

type destFile struct {
	Days map[string]map[string]int `json:"days"` // address -> Unix day -> connections
}

func (l *DestinationLog) saveLocked() {
	out := destFile{Days: make(map[string]map[string]int, len(l.days))}
	for ip, d := range l.days {
		m := make(map[string]int, len(d))
		for dd, n := range d {
			m[strconv.FormatInt(dd, 10)] = n
		}
		out.Days[ip] = m
	}
	data, err := json.Marshal(out)
	if err != nil {
		return
	}
	l.saved = l.now()
	if err := writeFileAtomic(l.path, data); err != nil {
		log.Printf("[egress] save %s: %v", l.path, err)
		return
	}
	l.dirty = false
}

func (l *DestinationLog) load() {
	if l.path == "" {
		return
	}
	data, err := os.ReadFile(l.path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[egress] read %s: %v", l.path, err)
		}
		return
	}
	var in destFile
	if err := json.Unmarshal(data, &in); err != nil {
		log.Printf("[egress] %s is not valid, ignored: %v", l.path, err)
		return
	}
	for ip, d := range in.Days {
		p := net.ParseIP(ip)
		if p == nil || !publicIPv4(p) {
			continue
		}
		m := map[int64]int{}
		for k, n := range d {
			if dd, err := strconv.ParseInt(k, 10, 64); err == nil && n > 0 {
				m[dd] = n
			}
		}
		if len(m) > 0 {
			l.days[p.To4().String()] = m
		}
	}
	l.pruneLocked(day(l.now()))
	l.saved = l.now()
}

func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".egress-destinations-*")
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

func publicIPv4(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil || IsPrivateIP(v4) || v4.IsUnspecified() || v4.IsLinkLocalUnicast() || v4.IsMulticast() || v4[0] == 0 {
		return false
	}
	// Shared address space (carrier-grade NAT).
	return !(v4[0] == 100 && v4[1]&0xC0 == 64)
}

// readConntrack returns the start of /proc/net/nf_conntrack ("" without
// it). No process is started: the table is read only where the kernel
// exposes it.
func readConntrack() string {
	f, err := os.Open("/proc/net/nf_conntrack")
	if err != nil {
		return ""
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, maxConntrackRead))
	return string(b)
}

func localAddrs() map[string]bool {
	out := map[string]bool{}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			out[n.IP.String()] = true
		}
	}
	return out
}

// conntrackOutbound returns the TCP flows this host or one of its
// containers started to a public IPv4 address, established or finished
// normally: the original source is a local or private address, the
// original destination a public one that is not this host. Keyed like the
// sockets of Observe for the host's own connections, by the original tuple
// for the others.
func conntrackOutbound(table string, local map[string]bool) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(table, "\n") {
		f := strings.Fields(line)
		ok, isTCP := false, false
		var src, dst, sport, dport string
		for _, w := range f {
			switch {
			case w == "tcp":
				isTCP = true
			case w == "ESTABLISHED" || w == "TIME_WAIT":
				ok = true
			case strings.HasPrefix(w, "src=") && src == "":
				src = w[4:]
			case strings.HasPrefix(w, "dst=") && dst == "":
				dst = w[4:]
			case strings.HasPrefix(w, "sport=") && sport == "":
				sport = w[6:]
			case strings.HasPrefix(w, "dport=") && dport == "":
				dport = w[6:]
			}
		}
		if !ok || !isTCP {
			continue
		}
		s, d := net.ParseIP(src), net.ParseIP(dst)
		if s == nil || d == nil || local[d.String()] || !publicIPv4(d) {
			continue
		}
		if !local[s.String()] && !IsPrivateIP(s) {
			continue // started outside: inbound
		}
		ip := d.To4().String()
		if local[s.String()] {
			// The host's own connection: the same key as its socket, so
			// it is counted once.
			out["s "+sport+" "+ip+":"+dport] = ip
		} else {
			out["c "+s.String()+":"+sport+" "+ip+":"+dport] = ip
		}
	}
	return out
}
