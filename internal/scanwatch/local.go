package scanwatch

import (
	"log"
	"net/netip"
	"sync"
	"time"
)

// A connection attempt counts as a probe only when nothing on this server
// answered it. The SYN is seen before the kernel handles it, so each one
// waits a moment and is then checked against the TCP table:
//
//   - a port with a listening socket is an open service, never a probe;
//   - a connection from the same address to the same port (accepted by a
//     listener, open or closing) means the port was open when the SYN came,
//     even if its listener is gone by now;
//   - a port in the FTP server's passive range, from an address that has a
//     connection to an FTP control port or tried one while the FTP server
//     listened, is an FTP data connection. The server opens a new port for
//     each listing or transfer and closes it right after, so an upload can
//     be over before the table is read; a short session (twenty uploads in
//     a second) can be over entirely, control connection included.
//
// An address that talks to the FTP server is still reported for every port
// outside the passive range; any other address, for every port. A scanner
// that tries the FTP port first can probe the passive range unseen, where
// nothing but the FTP server's own data ports listen.

const (
	// How old an attempt must be before the table is read: by then the
	// kernel has answered it (a listener records it at once).
	settleDelay = 100 * time.Millisecond
	// The table is read only while attempts are waiting, at most once per
	// minSnapshotInterval, or less often when reading it is slow (a server
	// with very many connections): readCostFactor times the last read,
	// up to maxSnapshotInterval. The listening ports it found are trusted
	// for maxSnapshotAge.
	minSnapshotInterval = time.Second
	maxSnapshotInterval = 20 * time.Second
	readCostFactor      = 20
	maxSnapshotAge      = 30 * time.Second
	// An address seen with an FTP control connection keeps its data
	// connections uncounted for this long after (a session that just ended).
	ftpClientMemory = 2 * time.Minute
	// The FTP configuration is read again every ftpReload.
	ftpReload = time.Minute
	// Attempts waiting at most; beyond that they are dropped (the watcher
	// already limits them to maxPacketsPerSecond).
	maxPending = 20000
)

type attempt struct {
	src  netip.Addr
	port uint16
	at   time.Time
}

// Local holds the attempts waiting to be checked and what it last read of
// this server's sockets and FTP configuration. Add is called from the
// capture loop, Due from one other goroutine; files are read outside the
// lock, so the capture loop never waits for them.
type Local struct {
	root string // "/" on a server, a test directory otherwise

	mu      sync.Mutex
	pending []attempt
	snap    *sockets
	snapAt  time.Time
	// Control ports (copied from the FTP configuration) and the addresses
	// that tried one while it listened, until Due collects them.
	control map[uint16]bool
	ftpSYN  map[netip.Addr]time.Time

	// Used by Due only.
	nextRead   time.Time
	readErr    bool
	ftp        FTPConfig
	ftpAt      time.Time
	ftpLogged  string
	ftpClients map[netip.Addr]time.Time // seen with an FTP control connection
}

// NewLocal reads the sockets and FTP configuration under root.
func NewLocal(root string) *Local {
	ftp := LoadFTPConfig(root)
	return &Local{
		root: root, ftp: ftp, ftpAt: time.Now(), control: ftp.Control,
		ftpClients: map[netip.Addr]time.Time{}, ftpSYN: map[netip.Addr]time.Time{},
	}
}

// Add queues an attempt from src to port. It returns false when the attempt
// was dropped (too many waiting).
func (l *Local) Add(src netip.Addr, port uint16, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.control[port] && len(l.ftpSYN) < maxTracked {
		l.ftpSYN[src.Unmap()] = now
	}
	if l.snap != nil && now.Sub(l.snapAt) < maxSnapshotAge && l.snap.listening[port] {
		return true // an open service
	}
	if len(l.pending) >= maxPending {
		return false
	}
	l.pending = append(l.pending, attempt{src.Unmap(), port, now})
	return true
}

// Due returns the waiting attempts that are probes, checked against a fresh
// read of the TCP table; call it a few times a second, from one goroutine.
func (l *Local) Due(now time.Time) []attempt {
	if l.ftpAt.IsZero() || now.Sub(l.ftpAt) >= ftpReload {
		l.ftp = LoadFTPConfig(l.root)
		l.ftpAt = now
		l.mu.Lock()
		snap := l.snap
		l.control = l.ftp.Control
		l.mu.Unlock()
		l.logFTP(snap)
	}
	if now.Before(l.nextRead) {
		return nil
	}
	l.mu.Lock()
	cut := 0
	for cut < len(l.pending) && now.Sub(l.pending[cut].at) >= settleDelay {
		cut++
	}
	ready := l.pending[:cut]
	if cut > 0 {
		l.pending = append([]attempt(nil), l.pending[cut:]...)
	}
	var syns map[netip.Addr]time.Time
	if cut > 0 && len(l.ftpSYN) > 0 {
		syns, l.ftpSYN = l.ftpSYN, map[netip.Addr]time.Time{}
	}
	l.mu.Unlock()
	if cut == 0 {
		return nil
	}

	want := make(map[netip.Addr]bool, len(ready))
	for _, a := range ready {
		want[a.src] = true
	}
	start := time.Now()
	snap, err := readSockets(l.root, want, l.ftp.Control)
	wait := readCostFactor * time.Since(start)
	l.nextRead = now.Add(min(max(wait, minSnapshotInterval), maxSnapshotInterval))
	l.mu.Lock()
	l.snap, l.snapAt = snap, now
	l.mu.Unlock()
	if err != nil {
		// Without the table every attempt counts, as it did before.
		if !l.readErr {
			log.Printf("[portscan] cannot read the TCP table (%v): open ports and FTP data connections are counted too", err)
			l.readErr = true
		}
		return ready
	}
	l.readErr = false

	ftpListening := l.ftpListening(snap)
	passive := l.ftp.passiveRanges(ftpListening)
	l.logFTP(snap)
	if ftpListening {
		for addr, t := range syns {
			l.ftpClients[addr] = t
		}
	}
	for addr := range snap.ftpControl {
		l.ftpClients[addr] = now
	}
	for addr, t := range l.ftpClients {
		if now.Sub(t) > ftpClientMemory {
			delete(l.ftpClients, addr)
		}
	}
	if len(l.ftpClients) > maxTracked {
		l.ftpClients = map[netip.Addr]time.Time{}
	}

	out := ready[:0]
	for _, a := range ready {
		if snap.listening[a.port] || snap.accepted[addrPort{a.src, a.port}] {
			continue
		}
		if _, ftp := l.ftpClients[a.src]; ftp && inRanges(passive, a.port) {
			continue
		}
		out = append(out, a)
	}
	return out
}

// ftpListening: an FTP control port has a listening socket.
func (l *Local) ftpListening(snap *sockets) bool {
	if snap == nil {
		return false
	}
	for p := range l.ftp.Control {
		if snap.listening[p] {
			return true
		}
	}
	return false
}

// logFTP logs the FTP configuration in effect when it changes.
func (l *Local) logFTP(snap *sockets) {
	listening := l.ftpListening(snap)
	if len(l.ftp.passiveRanges(listening)) == 0 {
		return
	}
	if s := l.ftp.Summary(listening); s != l.ftpLogged {
		log.Printf("[portscan] FTP server: %s; data connections of FTP clients are not counted", s)
		l.ftpLogged = s
	}
}
