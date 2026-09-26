package dnswatch

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/infrafence/infrafence-agent/internal/monitor"
)

// ownerFinder attributes local UDP ports to processes. The machine's own DNS
// services are recognized cheaply (by the user their sockets belong to, or
// by their open sockets); anything else needs a scan of /proc/*/fd, which
// is rate-limited so heavy DNS traffic can't make the agent expensive.
type ownerFinder struct {
	procRoot string

	mu          sync.Mutex
	table       map[uint16]sock // local port -> socket, from /proc/net/udp{,6}
	tableV6     map[uint16]sock
	tableAt     time.Time
	resolverUID map[uint32]*monitor.ProcInfo // non-root users running a system resolver
	resolverPID map[int]*monitor.ProcInfo
	resolversAt time.Time
	byInode     map[uint64]*monitor.ProcInfo
	scans       []time.Time
}

type sock struct {
	uid   uint32
	inode uint64
}

const maxScansPerSecond = 10

func newOwnerFinder() *ownerFinder {
	return &ownerFinder{procRoot: "/proc", byInode: map[uint64]*monitor.ProcInfo{}}
}

func (o *ownerFinder) Lookup(port uint16, v6 bool) *monitor.ProcInfo {
	o.mu.Lock()
	defer o.mu.Unlock()
	now := time.Now()
	if now.Sub(o.tableAt) > 200*time.Millisecond {
		o.table = readUDPTable(filepath.Join(o.procRoot, "net/udp"))
		o.tableV6 = readUDPTable(filepath.Join(o.procRoot, "net/udp6"))
		o.tableAt = now
	}
	s, ok := o.table[port]
	if v6 || !ok {
		if s6, ok6 := o.tableV6[port]; ok6 {
			s, ok = s6, true
		}
	}
	if !ok || s.inode == 0 {
		return nil
	}
	if p, ok := o.byInode[s.inode]; ok {
		return p
	}
	o.refreshResolvers(now)
	if s.uid != 0 {
		if p := o.resolverUID[s.uid]; p != nil {
			return p
		}
	}
	for pid, p := range o.resolverPID {
		if hasSocket(filepath.Join(o.procRoot, strconv.Itoa(pid), "fd"), s.inode) {
			o.remember(s.inode, p)
			return p
		}
	}
	// Full scan, rate-limited.
	cut := now.Add(-time.Second)
	for len(o.scans) > 0 && o.scans[0].Before(cut) {
		o.scans = o.scans[1:]
	}
	if len(o.scans) >= maxScansPerSecond {
		return nil
	}
	o.scans = append(o.scans, now)
	p := monitor.SocketOwners(map[uint64]bool{s.inode: true})[s.inode]
	if p != nil {
		o.remember(s.inode, p)
	}
	return p
}

func (o *ownerFinder) remember(inode uint64, p *monitor.ProcInfo) {
	if len(o.byInode) > 4096 {
		o.byInode = map[uint64]*monitor.ProcInfo{}
	}
	o.byInode[inode] = p
}

// refreshResolvers finds running system DNS services every 30 seconds.
func (o *ownerFinder) refreshResolvers(now time.Time) {
	if now.Sub(o.resolversAt) < 30*time.Second {
		return
	}
	o.resolversAt = now
	o.resolverUID = map[uint32]*monitor.ProcInfo{}
	o.resolverPID = map[int]*monitor.ProcInfo{}
	entries, err := os.ReadDir(o.procRoot)
	if err != nil {
		return
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		comm, err := os.ReadFile(filepath.Join(o.procRoot, e.Name(), "comm"))
		if err != nil {
			continue
		}
		p := &monitor.ProcInfo{PID: pid, Name: strings.TrimSpace(string(comm))}
		if exe, err := os.Readlink(filepath.Join(o.procRoot, e.Name(), "exe")); err == nil {
			p.Exe = exe
		}
		if !monitor.IsSystemResolver(p) {
			continue
		}
		full := monitor.ProcInfoOf(pid)
		o.resolverPID[pid] = full
		if uid, ok := procUID(filepath.Join(o.procRoot, e.Name(), "status")); ok && uid != 0 {
			o.resolverUID[uid] = full
		}
	}
}

func procUID(statusPath string) (uint32, bool) {
	b, err := os.ReadFile(statusPath)
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "Uid:" {
			u, err := strconv.ParseUint(f[1], 10, 32)
			return uint32(u), err == nil
		}
	}
	return 0, false
}

func hasSocket(fdDir string, inode uint64) bool {
	want := "socket:[" + strconv.FormatUint(inode, 10) + "]"
	fds, err := os.ReadDir(fdDir)
	if err != nil {
		return false
	}
	for _, fd := range fds {
		if l, err := os.Readlink(filepath.Join(fdDir, fd.Name())); err == nil && l == want {
			return true
		}
	}
	return false
}

// readUDPTable maps local ports to sockets from /proc/net/udp or udp6:
// "sl local_address rem_address st tx:rx tr:when retrnsmt uid timeout inode".
func readUDPTable(path string) map[uint16]sock {
	out := map[uint16]sock{}
	b, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for i, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 10 {
			continue
		}
		_, portHex, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		port, err1 := strconv.ParseUint(portHex, 16, 16)
		uid, err2 := strconv.ParseUint(f[7], 10, 32)
		inode, err3 := strconv.ParseUint(f[9], 10, 64)
		if err1 != nil || err2 != nil || err3 != nil {
			continue
		}
		out[uint16(port)] = sock{uid: uint32(uid), inode: inode}
	}
	return out
}
