package monitor

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

// ProcInfo identifies the process that owns a socket.
type ProcInfo struct {
	PID  int
	Name string // /proc/<pid>/comm
	Exe  string // /proc/<pid>/exe target ("" if unreadable)
	User string
}

// Details returns the process as event details.
func (p *ProcInfo) Details() map[string]string {
	if p == nil {
		return map[string]string{}
	}
	d := map[string]string{"process": p.Name, "pid": strconv.Itoa(p.PID)}
	if p.Exe != "" {
		d["exe"] = p.Exe
	}
	if p.User != "" {
		d["user"] = p.User
	}
	return d
}

// procRoot is overridable in tests.
var procRoot = "/proc"

// socketOwners maps socket inodes to the processes holding them, by scanning
// /proc/<pid>/fd. Only the inodes asked for are looked up, and the scan stops
// once all are found; it runs only when a flow needs explaining.
func socketOwners(inodes map[uint64]bool) map[uint64]*ProcInfo {
	out := make(map[uint64]*ProcInfo, len(inodes))
	if len(inodes) == 0 {
		return out
	}
	pids, err := os.ReadDir(procRoot)
	if err != nil {
		return out
	}
	for _, p := range pids {
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join(procRoot, p.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			ino, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]"), 10, 64)
			if err != nil || !inodes[ino] || out[ino] != nil {
				continue
			}
			out[ino] = procInfo(pid)
			if len(out) == len(inodes) {
				return out
			}
		}
	}
	return out
}

func procInfo(pid int) *ProcInfo {
	dir := filepath.Join(procRoot, strconv.Itoa(pid))
	info := &ProcInfo{PID: pid}
	if b, err := os.ReadFile(filepath.Join(dir, "comm")); err == nil {
		info.Name = strings.TrimSpace(string(b))
	}
	if exe, err := os.Readlink(filepath.Join(dir, "exe")); err == nil {
		info.Exe = exe
	}
	if st, err := os.ReadFile(filepath.Join(dir, "status")); err == nil {
		for _, line := range strings.Split(string(st), "\n") {
			if f := strings.Fields(line); len(f) >= 2 && f[0] == "Uid:" {
				if u, err := user.LookupId(f[1]); err == nil {
					info.User = u.Username
				} else {
					info.User = f[1]
				}
				break
			}
		}
	}
	return info
}

// systemResolvers are DNS services whose job is to query upstream or root
// servers on the machine's behalf (process name as in /proc/<pid>/comm,
// which the kernel truncates to 15 characters).
var systemResolvers = map[string]bool{
	"systemd-resolve": true, // systemd-resolved
	"dnsmasq":         true,
	"unbound":         true,
	"named":           true, // BIND
	"pdns_recursor":   true,
	"kresd":           true, // Knot Resolver
	"coredns":         true,
	"nscd":            true,
	"dnscrypt-proxy":  true,
	"stubby":          true,
	"pihole-FTL":      true,
	"AdGuardHome":     true,
	"dockerd":         true, // Docker's embedded DNS forwards container queries
}

// systemExeDirs: a system resolver must run from a package-managed
// location, so a process that merely calls itself "dnsmasq" gets no pass.
var systemExeDirs = []string{"/usr/", "/lib/", "/lib64/", "/opt/", "/sbin/", "/bin/"}

// isSystemResolver reports whether p is the machine's own DNS service.
func isSystemResolver(p *ProcInfo) bool {
	if p == nil || !systemResolvers[p.Name] || p.Exe == "" {
		return false
	}
	if strings.HasSuffix(p.Exe, " (deleted)") {
		return false
	}
	for _, d := range systemExeDirs {
		if strings.HasPrefix(p.Exe, d) {
			return true
		}
	}
	return false
}
