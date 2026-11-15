//go:build freebsd

package main

import (
	"encoding/binary"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/infrafence/infrafence-agent/internal/api"
)

type applianceMetrics struct {
	api.SystemMetrics
	RSS    uint64
	Uptime int64
}

var cpuPrev struct {
	sync.Mutex
	total, idle uint64
}

// readApplianceMetrics reads FreeBSD's sysctls (no /proc on FreeBSD).
func readApplianceMetrics() applianceMetrics {
	var m applianceMetrics
	if phys, err := unix.SysctlUint64("hw.physmem"); err == nil {
		m.MemoryTotal = phys
		page, _ := unix.SysctlUint32("hw.pagesize")
		free, _ := unix.SysctlUint32("vm.stats.vm.v_free_count")
		inact, _ := unix.SysctlUint32("vm.stats.vm.v_inactive_count")
		avail := uint64(free+inact) * uint64(page)
		if avail < phys {
			m.MemoryUsed = phys - avail
		}
		if phys > 0 {
			m.MemoryPercent = float64(m.MemoryUsed) * 100 / float64(phys)
		}
	}
	// struct loadavg { fixpt_t ldavg[3]; long fscale; }
	if raw, err := unix.SysctlRaw("vm.loadavg"); err == nil && len(raw) >= 16 {
		fscale := float64(binary.LittleEndian.Uint32(raw[12:16]))
		if len(raw) >= 24 {
			fscale = float64(binary.LittleEndian.Uint64(raw[16:24]))
		}
		if fscale > 0 {
			m.LoadAvg1 = float64(binary.LittleEndian.Uint32(raw[0:4])) / fscale
			m.LoadAvg5 = float64(binary.LittleEndian.Uint32(raw[4:8])) / fscale
			m.LoadAvg15 = float64(binary.LittleEndian.Uint32(raw[8:12])) / fscale
		}
	}
	// kern.cp_time: user, nice, sys, intr, idle (longs).
	if raw, err := unix.SysctlRaw("kern.cp_time"); err == nil && len(raw) >= 40 {
		var total uint64
		for i := 0; i < 5; i++ {
			total += binary.LittleEndian.Uint64(raw[i*8:])
		}
		idle := binary.LittleEndian.Uint64(raw[32:])
		cpuPrev.Lock()
		if dt := total - cpuPrev.total; cpuPrev.total > 0 && dt > 0 {
			m.CPUPercent = float64(dt-(idle-cpuPrev.idle)) * 100 / float64(dt)
		}
		cpuPrev.total, cpuPrev.idle = total, idle
		cpuPrev.Unlock()
	}
	var st unix.Statfs_t
	if unix.Statfs("/", &st) == nil {
		m.DiskTotal = st.Blocks * st.Bsize
		if st.Bavail > 0 {
			m.DiskUsed = m.DiskTotal - uint64(st.Bavail)*st.Bsize
		}
		if m.DiskTotal > 0 {
			m.DiskPercent = float64(m.DiskUsed) * 100 / float64(m.DiskTotal)
		}
	}
	var ru syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &ru) == nil {
		m.RSS = uint64(ru.Maxrss) * 1024 // peak RSS, KiB on FreeBSD
	}
	if tv, err := unix.SysctlTimeval("kern.boottime"); err == nil {
		m.Uptime = int64(time.Since(time.Unix(tv.Sec, int64(tv.Usec)*1000)).Seconds())
	}
	return m
}
