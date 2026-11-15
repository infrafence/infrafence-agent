package main

import (
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/router/sysinfo"
)

// status is what LuCI and `infrafence-router status` show. No secrets:
// the file is world-readable (LuCI reads it through rpcd's file ACL).
type status struct {
	Running        bool     `json:"running"`
	Registered     bool     `json:"registered"`
	Version        string   `json:"version"`
	Server         string   `json:"server"`
	AgentID        int64    `json:"agent_id"`
	Connected      bool     `json:"connected"`
	LastHeartbeat  string   `json:"last_heartbeat,omitempty"`
	LastSync       string   `json:"last_sync,omitempty"`
	Mode           string   `json:"mode"`
	Synced         bool     `json:"synced"`
	Suspended      bool     `json:"suspended,omitempty"`
	Firewall       string   `json:"firewall"`
	Backend        string   `json:"firewall_backend"`
	Bans           int      `json:"bans"`
	Feed           int      `json:"feed"`
	C2             int      `json:"c2"`
	BlockedDomains int      `json:"blocked_domains"`
	DNSBlocking    bool     `json:"dns_blocking_active"`
	DNSCapture     bool     `json:"dns_capture"`
	LANDevices     int      `json:"lan_devices"`
	Flagged        int      `json:"flagged_devices"`
	Coexisting     []string `json:"coexisting,omitempty"`
	Error          string   `json:"error,omitempty"`
	UpdatedAt      string   `json:"updated_at"`
}

func (a *agent) writeStatus() {
	b, f, c := 0, 0, 0
	if a.fw != nil {
		b, f, c = a.fw.Counts()
	}
	n, _ := a.dns.Count()
	a.mu.Lock()
	st := status{
		Running:        true,
		Registered:     true,
		Version:        version,
		Server:         a.cfg.ServerURL,
		AgentID:        a.cfg.AgentID,
		Connected:      !a.lastHeartbeat.IsZero() && time.Since(a.lastHeartbeat) < 3*heartbeatEvery,
		Mode:           a.mode.String(),
		Synced:         a.synced,
		Suspended:      a.suspended,
		Firewall:       a.info.Firewall,
		Backend:        a.backendName(),
		Bans:           b,
		Feed:           f,
		C2:             c,
		BlockedDomains: n,
		DNSBlocking:    a.dnsActive,
		DNSCapture:     a.dnsCapturing,
		LANDevices:     a.inv.Len(),
		Coexisting:     a.info.Coexisting,
		Error:          a.lastError,
		UpdatedAt:      time.Now().UTC().Format(time.RFC3339),
	}
	if !a.lastHeartbeat.IsZero() {
		st.LastHeartbeat = a.lastHeartbeat.UTC().Format(time.RFC3339)
	}
	if !a.lastSync.IsZero() {
		st.LastSync = a.lastSync.UTC().Format(time.RFC3339)
	}
	if st.Error == "" && a.dnsErr != "" {
		st.Error = "dns: " + a.dnsErr
	}
	a.mu.Unlock()
	st.Flagged = a.find.flaggedCount()
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return
	}
	if err := writeFileAtomic(statusPath, append(data, '\n'), 0o644); err != nil {
		log.Printf("[status] %v", err)
	}
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// metrics are memory and overlay (flash) use; CPU is the load average.
func metrics(info sysinfo.Info) *api.SystemMetrics {
	m := &api.SystemMetrics{}
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		var total, avail uint64
		for _, l := range strings.Split(string(b), "\n") {
			fs := strings.Fields(l)
			if len(fs) < 2 {
				continue
			}
			v, _ := strconv.ParseUint(fs[1], 10, 64)
			switch fs[0] {
			case "MemTotal:":
				total = v * 1024
			case "MemAvailable:":
				avail = v * 1024
			}
		}
		if total > 0 && avail <= total {
			m.MemoryTotal, m.MemoryUsed = total, total-avail
			m.MemoryPercent = float64(total-avail) * 100 / float64(total)
		}
	}
	for _, p := range []string{"/overlay", "/"} {
		var st syscall.Statfs_t
		if syscall.Statfs(p, &st) == nil && st.Blocks > 0 {
			total := uint64(st.Blocks) * uint64(st.Bsize)
			free := uint64(st.Bavail) * uint64(st.Bsize)
			m.DiskTotal, m.DiskUsed = total, total-free
			m.DiskPercent = float64(total-free) * 100 / float64(total)
			break
		}
	}
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		if fs := strings.Fields(string(b)); len(fs) > 0 {
			l, _ := strconv.ParseFloat(fs[0], 64)
			m.CPUPercent = l * 100 // one-minute load as a share of one core
		}
	}
	return m
}

func rss() uint64 {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "VmRSS:") {
			fs := strings.Fields(l)
			if len(fs) >= 2 {
				kb, _ := strconv.ParseUint(fs[1], 10, 64)
				return kb * 1024
			}
		}
	}
	return 0
}

func runQuiet(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// applyTestIntervals shortens the loops for the e2e test (never set on a
// real router): INFRAFENCE_TEST_FAST=1.
func applyTestIntervals() {
	if os.Getenv("INFRAFENCE_TEST_FAST") != "1" {
		return
	}
	heartbeatEvery = 5 * time.Second
	syncEvery = 15 * time.Second
	hitsEvery = 5 * time.Second
	watchdogEvery = 5 * time.Second
	conntrackEvery = 10 * time.Second
	devicesEvery = 10 * time.Second
	reportDevEvery = 10 * time.Second
	statusEvery = 3 * time.Second
	dnsMinRestart = 5 * time.Second
}
