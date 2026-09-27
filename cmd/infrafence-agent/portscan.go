package main

import (
	"log"
	"net"
	"sync/atomic"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/firewall"
	"github.com/infrafence/infrafence-agent/internal/scanwatch"
)

// portScanBan: the dashboard asked to ban detected port scanners (off by
// default — monitoring services and search engines like Shodan scan too).
var portScanBan atomic.Bool

// portScanWatcher detects port scans from incoming connection attempts
// (internal/scanwatch); started by the first sync unless the dashboard
// turned it off.
var portScanWatcher = scanwatch.New(portScanSkip, onPortScan)

// portScanSkip: never report reserved/own/protected or whitelisted
// addresses.
func portScanSkip(ip net.IP) bool {
	if firewall.IsSafeIP(ip) {
		return true
	}
	intelState.Lock()
	wl := intelState.whitelist
	intelState.Unlock()
	for _, w := range wl {
		if w == ip.String() {
			return true
		}
		if _, n, err := net.ParseCIDR(w); err == nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

func onPortScan(s scanwatch.Scan) {
	client := currentAPIClient.Load()
	if client == nil {
		return
	}
	log.Printf("[portscan] %s tried %d ports in %s (%v)", s.IP, s.Ports, scanwatch.Window, s.Sample)
	if err := client.ReportEvents([]api.EventRequest{{
		Type:       "port_scan",
		Severity:   "warning",
		SourceIP:   s.IP,
		Details:    s.Details(),
		OccurredAt: time.Now().UTC().Format(time.RFC3339),
	}}); err != nil {
		log.Printf("[portscan] failed to report: %v", err)
	}
	if portScanBan.Load() {
		intelState.Lock()
		monitor := intelState.monitorMode
		intelState.Unlock()
		if !monitor {
			banAndReport(client, "portscan", s.IP, "port_scan", s.Ports)
		}
	}
}
