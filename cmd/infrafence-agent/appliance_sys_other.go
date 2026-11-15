//go:build !freebsd

package main

import "github.com/infrafence/infrafence-agent/internal/api"

type applianceMetrics struct {
	api.SystemMetrics
	RSS    uint64
	Uptime int64
}

// readApplianceMetrics: the appliance mode only runs on FreeBSD; elsewhere
// (tests) it reports nothing.
func readApplianceMetrics() applianceMetrics { return applianceMetrics{} }
