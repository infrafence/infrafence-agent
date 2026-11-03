package main

import (
	"log"
	"strconv"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/watcher"
)

// Replaced in tests.
var (
	exposedDBPortList = watcher.ExposedDBPortList
	dbPortClosed      = portClosedByAgent
)

// watchExposedDBPorts reports the database ports open to the internet at
// startup and then every interval (read only: the socket table). A port is
// reported again only when it changes: newly exposed, listening on other
// addresses, or no longer closed by the agent's firewall. A port the
// agent's firewall closes to the public is not exposed: reporting it again
// would reopen the problem it resolved (resolution.go).
func watchExposedDBPorts(client *api.Client, interval time.Duration) {
	last := map[int]string{}
	for {
		checkExposedDBPorts(last, func(e api.EventRequest) { client.ReportEvents([]api.EventRequest{e}) })
		time.Sleep(interval)
	}
}

// checkExposedDBPorts runs one check; last holds what each port looked
// like at the previous one and is updated.
func checkExposedDBPorts(last map[int]string, report func(api.EventRequest)) {
	now := map[int]bool{}
	for _, x := range exposedDBPortList() {
		now[x.Port] = true
		closed := dbPortClosed(x.Port)
		state := x.BindAddress
		if closed {
			state = "closed|" + state
		}
		if last[x.Port] == state {
			continue
		}
		last[x.Port] = state
		if closed {
			log.Printf("[dbwatcher] %s listens on %s; the firewall closes it to the public", x.Service, x.BindAddress)
			continue
		}
		log.Printf("[dbwatcher] WARNING: %s (%s)", x.Warning, x.BindAddress)
		report(api.EventRequest{
			Type:     "db_exposed",
			Severity: "critical",
			Details: map[string]string{
				"warning": x.Warning, "port": strconv.Itoa(x.Port), "proto": "tcp", "service": x.Service,
				"bind_address": x.BindAddress,
			},
			OccurredAt: time.Now().UTC().Format(time.RFC3339),
		})
	}
	for port := range last {
		if !now[port] {
			log.Printf("[dbwatcher] port %d no longer listens on a public address", port)
			delete(last, port)
		}
	}
}
