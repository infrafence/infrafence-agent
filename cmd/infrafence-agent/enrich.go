package main

import (
	"net"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/netstate"
)

// enrichEvent completes an event before it is sent: SSH logins carry their
// address only in details.ip, so it becomes the source address too, and an
// event from a public address gets its country (ISO-2) when the country
// database knows it. country may be nil (no database).
func enrichEvent(e *api.EventRequest, country func(string) string) {
	if e.SourceIP == "" && e.Details["ip"] != "" &&
		(e.Type == "ssh_session" || e.Type == "system_audit" && e.Details["operation"] == "ssh_login") {
		if ip := net.ParseIP(e.Details["ip"]); ip != nil {
			e.SourceIP = ip.String()
		}
	}
	if country == nil || e.SourceIP == "" || e.Details["country"] != "" {
		return
	}
	ip := net.ParseIP(e.SourceIP)
	if ip == nil || !netstate.IsPublic(ip) {
		return
	}
	cc := country(ip.String())
	if cc == "" {
		return
	}
	// The details map may be shared with the caller: copy before adding.
	d := make(map[string]string, len(e.Details)+1)
	for k, v := range e.Details {
		d[k] = v
	}
	d["country"] = cc
	e.Details = d
}
