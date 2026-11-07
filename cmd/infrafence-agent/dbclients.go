package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/dbclients"
	"github.com/infrafence/infrafence-agent/internal/firewall"
	"github.com/infrafence/infrafence-agent/internal/netstate"
)

// Regular clients of the closable ports (dbclients package). Once a minute
// the agent reads, read only, which public addresses have an established
// connection to a port of closablePorts (the socket table, and the
// conntrack table for published container ports), and counts each address
// once per minute per port and day. An address seen on 3 of the last 7
// days is a regular client; on cPanel/WHM the Additional MySQL Access Hosts
// are declared clients of 3306 from the first minute.
//
// The database watcher never bans a regular client that holds its
// connections open (a connection pool, a replica: knownDBClient, from
// dbclients.Log.Held) or a declared client: an application with a wrong or
// just changed password keeps failing its logins and must not be cut off.
// Accepted residual risk: a host that keeps an unauthenticated connection
// open on 3 of 7 days (an idle Redis or MongoDB connection, which those
// services allow) becomes known too.
//
// Before a port is closed (whoever asks: AutoMode, emergency mode, a
// person), the agent refuses with regular_clients while a regular or
// declared client is not on the allow list: closing would cut it off.
// Allow-listed addresses keep reaching a closed port, so once the clients
// are whitelisted the port closes.
//
// Every 15 minutes the counts the dashboard does not have yet go to
// /api/v1/agent/db-clients (at most dbReportMax entries per request), with
// the declared clients. A dashboard without the endpoint answers 404: the
// agent keeps counting and tries again an hour later.

var (
	dbClientsPath = "/var/lib/infrafence/db-clients.json"
	dbClientLog   atomic.Pointer[dbclients.Log]
	// dbDeclared: the declared clients last read (nil until read).
	dbDeclared atomic.Pointer[[]dbclients.Declared]
)

const (
	dbSampleEvery   = time.Minute
	dbReportEvery   = 15 * time.Minute
	dbDeclaredEvery = time.Hour
	// The conntrack tool (when /proc/net/nf_conntrack does not exist) runs
	// at most this often.
	dbToolEvery = 5 * time.Minute
	dbReportMax = 2000
	// dbMySQLPort: the declared cPanel hosts are clients of MySQL.
	dbMySQLPort = 3306
	// dbMessageMax: addresses named in a refusal message.
	dbMessageMax = 10
)

// dbTestDuration reads a duration from the environment in test builds
// (version "...-test"), so the distro test does not wait days.
func dbTestDuration(ver, name string, def time.Duration) time.Duration {
	if strings.HasSuffix(ver, "-test") {
		if d, err := time.ParseDuration(os.Getenv(name)); err == nil && d > 0 {
			return d
		}
	}
	return def
}

// startDBClients loads the log and starts sampling and reporting.
func startDBClients(client func() *api.Client, ver string) {
	l := dbclients.New(dbClientsPath)
	l.DayLength = dbTestDuration(ver, "INFRAFENCE_TEST_DBCLIENTS_DAY", 24*time.Hour)
	dbClientLog.Store(l)
	sample := dbTestDuration(ver, "INFRAFENCE_TEST_DBCLIENTS_SAMPLE", dbSampleEvery)
	report := dbTestDuration(ver, "INFRAFENCE_TEST_DBCLIENTS_REPORT", dbReportEvery)
	go watchDBClients(l, client, sample, report)
}

// Replaced in tests.
var (
	dbInbound     = netstate.InboundClients
	dbReadCPanel  = dbclients.ReadCPanelAccessHosts
	dbAllowListed = firewall.IsAllowListed
	dbAllowNet    = firewall.IsAllowListedNet
	dbSend        = func(c *api.Client, req api.DBClientsRequest) error { return c.ReportDBClients(req) }
)

func closablePortList() []int {
	out := make([]int, 0, len(closablePorts))
	for p := range closablePorts {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

func watchDBClients(l *dbclients.Log, client func() *api.Client, sample, report time.Duration) {
	var lastTool, lastDeclared, lastReport, retryAt time.Time
	ports := closablePortList()
	for {
		now := time.Now()
		withTool := now.Sub(lastTool) >= dbToolEvery
		if withTool {
			lastTool = now
		}
		clients, conns := dbInbound(ports, withTool)
		l.Observe(clients)
		l.ObserveConns(conns)
		if now.Sub(lastDeclared) >= dbDeclaredEvery {
			lastDeclared = now
			// Host names are resolved (bounded): not in the sampling path.
			go readDeclared()
		}
		if now.Sub(lastReport) >= report && !now.Before(retryAt) {
			lastReport = now
			if c := client(); c != nil {
				if err := reportDBClients(c, l); err != nil {
					// An older dashboard (404) or a transient error: the
					// counts are kept and sent later.
					log.Printf("[dbclients] report: %v (sent again later)", err)
					if api.IsRejected(err) {
						retryAt = now.Add(time.Hour)
					}
				}
			}
		}
		time.Sleep(sample)
	}
}

var dbDeclaredLogged sync.Once

func readDeclared() {
	d, ok := dbReadCPanel()
	if !ok {
		d = []dbclients.Declared{}
	}
	if len(d) > 0 {
		dbDeclaredLogged.Do(func() {
			log.Printf("[dbclients] %d declared MySQL client(s) in the WHM access hosts", len(d))
		})
	}
	dbDeclared.Store(&d)
}

// reportDBClients sends what the dashboard does not have yet.
func reportDBClients(c *api.Client, l *dbclients.Log) error {
	pending := l.Pending(dbReportMax)
	req := api.DBClientsRequest{Clients: make([]api.DBClient, 0, len(pending))}
	for _, r := range pending {
		req.Clients = append(req.Clients, api.DBClient{Port: r.Port, IP: r.IP, Day: r.Day, FirstSeen: r.FirstSeen, LastSeen: r.LastSeen, Samples: r.Samples})
	}
	if d := dbDeclared.Load(); d != nil {
		req.Declared = make([]api.DBDeclared, 0, len(*d))
		for _, x := range *d {
			req.Declared = append(req.Declared, api.DBDeclared{Port: dbMySQLPort, Entry: x.Entry, Host: x.Host, Source: x.Source})
		}
		req.DeclaredRead = true
	}
	if len(req.Clients) == 0 && !req.DeclaredRead {
		return nil
	}
	if err := dbSend(c, req); err != nil {
		return err
	}
	l.MarkSent(pending)
	return nil
}

// fwRegularClients is replaced in tests: the regular and declared clients
// of port that are not on the allow list (addresses or CIDR ranges).
var fwRegularClients = regularClientsNotAllowed

func regularClientsNotAllowed(port int) []string {
	var out []string
	seen := map[string]bool{}
	for _, c := range dbClientLog.Load().Regular(port) {
		if !seen[c.IP] && !dbAllowListed(c.IP) {
			seen[c.IP] = true
			out = append(out, c.IP)
		}
	}
	if port == dbMySQLPort {
		if d := dbDeclared.Load(); d != nil {
			for _, x := range *d {
				if !seen[x.Entry] && !dbAllowNet(x.Entry) {
					seen[x.Entry] = true
					out = append(out, x.Entry)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// knownDBClient is the database watcher's guard, on every server, panel or
// not: "regular_client" for a regular client of a port of closablePorts
// that held a connection open on those days (the sampler sees host and
// published container ports alike; a client that only connects for a
// moment, as a PHP page does, is protected by the whitelist),
// "declared_mysql_host" for an address in a declared remote MySQL host (an
// address or a range, cPanel/WHM only), "" when the address may be banned.
func knownDBClient(ip string) string {
	p := net.ParseIP(ip)
	if p == nil {
		return ""
	}
	l := dbClientLog.Load()
	for _, port := range closablePortList() {
		for _, c := range l.Held(port) {
			if net.ParseIP(c.IP).Equal(p) {
				return "regular_client"
			}
		}
	}
	if d := dbDeclared.Load(); d != nil {
		for _, x := range *d {
			if _, n, err := net.ParseCIDR(x.Entry); err == nil && n.Contains(p) {
				return "declared_mysql_host"
			}
			if net.ParseIP(x.Entry).Equal(p) {
				return "declared_mysql_host"
			}
		}
	}
	return ""
}

// regularClientsMessage words a regular_clients refusal.
func regularClientsMessage(port int, clients []string) string {
	named := clients
	more := ""
	if len(named) > dbMessageMax {
		named = named[:dbMessageMax]
		more = fmt.Sprintf(" and %d more", len(clients)-dbMessageMax)
	}
	return fmt.Sprintf("%d regular client(s) of port %d are not whitelisted (seen on %d of the last %d days, or declared remote MySQL hosts): %s%s",
		len(clients), port, dbclients.MinDays, dbclients.WindowDays, strings.Join(named, ", "), more)
}

func firstN(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
