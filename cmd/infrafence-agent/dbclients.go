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
	dbReadGrants  = dbclients.ReadMySQLGrants
	dbReadHBA     = dbclients.ReadPGHBA
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
			// Host names are resolved and the databases asked (bounded):
			// not in the sampling path, never two reads at once.
			if dbDeclaredRunning.CompareAndSwap(false, true) {
				go func() {
					defer dbDeclaredRunning.Store(false)
					readDeclared()
				}()
			}
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

var (
	dbDeclaredLogged, dbGrantsLogged, dbGrantNamesLogged, dbHBALogged sync.Once
	// dbGrantsFailing, dbHBAFailing: the source failed at the last read (its
	// previous entries are kept). Only readDeclared uses them, and reads
	// never overlap (dbDeclaredRunning).
	dbGrantsFailing, dbHBAFailing bool
	dbDeclaredRunning             atomic.Bool
	// dbWideLogged: the too wide entries already logged.
	dbWideLogged = map[string]bool{}
)

// readDeclared reads the declared clients: the WHM access hosts, the hosts
// of MySQL's accounts and pg_hba.conf's host lines. A source that cannot
// be read keeps its entries of the last read (a database restarting, a
// timeout under load), logged once per failure streak. Ranges wider than
// a /16 (IPv4) or a /48 (IPv6) are left out.
func readDeclared() {
	var prev []dbclients.Declared
	if p := dbDeclared.Load(); p != nil {
		prev = *p
	}
	kept := func(source string) []dbclients.Declared {
		var out []dbclients.Declared
		for _, x := range prev {
			if x.Source == source {
				out = append(out, x)
			}
		}
		return out
	}

	cp, _ := dbReadCPanel()
	d := append([]dbclients.Declared(nil), cp...)
	if len(d) > 0 {
		n := len(d)
		dbDeclaredLogged.Do(func() {
			log.Printf("[dbclients] %d declared MySQL client(s) in the WHM access hosts", n)
		})
	}

	g, names, err := dbReadGrants()
	if err != nil {
		g = kept(dbclients.SourceMySQLGrants)
		if !dbGrantsFailing {
			dbGrantsFailing = true
			log.Printf("[dbclients] MySQL accounts not read (%v): the %d declared client(s) of the last read are kept", err, len(g))
		}
	} else {
		if dbGrantsFailing {
			dbGrantsFailing = false
			log.Printf("[dbclients] MySQL accounts read again")
		}
		if len(g) > 0 {
			n := len(g)
			dbGrantsLogged.Do(func() {
				log.Printf("[dbclients] %d declared MySQL client(s) in the accounts' hosts", n)
			})
		}
		if len(names) > 0 {
			dbGrantNamesLogged.Do(func() {
				log.Printf("[dbclients] MySQL accounts: host name(s) ignored, not resolved (only addresses and ranges count): %s", strings.Join(firstN(names, dbMessageMax), ", "))
			})
		}
	}
	d = append(d, g...)

	h, ok := dbReadHBA()
	if !ok {
		h = kept(dbclients.SourcePGHBA)
		if !dbHBAFailing && len(h) > 0 {
			log.Printf("[dbclients] pg_hba.conf not read: the %d declared client(s) of the last read are kept", len(h))
		}
		dbHBAFailing = true
	} else {
		if dbHBAFailing && len(kept(dbclients.SourcePGHBA)) > 0 {
			log.Printf("[dbclients] pg_hba.conf read again")
		}
		dbHBAFailing = false
		if len(h) > 0 {
			n := len(h)
			dbHBALogged.Do(func() {
				log.Printf("[dbclients] %d declared PostgreSQL client(s) in pg_hba.conf", n)
			})
		}
	}
	d = append(d, h...)

	out := d[:0:0]
	for _, x := range d {
		if !declaredSpecific(x.Entry) {
			if key := x.Source + " " + x.Entry; !dbWideLogged[key] {
				dbWideLogged[key] = true
				log.Printf("[dbclients] %s %s (%s) ignored: wider than a /16 (IPv4) or a /48 (IPv6), it would exempt too many addresses", x.Source, x.Entry, x.Host)
			}
			continue
		}
		out = append(out, x)
	}
	dbDeclared.Store(&out)
}

// declaredSpecific: entry is an address, or a range of at least a /16
// (IPv4) or a /48 (IPv6).
func declaredSpecific(entry string) bool {
	if _, n, err := net.ParseCIDR(entry); err == nil {
		ones, bits := n.Mask.Size()
		return bits == 32 && ones >= 16 || bits == 128 && ones >= 48
	}
	return net.ParseIP(entry) != nil
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
			req.Declared = append(req.Declared, api.DBDeclared{Port: x.ClientPort(), Entry: x.Entry, Host: x.Host, Source: x.Source})
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
	if d := dbDeclared.Load(); d != nil {
		for _, x := range *d {
			if x.ClientPort() == port && !seen[x.Entry] && !dbAllowNet(x.Entry) {
				seen[x.Entry] = true
				out = append(out, x.Entry)
			}
		}
	}
	sort.Strings(out)
	return out
}

// knownDBClient is the database watcher's guard for a failed login on
// port, on every server, panel or not:
//   - "regular_client": a regular client of a port of closablePorts that
//     held a connection open on those days (the sampler sees host and
//     published container ports alike);
//   - a declared client of port: "declared_mysql_host" (the WHM access
//     hosts), "mysql_grant" (the hosts of MySQL's accounts), "pg_hba"
//     (pg_hba.conf), from the first minute and whatever its connections
//     (a PHP page that connects for a moment). Declared ranges wider than
//     a /16 (IPv4) or a /48 (IPv6) do not count;
//
// "" when the address may be banned. port 0 (a log of unknown type): a
// declared client of any port.
func knownDBClient(ip string, port int) string {
	p := net.ParseIP(ip)
	if p == nil {
		return ""
	}
	l := dbClientLog.Load()
	for _, cp := range closablePortList() {
		for _, c := range l.Held(cp) {
			if net.ParseIP(c.IP).Equal(p) {
				return "regular_client"
			}
		}
	}
	if d := dbDeclared.Load(); d != nil {
		for _, x := range *d {
			if !declaredFor(x, port) || !declaredCovers(x.Entry, p) {
				continue
			}
			switch x.Source {
			case dbclients.SourceMySQLGrants:
				return "mysql_grant"
			case dbclients.SourcePGHBA:
				return "pg_hba"
			}
			return "declared_mysql_host"
		}
	}
	return ""
}

// declaredFor: x is a declared client of the database whose log line was
// on port (the database's default port; 0: any). MySQL's and PostgreSQL's
// own lists count for their database whatever port it listens on.
func declaredFor(x dbclients.Declared, port int) bool {
	switch {
	case port == 0:
		return true
	case x.Source == dbclients.SourcePGHBA:
		return port == 5432
	case x.Source == dbclients.SourceMySQLGrants, x.Port == 0:
		return port == dbMySQLPort
	}
	return x.ClientPort() == port
}

// declaredCovers: entry (an address or a range of at least a /16 or a
// /48) contains p.
func declaredCovers(entry string, p net.IP) bool {
	if _, n, err := net.ParseCIDR(entry); err == nil {
		ones, bits := n.Mask.Size()
		return n.Contains(p) && (bits == 32 && ones >= 16 || bits == 128 && ones >= 48)
	}
	return net.ParseIP(entry).Equal(p)
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
