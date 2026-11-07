package dbclients

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"
)

// Declared clients the database itself authorizes, on every server, panel
// or not: the hosts of MySQL/MariaDB's accounts (mysql.user, the hosts an
// administrator granted: on cPanel also each account's Remote MySQL hosts)
// and the host lines of PostgreSQL's pg_hba.conf. Only what an
// administrator wrote counts, so a client cannot add itself. Read only: one
// SELECT through the local socket as root with root's own option file
// (/root/.my.cnf, as cPanel and Debian keep it) or the socket's own
// authentication, never a prompt; for PostgreSQL the file pg_hba.conf.
// Kept: addresses, CIDR ranges, address/netmask and a.b.c.% patterns of
// public networks (hostEntry), never "%", local addresses or host names
// (not resolved). Databases in containers are not read (no exec into a
// container): their published ports are covered by held connections and
// the allow list only.

const (
	// Sources of Declared.
	SourceMySQLGrants = "mysql_grants"
	SourcePGHBA       = "pg_hba"

	mysqlPort    = 3306
	pgPort       = 5432
	queryTimeout = 10 * time.Second
	maxHBAFile   = 1 << 20
)

// Replaced in tests.
var (
	// MySQLQuery runs the grant hosts query, nil error on success.
	MySQLQuery = runMySQLQuery
	// PGHBAFile asks PostgreSQL where pg_hba.conf is ("" when it cannot).
	PGHBAFile = askHBAFile
	// PGHBAPaths are tried when PostgreSQL cannot be asked.
	PGHBAPaths = []string{
		"/etc/postgresql/*/main/pg_hba.conf",
		"/var/lib/pgsql/*/data/pg_hba.conf",
		"/var/lib/pgsql/data/pg_hba.conf",
	}
	rootMyCnf = "/root/.my.cnf"
)

const grantHostsQuery = "SELECT DISTINCT Host FROM mysql.user"

func runMySQLQuery() ([]byte, error) {
	bin, err := exec.LookPath("mysql")
	if err != nil {
		if bin, err = exec.LookPath("mariadb"); err != nil {
			return nil, err
		}
	}
	var args []string
	if _, err := os.Stat(rootMyCnf); err == nil {
		args = append(args, "--defaults-file="+rootMyCnf)
	}
	args = append(args, "--protocol=socket", "--connect-timeout=5", "-N", "-B", "-e", grantHostsQuery)
	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = nil
	var out bytes.Buffer
	cmd.Stdout = &limitWriter{w: &out, n: maxAccessFile}
	err = cmd.Run()
	return out.Bytes(), err
}

func askHBAFile() string {
	if _, err := exec.LookPath("psql"); err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "runuser", "-u", "postgres", "--", "psql", "-w", "-X", "-Atc", "SHOW hba_file")
	cmd.Env = append(os.Environ(), "PGCONNECT_TIMEOUT=5")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// ReadMySQLGrants returns the declared clients of MySQL from its accounts'
// hosts and the host names left out. err is set when the query failed (no
// client, no server, no access).
func ReadMySQLGrants() (out []Declared, names []string, err error) {
	b, err := MySQLQuery()
	if err != nil {
		return nil, nil, err
	}
	out, names = ParseGrantHosts(string(b))
	return out, names, nil
}

// ParseGrantHosts parses the Host column, one per line.
func ParseGrantHosts(data string) (out []Declared, names []string) {
	seen := map[string]bool{}
	for _, line := range strings.Split(data, "\n") {
		host := strings.TrimSpace(line)
		if host == "" {
			continue
		}
		if e := specificEntry(host); e != "" {
			if !seen[e] && len(out) < maxAccessHosts {
				seen[e] = true
				out = append(out, Declared{Entry: e, Host: host, Source: SourceMySQLGrants, Port: mysqlPort})
			}
			continue
		}
		// A host name or a name pattern (%.example.com): not resolved.
		if net.ParseIP(host) == nil && !strings.EqualFold(host, "localhost") &&
			strings.IndexFunc(host, unicode.IsLetter) >= 0 {
			names = append(names, host)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Entry < out[j].Entry })
	sort.Strings(names)
	return out, names
}

// ReadPGHBA returns the declared clients of PostgreSQL from pg_hba.conf
// (the file PostgreSQL names, else the usual places). ok is false when no
// file was found.
func ReadPGHBA() (out []Declared, ok bool) {
	var files []string
	if f := PGHBAFile(); f != "" {
		files = []string{f}
	} else {
		for _, pat := range PGHBAPaths {
			m, _ := filepath.Glob(pat)
			files = append(files, m...)
		}
	}
	seen := map[string]bool{}
	for _, path := range files {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(f, maxHBAFile))
		f.Close()
		ok = true
		for _, d := range ParsePGHBA(string(b)) {
			if !seen[d.Entry] && len(out) < maxAccessHosts {
				seen[d.Entry] = true
				out = append(out, d)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Entry < out[j].Entry })
	return out, ok
}

// ParsePGHBA parses pg_hba.conf: the host, hostssl, hostnossl, hostgssenc
// and hostnogssenc lines with an address or range of a public network and
// a method other than reject. "all", samehost, samenet, host names and
// include directives are left out.
func ParsePGHBA(data string) []Declared {
	var out []Declared
	for _, line := range strings.Split(data, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		switch f[0] {
		case "host", "hostssl", "hostnossl", "hostgssenc", "hostnogssenc":
		default:
			continue
		}
		addr, rest := strings.Trim(f[3], `"`), f[4:]
		if !strings.Contains(addr, "/") {
			// An address with its netmask in the next field.
			if len(rest) < 2 {
				continue
			}
			addr, rest = addr+"/"+rest[0], rest[1:]
		}
		if strings.EqualFold(rest[0], "reject") {
			continue
		}
		if e := specificEntry(addr); e != "" {
			out = append(out, Declared{Entry: e, Host: f[3], Source: SourcePGHBA, Port: pgPort})
		}
	}
	return out
}

// specificEntry is hostEntry with a single-address range (/32, /128) as
// the address.
func specificEntry(h string) string {
	e := hostEntry(h)
	if _, n, err := net.ParseCIDR(e); err == nil {
		if ones, bits := n.Mask.Size(); ones == bits {
			return normIP(n.IP.String())
		}
	}
	return e
}

// limitWriter keeps the first n bytes and drops the rest.
type limitWriter struct {
	w io.Writer
	n int
}

func (l *limitWriter) Write(p []byte) (int, error) {
	k := len(p)
	if l.n <= 0 {
		return k, nil
	}
	if len(p) > l.n {
		p = p[:l.n]
	}
	n, err := l.w.Write(p)
	l.n -= n
	if err != nil {
		return n, err
	}
	return k, nil
}
