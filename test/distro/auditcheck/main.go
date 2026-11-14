// Command auditcheck validates an audit report (schema 1) for the distro
// matrix (test/distro/freeaudit.sh): strict decoding (no unknown field),
// the schema's rules (audit.Report.Validate), every v1 check id present,
// none of the forbidden strings (host name, server addresses) anywhere,
// and the facts the test set up (an SSH attack, a public database port).
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/infrafence/infrafence-agent/internal/audit"
)

var v1IDs = []string{
	audit.IDSSHPasswordAuth, audit.IDSSHRootLogin, audit.IDSSHDefaultPortOpen,
	audit.IDDBPublic, audit.IDAdminPublic, audit.IDUpdatesSecurity, audit.IDRebootRequired,
	audit.IDOSEOL, audit.IDFirewallNone, audit.IDBruteforceNoProtect, audit.IDUsersUID0Extra,
	audit.IDUsersEmptyPassword, audit.IDFilesWorldWritable, audit.IDPHPDangerous,
}

func main() {
	path := flag.String("report", "", "report JSON file")
	forbid := flag.String("forbid", "", "comma-separated strings that must not appear")
	minSSH := flag.Int("min-ssh", 0, "at least this many failed SSH logins")
	topIP := flag.String("top-ip", "", "an address that must be in top_ips")
	dbPort := flag.String("db-port", "", "a port that must be reported as services.db_public fail")
	flag.Parse()

	var errs []string
	fail := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }

	raw, err := os.ReadFile(*path)
	if err != nil {
		fmt.Println("auditcheck:", err)
		os.Exit(1)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var r audit.Report
	if err := dec.Decode(&r); err != nil {
		fmt.Println("auditcheck: decode:", err)
		os.Exit(1)
	}
	if err := r.Validate(); err != nil {
		fail("schema: %v", err)
	}
	seen := map[string]bool{}
	dbOK := *dbPort == ""
	for _, c := range r.Checks {
		seen[c.ID] = true
		if c.ID == audit.IDDBPublic && c.Status == audit.StatusFail && c.Facts["port"] == *dbPort {
			dbOK = true
		}
	}
	for _, id := range v1IDs {
		if !seen[id] {
			fail("check %s missing", id)
		}
	}
	if !dbOK {
		fail("port %s not reported as a public database", *dbPort)
	}
	low := strings.ToLower(string(raw))
	for _, s := range strings.Split(*forbid, ",") {
		if s = strings.TrimSpace(s); s != "" && strings.Contains(low, strings.ToLower(s)) {
			fail("private value %q in the report", s)
		}
	}
	if r.Attacks.SSHFailedLogins < *minSSH {
		fail("ssh_failed_logins %d < %d", r.Attacks.SSHFailedLogins, *minSSH)
	}
	if *topIP != "" {
		found := false
		for _, t := range r.Attacks.TopIPs {
			found = found || t.IP == *topIP
		}
		if !found {
			fail("%s not in top_ips %+v", *topIP, r.Attacks.TopIPs)
		}
	}
	if len(errs) > 0 {
		for _, e := range errs {
			fmt.Println("auditcheck:", e)
		}
		os.Exit(1)
	}
	fmt.Printf("auditcheck: ok (%d checks, ssh %d/%d, web %d, firewall %s, updates %s/%s)\n",
		len(r.Checks), r.Attacks.SSHFailedLogins, r.Attacks.SSHUniqueIPs, r.Attacks.WebSuspiciousRequests,
		r.Protection.Firewall, intOrNull(r.Updates.Security), intOrNull(r.Updates.Total))
}

func intOrNull(p *int) string {
	if p == nil {
		return "null"
	}
	return fmt.Sprint(*p)
}
