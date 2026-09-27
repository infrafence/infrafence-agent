//go:build integration

package pkgupdate_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/infrafence/infrafence-agent/internal/pkgupdate"
	"github.com/infrafence/infrafence-agent/internal/preflight"
)

// Needs a throwaway Ubuntu 24.04 container where both perl and audit have
// updates (see test/distro or run it by hand). Never on a real server.
func TestRealAptUpdateOnlyRequestedSource(t *testing.T) {
	if os.Getenv("PKGUPDATE_INTEGRATION") != "1" {
		t.Skip("set PKGUPDATE_INTEGRATION=1 inside a throwaway container")
	}
	ver := func(p string) string {
		out, _ := exec.Command("dpkg-query", "-W", "-f=${Version}", p).Output()
		return string(out)
	}
	perlBefore, auditBefore := ver("perl-base"), ver("libaudit1")

	res, err := pkgupdate.Update(pkgupdate.NewHost(preflight.PackageOperationsRunning), []string{"perl"})
	if err != nil {
		t.Fatalf("Update: %v\n%s", err, res.Output)
	}
	t.Logf("upgraded: %v", res.Upgraded)
	t.Logf("services: %v reboot: %v", res.ServicesToRestart, res.RebootRequired)
	if ver("perl-base") == perlBefore {
		t.Fatal("perl-base not upgraded")
	}
	if ver("libaudit1") != auditBefore {
		t.Fatal("libaudit1 was upgraded although only perl was requested")
	}
	if len(res.Upgraded) == 0 || !strings.Contains(strings.Join(res.Upgraded, " "), "perl-base") {
		t.Fatalf("result = %+v", res.Upgraded)
	}
}
