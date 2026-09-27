package pkgupdate

import (
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeHost struct {
	bins    map[string]bool
	files   map[string]bool
	busy    []string
	calls   []string
	envs    [][]string
	queries int
	// dpkg-query output before and after the upgrade
	before, after string
	fail          map[string]bool
}

func (h *fakeHost) Run(_ time.Duration, env []string, name string, args ...string) (string, error) {
	h.calls = append(h.calls, name+" "+strings.Join(args, " "))
	h.envs = append(h.envs, env)
	if h.fail[name] {
		return "E: something broke", errors.New("exit 100")
	}
	switch name {
	case "dpkg-query", "rpm":
		h.queries++
		if h.queries == 1 {
			return h.before, nil
		}
		return h.after, nil
	case "needrestart":
		return "NEEDRESTART-VER: 3.6\nNEEDRESTART-KSTA: 1\nNEEDRESTART-SVC: nginx.service\nNEEDRESTART-SVC: ssh.service\n", nil
	}
	return "done", nil
}
func (h *fakeHost) LookPath(n string) bool { return h.bins[n] }
func (h *fakeHost) Exists(p string) bool   { return h.files[p] }
func (h *fakeHost) Busy() []string         { return h.busy }

func aptHost() *fakeHost {
	return &fakeHost{
		bins:  map[string]bool{"apt-get": true, "dpkg-query": true, "needrestart": true},
		files: map[string]bool{},
		before: "ii \topenssh-server\topenssh\t1:9.2p1-2+deb12u2\n" +
			"ii \topenssh-client\topenssh\t1:9.2p1-2+deb12u2\n" +
			"ii \tlibssl3\topenssl\t3.0.11-1~deb12u2\n" +
			"ii \tbash\t\t5.2.15-2+b7\n" +
			"rc \told\told\t1\n",
		after: "ii \topenssh-server\topenssh\t1:9.2p1-2+deb12u3\n" +
			"ii \topenssh-client\topenssh\t1:9.2p1-2+deb12u3\n" +
			"ii \tlibssl3\topenssl\t3.0.11-1~deb12u2\n" +
			"ii \tbash\t\t5.2.15-2+b7\n",
	}
}

func TestAptUpgradesOnlyInstalledPackagesOfTheSources(t *testing.T) {
	h := aptHost()
	res, err := Update(h, []string{"openssh", "notinstalled"})
	if err != nil {
		t.Fatal(err)
	}
	var install string
	for _, c := range h.calls {
		if strings.HasPrefix(c, "apt-get install") {
			install = c
		}
	}
	for _, want := range []string{"--only-upgrade", "--force-confold", "openssh-client", "openssh-server"} {
		if !strings.Contains(install, want) {
			t.Fatalf("install call %q lacks %q", install, want)
		}
	}
	if strings.Contains(install, "libssl3") || strings.Contains(install, "notinstalled") || strings.Contains(install, "bash") {
		t.Fatalf("unrequested package in %q", install)
	}
	if len(res.Upgraded) != 2 || !strings.Contains(res.Upgraded[0], "→ 1:9.2p1-2+deb12u3") {
		t.Fatalf("upgraded = %v", res.Upgraded)
	}
	if strings.Join(res.ServicesToRestart, ",") != "nginx.service,ssh.service" {
		t.Fatalf("services = %v", res.ServicesToRestart)
	}
	// needrestart in list mode, never automatic restarts
	for i, c := range h.calls {
		if strings.HasPrefix(c, "apt-get") && !contains(h.envs[i], "NEEDRESTART_MODE=l") {
			t.Fatalf("%s without NEEDRESTART_MODE=l", c)
		}
	}
}

func TestBinaryNameAlsoAccepted(t *testing.T) {
	h := aptHost()
	if _, err := Update(h, []string{"bash"}); err != nil {
		t.Fatal(err)
	}
	if !anyContains(h.calls, "--force-confold bash") {
		t.Fatalf("a package without a separate source is matched by its own name: %v", h.calls)
	}
}

func TestRefusesWhileAnotherOperationRuns(t *testing.T) {
	h := aptHost()
	h.busy = []string{"unattended-upgr"}
	_, err := Update(h, []string{"openssh"})
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("err = %v", err)
	}
	if len(h.calls) != 0 {
		t.Fatalf("nothing should run: %v", h.calls)
	}
}

func TestNothingInstalledRunsNothing(t *testing.T) {
	h := aptHost()
	_, err := Update(h, []string{"nginx"})
	if !errors.Is(err, ErrNothing) {
		t.Fatalf("err = %v", err)
	}
	if anyContains(h.calls, "apt-get") {
		t.Fatalf("apt-get must not run: %v", h.calls)
	}
}

func TestInvalidNamesDropped(t *testing.T) {
	got := ValidNames([]string{"openssh", "-oDpkg::Options::=x", "OpenSSL", "a;rm -rf /", "", "openssh"})
	if strings.Join(got, ",") != "openssh,openssl" {
		t.Fatalf("got %v", got)
	}
}

func TestFailureReportsOutput(t *testing.T) {
	h := aptHost()
	h.fail = map[string]bool{"apt-get": true}
	res, err := Update(h, []string{"openssh"})
	if err == nil || !strings.Contains(res.Output, "E: something broke") {
		t.Fatalf("err=%v output=%q", err, res.Output)
	}
}

func TestDnf(t *testing.T) {
	h := &fakeHost{
		bins:   map[string]bool{"dnf": true, "needs-restarting": true},
		before: "openssl-libs\topenssl-3.0.7-24.el9.src.rpm\t1:3.0.7-24.el9\nbash\tbash-5.1.8-9.el9.src.rpm\t5.1.8-9.el9\n",
		after:  "openssl-libs\topenssl-3.0.7-27.el9.src.rpm\t1:3.0.7-27.el9\nbash\tbash-5.1.8-9.el9.src.rpm\t5.1.8-9.el9\n",
	}
	res, err := Update(h, []string{"openssl"})
	if err != nil {
		t.Fatal(err)
	}
	if !anyContains(h.calls, "dnf upgrade -y --refresh openssl-libs") || anyContains(h.calls, "bash") {
		t.Fatalf("calls = %v", h.calls)
	}
	if len(res.Upgraded) != 1 {
		t.Fatalf("upgraded = %v", res.Upgraded)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func anyContains(list []string, s string) bool {
	for _, x := range list {
		if strings.Contains(x, s) {
			return true
		}
	}
	return false
}
