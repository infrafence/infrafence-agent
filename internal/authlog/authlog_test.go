package authlog

import (
	"errors"
	"io/fs"
	"os"
	"testing"
)

func fake(t *testing.T, files []string, journal bool) {
	t.Helper()
	oldStat, oldLook, oldReady := stat, lookPath, journalReady
	t.Cleanup(func() { stat, lookPath, journalReady = oldStat, oldLook, oldReady })
	set := map[string]bool{}
	for _, f := range files {
		set[f] = true
	}
	stat = func(p string) (os.FileInfo, error) {
		if set[p] {
			return nil, nil
		}
		return nil, fs.ErrNotExist
	}
	lookPath = func(string) (string, error) {
		if journal {
			return "/usr/bin/journalctl", nil
		}
		return "", errors.New("not found")
	}
	journalReady = func() bool { return journal }
}

func TestDetect(t *testing.T) {
	cases := []struct {
		name    string
		env     string
		files   []string
		journal bool
		want    Source
	}{
		{"systemd with rsyslog: journal first", "", []string{"/var/log/auth.log"}, true, Source{Journal: true}},
		{"rhel with rsyslog: journal first", "", []string{"/var/log/secure"}, true, Source{Journal: true}},
		{"journald only", "", nil, true, Source{Journal: true}},
		{"no journal (container)", "", []string{"/var/log/auth.log"}, false, Source{Path: "/var/log/auth.log"}},
		{"no journal, rhel file", "", []string{"/var/log/secure"}, false, Source{Path: "/var/log/secure"}},
		{"nothing at all", "", nil, false, Source{Path: "/var/log/auth.log"}},
		{"installer default path: journal first", "/var/log/auth.log", []string{"/var/log/auth.log"}, true, Source{Journal: true}},
		{"custom path set by the admin", "/custom/auth", []string{"/custom/auth", "/var/log/auth.log"}, true, Source{Path: "/custom/auth"}},
		{"custom path missing, journal available", "/custom/auth", nil, true, Source{Journal: true}},
		{"custom path missing, no journal", "/custom/auth", nil, false, Source{Path: "/custom/auth"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fake(t, c.files, c.journal)
			t.Setenv("AUTH_LOG_PATH", c.env)
			if got := Detect(); got != c.want {
				t.Fatalf("Detect() = %+v, want %+v", got, c.want)
			}
		})
	}
}
