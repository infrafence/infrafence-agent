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
		{"debian with rsyslog", "", []string{"/var/log/auth.log"}, true, Source{Path: "/var/log/auth.log"}},
		{"rhel with rsyslog", "", []string{"/var/log/secure"}, true, Source{Path: "/var/log/secure"}},
		{"journald only", "", nil, true, Source{Journal: true}},
		{"nothing at all", "", nil, false, Source{Path: "/var/log/auth.log"}},
		{"configured file exists", "/custom/auth", []string{"/custom/auth", "/var/log/auth.log"}, true, Source{Path: "/custom/auth"}},
		{"installer set a missing file", "/var/log/auth.log", nil, true, Source{Journal: true}},
		{"missing file, secure exists", "/var/log/auth.log", []string{"/var/log/secure"}, true, Source{Path: "/var/log/secure"}},
		{"missing file, no journal", "/custom/auth", nil, false, Source{Path: "/custom/auth"}},
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
