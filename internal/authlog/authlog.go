// Package authlog decides where the agent reads SSH and other
// authentication messages from, and follows the systemd journal when there
// is no log file.
//
// On systemd hosts every authentication message goes to the journal first;
// rsyslog, where installed, copies it to /var/log/auth.log (Debian/Ubuntu)
// or /var/log/secure (RHEL family). Recent Debian, Fedora and Amazon Linux
// don't install rsyslog at all. Reading the journal's auth and authpriv
// facilities gives exactly the lines rsyslog writes, in the same
// "Mon DD HH:MM:SS host prog[pid]: message" format, so every parser works on
// either source unchanged.
package authlog

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
)

// Source is where authentication messages are read from: a log file, or the
// journal when Journal is true.
type Source struct {
	Path    string
	Journal bool
}

func (s Source) String() string {
	if s.Journal {
		return "the systemd journal (auth, authpriv)"
	}
	return s.Path
}

// Candidate log files, in order.
var logFiles = []string{"/var/log/auth.log", "/var/log/secure"}

// Replaced in tests.
var (
	stat         = os.Stat
	lookPath     = exec.LookPath
	journalReady = func() bool {
		_, err := os.Stat("/run/systemd/journal")
		return err == nil
	}
)

func exists(p string) bool {
	_, err := stat(p)
	return err == nil
}

func journalAvailable() bool {
	if _, err := lookPath("journalctl"); err != nil {
		return false
	}
	return journalReady()
}

// Detect picks the source. On systemd hosts the journal comes first: sshd
// and PAM log to it (/dev/log is journald's socket) and rsyslog only copies
// from it, so the journal has every message even when rsyslog is stopped or
// its journal reader is stuck — which left /var/log/secure empty on Rocky
// Linux 9 in our tests while the journal had every failed login.
//
// A log file is used when there is no journal (the agent in a container,
// non-systemd hosts), or when AUTH_LOG_PATH names a file other than the
// standard ones (a custom setup the admin chose). The standard paths are
// what installers before v1.0.25 wrote into the service by default.
func Detect() Source {
	if p := os.Getenv("AUTH_LOG_PATH"); p != "" && !isStandard(p) {
		if exists(p) || !journalAvailable() {
			return Source{Path: p}
		}
	}
	if journalAvailable() {
		return Source{Journal: true}
	}
	for _, p := range logFiles {
		if exists(p) {
			return Source{Path: p}
		}
	}
	return Source{Path: logFiles[0]}
}

func isStandard(p string) bool {
	for _, f := range logFiles {
		if p == f {
			return true
		}
	}
	return false
}

// journalArgs follow new auth/authpriv messages only (no history), in the
// syslog-like "short" format.
var journalArgs = []string{"--follow", "--lines=0", "--output=short", "--no-pager",
	"SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10"}

// FollowJournal calls onLine for every new authentication message in the
// journal until ctx is done or journalctl exits (the caller retries).
func FollowJournal(ctx context.Context, onLine func(string)) error {
	cmd := exec.CommandContext(ctx, "journalctl", journalArgs...)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("journalctl pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start journalctl: %w", err)
	}
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		// journalctl prints "-- No entries --"/"-- Boot ... --" markers.
		if len(line) > 0 && line[0] != '-' {
			onLine(line)
		}
	}
	scanErr := sc.Err()
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if scanErr != nil {
		return fmt.Errorf("read journalctl: %w", scanErr)
	}
	if waitErr != nil {
		return fmt.Errorf("journalctl exited: %w", waitErr)
	}
	return errors.New("journalctl exited")
}

// Logf is a helper for callers: one line saying which source is used.
func Logf(prefix string, s Source) {
	log.Printf("%s reading authentication messages from %s", prefix, s)
}
