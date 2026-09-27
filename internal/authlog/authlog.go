// Package authlog decides where the agent reads SSH and other
// authentication messages from, and follows the systemd journal when there
// is no log file.
//
// Distributions that install rsyslog write these messages to
// /var/log/auth.log (Debian/Ubuntu) or /var/log/secure (RHEL family). Recent
// Debian, Fedora and Amazon Linux don't install rsyslog: the messages are
// only in the journal. Reading the journal's auth and authpriv facilities
// gives exactly the lines rsyslog would have written, in the same
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

// Detect picks the source: AUTH_LOG_PATH if that file exists, otherwise
// the distribution's auth log file, otherwise the journal. A configured file
// that doesn't exist falls back too (installers before v1.0.25 always set
// AUTH_LOG_PATH, even where the file never existed).
func Detect() Source {
	if p := os.Getenv("AUTH_LOG_PATH"); p != "" {
		if exists(p) {
			return Source{Path: p}
		}
		if !journalAvailable() {
			// Nothing better: wait for the configured file to appear.
			return Source{Path: p}
		}
	}
	for _, p := range logFiles {
		if exists(p) {
			return Source{Path: p}
		}
	}
	if journalAvailable() {
		return Source{Journal: true}
	}
	return Source{Path: logFiles[0]}
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
