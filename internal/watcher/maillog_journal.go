package watcher

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os/exec"
	"slices"
	"strings"
	"time"
)

// mailJournalMatches select the journal's mail messages: the mail syslog
// facility, which Postfix (every postfix/* daemon), Dovecot and Exim use
// when they log to syslog, plus Dovecot and Exim by name for the lines
// they write to stderr under systemd (no facility). journalctl ORs the
// matches of one field and joins the two groups with "+".
var mailJournalMatches = []string{
	"SYSLOG_FACILITY=2",
	"+", "SYSLOG_IDENTIFIER=dovecot", "SYSLOG_IDENTIFIER=exim", "SYSLOG_IDENTIFIER=exim4",
}

// mailJournalArgs follow new mail messages only (no history) in the
// syslog-like "short" format, "Mon DD HH:MM:SS host postfix/smtpd[pid]:
// message": the lines rsyslog writes to /var/log/mail.log, so the same
// patterns give the same events and details.
func mailJournalArgs() []string {
	return append([]string{"--follow", "--lines=0", "--output=short", "--no-pager", "--quiet"}, mailJournalMatches...)
}

// Restart delays when journalctl exits: from the first to the last,
// doubling; back to the first after a run of journalRunOK.
const (
	journalRetryMin = 5 * time.Second
	journalRetryMax = 5 * time.Minute
	journalRunOK    = time.Minute
)

// followJournal reads the journal's mail messages for ever, restarting
// journalctl with a growing delay when it exits (messages logged while it
// is down are not read: no history, as for the SSH journal reader).
// Messages from a program whose own log file is also watched are skipped:
// Exim and Dovecot can log to their file and to syslog at the same time,
// and a line must not be counted twice.
func (w *MailWatcher) followJournal() {
	var skip []string
	for _, p := range w.logPaths {
		switch {
		case p == "/var/log/dovecot.log":
			skip = append(skip, "dovecot")
		case slices.Contains(eximLogPaths, p):
			skip = append(skip, "exim", "exim4")
		}
	}
	onLine := func(line string) {
		if !slices.Contains(skip, journalIdentifier(line)) {
			w.processLine(line)
		}
	}
	delay := journalRetryMin
	for {
		start := time.Now()
		err := followMailJournal(context.Background(), onLine)
		if time.Since(start) >= journalRunOK {
			delay = journalRetryMin
		}
		log.Printf("[mailwatcher] journal: %v — retrying in %s", err, delay)
		time.Sleep(delay)
		delay = min(delay*2, journalRetryMax)
	}
}

// followMailJournal runs journalctl and passes every new mail message to
// onLine until journalctl exits or ctx is done.
func followMailJournal(ctx context.Context, onLine func(string)) error {
	cmd := exec.CommandContext(ctx, "journalctl", mailJournalArgs()...)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("journalctl pipe: %w", err)
	}
	var stderr tailBuffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start journalctl: %w", err)
	}
	readErr := readMailJournal(out, onLine, time.Now, time.Sleep)
	if readErr != nil {
		// Stop journalctl: it would block on a pipe nobody reads.
		_ = cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if readErr != nil {
		return fmt.Errorf("read journalctl: %w", readErr)
	}
	if waitErr != nil {
		return fmt.Errorf("journalctl exited: %w %s", waitErr, stderr.String())
	}
	return errors.New("journalctl exited")
}

// tailBuffer keeps the last 512 bytes written to it (journalctl's error).
type tailBuffer struct{ b []byte }

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if len(t.b) > 512 {
		t.b = t.b[len(t.b)-512:]
	}
	return len(p), nil
}

func (t *tailBuffer) String() string { return strings.TrimSpace(string(t.b)) }

// journalIdentifier returns the program name of a line in journalctl's
// short format, "Nov 03 10:15:40 host postfix/smtpd[812]: message"
// ("postfix/smtpd"); "" when the line has another shape.
func journalIdentifier(line string) string {
	f := strings.SplitN(line, " ", 6)
	if len(f) < 6 || !strings.HasSuffix(f[4], ":") {
		return ""
	}
	id := strings.TrimSuffix(f[4], ":")
	if i := strings.IndexByte(id, '['); i >= 0 {
		id = id[:i]
	}
	return id
}

// readMailJournal splits r into lines with the file reader's bounds: a
// line longer than maxMailLine is dropped, and at most maxMailRead bytes
// are taken every 500 ms (journalctl waits on the pipe meanwhile, nothing
// is lost). journalctl's own "-- ... --" markers are skipped. It returns
// nil at the end of r.
func readMailJournal(r io.Reader, onLine func(string), now func() time.Time, sleep func(time.Duration)) error {
	const tick = 500 * time.Millisecond
	br := bufio.NewReaderSize(r, maxMailLine+1)
	windowStart := now()
	read := 0
	long := false // in the rest of a line longer than maxMailLine
	for {
		chunk, err := br.ReadSlice('\n')
		read += len(chunk)
		switch {
		case errors.Is(err, bufio.ErrBufferFull):
			long = true
		case len(chunk) > 0 && chunk[len(chunk)-1] == '\n':
			if !long {
				line := bytes.TrimSuffix(chunk[:len(chunk)-1], []byte{'\r'})
				if len(line) > 0 && !bytes.HasPrefix(line, []byte("-- ")) {
					onLine(string(line))
				}
			}
			long = false
		}
		if err != nil && !errors.Is(err, bufio.ErrBufferFull) {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if read >= maxMailRead {
			if wait := tick - now().Sub(windowStart); wait > 0 {
				sleep(wait)
			}
			windowStart, read = now(), 0
		} else if now().Sub(windowStart) >= tick {
			windowStart, read = now(), 0
		}
	}
}

// journalHasMail reports whether the journal has a mail message since t.
func journalHasMail(t time.Time) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	args := append([]string{"--quiet", "--no-pager", "--lines=1", "--output=cat",
		"--since=" + t.Format("2006-01-02 15:04:05")}, mailJournalMatches...)
	out, err := exec.CommandContext(ctx, "journalctl", args...).Output()
	return err == nil && len(bytes.TrimSpace(out)) > 0
}
