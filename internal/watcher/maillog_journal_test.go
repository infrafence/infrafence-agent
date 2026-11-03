package watcher

import (
	"io/fs"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestMailJournalArgs(t *testing.T) {
	args := mailJournalArgs()
	for _, want := range []string{"--follow", "--lines=0", "--output=short", "SYSLOG_FACILITY=2", "SYSLOG_IDENTIFIER=dovecot", "SYSLOG_IDENTIFIER=exim4"} {
		if !slices.Contains(args, want) {
			t.Errorf("args %v: missing %s", args, want)
		}
	}
	// The facility and the identifiers are alternatives: "+" between them.
	if i, j := slices.Index(args, "SYSLOG_FACILITY=2"), slices.Index(args, "+"); j != i+1 {
		t.Errorf("args %v: want \"+\" right after the facility", args)
	}
}

// journalctl --output=short prints what rsyslog writes to /var/log/mail.log;
// each journal line must give exactly the event and details of the file line.
func TestReadMailJournalSameEventsAsFile(t *testing.T) {
	cases := []struct {
		journal, file string
		ip, reason    string
		want          map[string]string
	}{
		{
			journal: "Nov 03 10:15:40 mx1 postfix/smtpd[23190]: NOQUEUE: reject: RCPT from unknown[203.0.113.9]: 554 5.7.1 <spam@Victim.example.org>: Relay access denied; from=<a@b.example> to=<spam@Victim.example.org> proto=ESMTP helo=<WIN-1>",
			file:    "Nov  3 10:15:40 mx1 postfix/smtpd[23190]: NOQUEUE: reject: RCPT from unknown[203.0.113.9]: 554 5.7.1 <spam@Victim.example.org>: Relay access denied; from=<a@b.example> to=<spam@Victim.example.org> proto=ESMTP helo=<WIN-1>",
			ip:      "203.0.113.9", reason: "mail_relay_scan",
			want: map[string]string{"mta": "postfix", "protocol": "smtp", "recipient": "spam@Victim.example.org", "recipient_domain": "victim.example.org"},
		},
		{
			journal: "Nov 03 10:14:03 mx1 postfix/submission/smtpd[812]: warning: unknown[203.0.113.5]: SASL PLAIN authentication failed: authentication failure, sasl_username=info@example.com",
			file:    "Nov  3 10:14:03 mx1 postfix/submission/smtpd[812]: warning: unknown[203.0.113.5]: SASL PLAIN authentication failed: authentication failure, sasl_username=info@example.com",
			ip:      "203.0.113.5", reason: "mail_brute_force",
			want: map[string]string{"mta": "postfix", "protocol": "submission", "auth_method": "plain", "target_user": "info@example.com"},
		},
		{
			// The journal shows Dovecot's pid; rsyslog's file does not.
			journal: "Nov 03 10:22:00 mx1 dovecot[611]: imap-login: Disconnected (auth failed, 3 attempts in 12 secs): user=<info@example.com>, method=PLAIN, rip=203.0.113.20, lip=192.0.2.1, TLS, session=<abc>",
			file:    "Nov  3 10:22:00 mx1 dovecot: imap-login: Disconnected (auth failed, 3 attempts in 12 secs): user=<info@example.com>, method=PLAIN, rip=203.0.113.20, lip=192.0.2.1, TLS, session=<abc>",
			ip:      "203.0.113.20", reason: "mail_brute_force",
			want: map[string]string{"mta": "dovecot", "protocol": "imap", "auth_method": "plain", "target_user": "info@example.com"},
		},
		{
			journal: "Nov 03 10:23:00 mx1 dovecot[611]: auth: passwd-file(admin,203.0.113.21,<x1>): unknown user",
			file:    "Nov  3 10:23:00 mx1 dovecot: auth: passwd-file(admin,203.0.113.21,<x1>): unknown user",
			ip:      "203.0.113.21", reason: "mail_brute_force",
			want: map[string]string{"mta": "dovecot", "target_user": "admin"},
		},
		{
			// Exim logging to syslog: no timestamp of its own in the message.
			journal: "Nov 03 10:20:11 mx1 exim[915]: dovecot_login authenticator failed for (User) [203.0.113.11]:59618: 535 Incorrect authentication data (set_id=sales@example.com)",
			file:    "2026-11-03 10:20:11 dovecot_login authenticator failed for (User) [203.0.113.11]:59618: 535 Incorrect authentication data (set_id=sales@example.com)",
			ip:      "203.0.113.11", reason: "mail_brute_force",
			want: map[string]string{"mta": "exim", "protocol": "smtp", "auth_method": "login", "target_user": "sales@example.com"},
		},
	}

	var out strings.Builder
	out.WriteString("-- Boot 1f2e3d4c5b6a --\n")
	for _, c := range cases {
		out.WriteString(c.journal + "\n")
	}
	var lines []string
	if err := readMailJournal(strings.NewReader(out.String()), func(l string) { lines = append(lines, l) }, time.Now, func(time.Duration) {}); err != nil {
		t.Fatal(err)
	}
	if len(lines) != len(cases) {
		t.Fatalf("got %d lines, want %d: %q", len(lines), len(cases), lines)
	}
	for i, c := range cases {
		if lines[i] != c.journal {
			t.Errorf("line %d = %q", i, lines[i])
		}
		ip, reason, d := parseMailLine(lines[i])
		if ip != c.ip || reason != c.reason || !maps.Equal(d, c.want) {
			t.Errorf("journal %q: got %s %s %v, want %s %s %v", c.journal, ip, reason, d, c.ip, c.reason, c.want)
		}
		fip, freason, fd := parseMailLine(c.file)
		if fip != ip || freason != reason || !maps.Equal(fd, d) {
			t.Errorf("file line %q: got %s %s %v, journal gave %s %s %v", c.file, fip, freason, fd, ip, reason, d)
		}
	}
}

func TestReadMailJournalLongLine(t *testing.T) {
	ok := "Nov 03 10:16:01 mx1 postfix/smtpd[23200]: too many errors after AUTH from unknown[203.0.113.7]"
	long := ok + " " + strings.Repeat("x", maxMailLine)
	exact := ok + strings.Repeat(" ", maxMailLine-len(ok))
	input := long + "\n" + ok + "\r\n" + exact + "\n" + "no newline at the end"
	var lines []string
	if err := readMailJournal(strings.NewReader(input), func(l string) { lines = append(lines, l) }, time.Now, func(time.Duration) {}); err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 || lines[0] != ok || lines[1] != exact {
		t.Errorf("lines %q: want the line after the long one and the %d-byte one", lines, maxMailLine)
	}
}

func TestReadMailJournalRate(t *testing.T) {
	line := "Nov 03 10:16:01 mx1 postfix/smtpd[23200]: connect from unknown[203.0.113.7]" + strings.Repeat(" ", 100) + "\n"
	n := 3*maxMailRead/len(line) + 1
	now := time.Unix(1_700_000_000, 0)
	var slept []time.Duration
	count := 0
	err := readMailJournal(strings.NewReader(strings.Repeat(line, n)), func(string) { count++ },
		func() time.Time { return now },
		func(d time.Duration) { slept = append(slept, d); now = now.Add(d) })
	if err != nil {
		t.Fatal(err)
	}
	if count != n {
		t.Errorf("%d lines, want %d", count, n)
	}
	// 3 MiB at 1 MiB per half second: three waits, none longer than the tick.
	if len(slept) != 3 {
		t.Errorf("slept %v, want 3 waits", slept)
	}
	for _, d := range slept {
		if d <= 0 || d > 500*time.Millisecond {
			t.Errorf("wait %s", d)
		}
	}
}

type fakeFileInfo struct{ mod time.Time }

func (f fakeFileInfo) Name() string       { return "" }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() fs.FileMode  { return 0o644 }
func (f fakeFileInfo) ModTime() time.Time { return f.mod }
func (f fakeFileInfo) IsDir() bool        { return false }
func (f fakeFileInfo) Sys() any           { return nil }

func TestDetectMailSources(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	fresh, stale := now.Add(-time.Hour), now.Add(-72*time.Hour)
	cases := []struct {
		name        string
		files       map[string]time.Time
		journal     bool // journald running
		journalMail bool // mail messages in the journal in the last day
		useJournal  bool
		want        mailSources
	}{
		{"no rsyslog: journal", nil, true, true, true, mailSources{journal: true}},
		{"no rsyslog, no journal", nil, false, false, true, mailSources{}},
		{"HasMailService never counts the journal", nil, true, true, false, mailSources{}},
		{"mail.log written: file only", map[string]time.Time{"/var/log/mail.log": fresh}, true, true, true,
			mailSources{paths: []string{"/var/log/mail.log"}}},
		{"maillog stale, journal has mail: journal only", map[string]time.Time{"/var/log/maillog": stale}, true, true, true,
			mailSources{journal: true}},
		{"mail.log stale, journal quiet too: file", map[string]time.Time{"/var/log/mail.log": stale}, true, false, true,
			mailSources{paths: []string{"/var/log/mail.log"}}},
		{"journal with dovecot.log and exim", map[string]time.Time{"/var/log/dovecot.log": fresh, "/var/log/exim4/mainlog": fresh}, true, true, true,
			mailSources{journal: true, paths: []string{"/var/log/dovecot.log", "/var/log/exim4/mainlog"}}},
		{"mail.log and dovecot.log: mail.log", map[string]time.Time{"/var/log/mail.log": fresh, "/var/log/dovecot.log": fresh}, true, true, true,
			mailSources{paths: []string{"/var/log/mail.log"}}},
		{"no journal: files as before", map[string]time.Time{"/var/log/dovecot.log": fresh, "/var/log/exim_mainlog": fresh}, false, false, true,
			mailSources{paths: []string{"/var/log/dovecot.log", "/var/log/exim_mainlog"}}},
	}
	defer func(s func(string) (os.FileInfo, error), n func() time.Time, a func() bool, h func(time.Time) bool) {
		mailStat, mailNow, mailJournalAvailable, mailJournalHasSince = s, n, a, h
	}(mailStat, mailNow, mailJournalAvailable, mailJournalHasSince)
	t.Setenv("MAIL_LOG_PATH", "")
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mailStat = func(p string) (os.FileInfo, error) {
				if m, ok := c.files[p]; ok {
					return fakeFileInfo{m}, nil
				}
				return nil, os.ErrNotExist
			}
			mailNow = func() time.Time { return now }
			mailJournalAvailable = func() bool { return c.journal }
			mailJournalHasSince = func(since time.Time) bool {
				if !since.Equal(now.Add(-mailLogStale)) {
					t.Errorf("since %s", since)
				}
				return c.journalMail
			}
			got := detectMailSources(c.useJournal)
			if got.journal != c.want.journal || !slices.Equal(got.paths, c.want.paths) {
				t.Errorf("got %+v, want %+v", got, c.want)
			}
		})
	}
	t.Run("MAIL_LOG_PATH", func(t *testing.T) {
		t.Setenv("MAIL_LOG_PATH", "/srv/mail/custom.log")
		mailJournalAvailable = func() bool { return true }
		got := detectMailSources(true)
		if got.journal || !slices.Equal(got.paths, []string{"/srv/mail/custom.log"}) {
			t.Errorf("got %+v", got)
		}
	})
}
