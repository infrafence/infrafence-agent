package watcher

import (
	"maps"
	"sync"
	"testing"
	"time"
)

func TestParseMailLine(t *testing.T) {
	cases := []struct {
		name   string
		line   string
		ip     string
		reason string
		want   map[string]string
	}{
		{
			name:   "postfix sasl login",
			line:   "Nov  2 10:14:03 mx1 postfix/smtpd[23145]: warning: unknown[203.0.113.5]: SASL LOGIN authentication failed: UGFzc3dvcmQ6",
			ip:     "203.0.113.5",
			reason: "mail_brute_force",
			want:   map[string]string{"mta": "postfix", "protocol": "smtp", "auth_method": "login"},
		},
		{
			name:   "postfix sasl with sasl_username, submission",
			line:   "Nov  2 10:14:03 mx1 postfix/submission/smtpd[23145]: warning: unknown[203.0.113.5]: SASL PLAIN authentication failed: authentication failure, sasl_username=info@example.com",
			ip:     "203.0.113.5",
			reason: "mail_brute_force",
			want:   map[string]string{"mta": "postfix", "protocol": "submission", "auth_method": "plain", "target_user": "info@example.com"},
		},
		{
			name:   "postfix smtps",
			line:   "Nov  2 10:14:03 mx1 postfix/smtps/smtpd[812]: warning: host.example.net[198.51.100.20]: SASL CRAM-MD5 authentication failed: authentication failure",
			ip:     "198.51.100.20",
			reason: "mail_brute_force",
			want:   map[string]string{"mta": "postfix", "protocol": "submission", "auth_method": "cram-md5"},
		},
		{
			name:   "postfix relay access denied",
			line:   "Nov  2 10:15:40 mx1 postfix/smtpd[23190]: NOQUEUE: reject: RCPT from unknown[203.0.113.9]: 554 5.7.1 <spam@Victim.example.org>: Relay access denied; from=<a@b.example> to=<spam@Victim.example.org> proto=ESMTP helo=<WIN-1>",
			ip:     "203.0.113.9",
			reason: "mail_relay_scan",
			want:   map[string]string{"mta": "postfix", "protocol": "smtp", "recipient": "spam@Victim.example.org", "recipient_domain": "victim.example.org"},
		},
		{
			name:   "postfix too many errors after auth",
			line:   "Nov  2 10:16:01 mx1 postfix/smtpd[23200]: too many errors after AUTH from unknown[203.0.113.7]",
			ip:     "203.0.113.7",
			reason: "mail_brute_force",
			want:   map[string]string{"mta": "postfix", "protocol": "smtp"},
		},
		{
			name:   "exim cpanel authenticator",
			line:   "2026-11-02 10:20:11 dovecot_login authenticator failed for (User) [203.0.113.11]:59618: 535 Incorrect authentication data (set_id=sales@example.com)",
			ip:     "203.0.113.11",
			reason: "mail_brute_force",
			want:   map[string]string{"mta": "exim", "protocol": "smtp", "auth_method": "login", "target_user": "sales@example.com"},
		},
		{
			name:   "exim debian authenticator with H=, no set_id",
			line:   "2026-11-02 10:20:12 plain_server authenticator failed for H=(localhost) [203.0.113.12]: 535 Incorrect authentication data",
			ip:     "203.0.113.12",
			reason: "mail_brute_force",
			want:   map[string]string{"mta": "exim", "protocol": "smtp", "auth_method": "plain"},
		},
		{
			name:   "exim relay not permitted",
			line:   "2026-11-02 10:21:00 H=(ylmf-pc) [203.0.113.13]:51234 F=<x@spammer.example> rejected RCPT <target@other.example.com>: relay not permitted",
			ip:     "203.0.113.13",
			reason: "mail_relay_scan",
			want:   map[string]string{"mta": "exim", "protocol": "smtp", "recipient": "target@other.example.com", "recipient_domain": "other.example.com"},
		},
		{
			name:   "dovecot imap disconnected",
			line:   "Nov  2 10:22:00 mx1 dovecot: imap-login: Disconnected (auth failed, 3 attempts in 12 secs): user=<info@example.com>, method=PLAIN, rip=203.0.113.20, lip=192.0.2.1, TLS, session=<abc>",
			ip:     "203.0.113.20",
			reason: "mail_brute_force",
			want:   map[string]string{"mta": "dovecot", "protocol": "imap", "auth_method": "plain", "target_user": "info@example.com"},
		},
		{
			name:   "dovecot 2.3 login aborted",
			line:   "Nov  2 10:22:01 mx1 dovecot: pop3-login: Login aborted: Connection closed (auth failed, 1 attempts in 4 secs) (auth_failed): user=<bob>, method=LOGIN, rip=203.0.113.21, lip=192.0.2.1, session=<xyz>",
			ip:     "203.0.113.21",
			reason: "mail_brute_force",
			want:   map[string]string{"mta": "dovecot", "protocol": "pop3", "auth_method": "login", "target_user": "bob"},
		},
		{
			name:   "dovecot submission disconnected connection closed, empty user",
			line:   "Nov  2 10:22:02 mx1 dovecot: submission-login: Disconnected: Connection closed (auth failed, 1 attempts in 2 secs): user=<>, method=PLAIN, rip=203.0.113.22, lip=192.0.2.1",
			ip:     "203.0.113.22",
			reason: "mail_brute_force",
			want:   map[string]string{"mta": "dovecot", "protocol": "submission", "auth_method": "plain"},
		},
		{
			name:   "dovecot managesieve",
			line:   "Nov  2 10:22:03 mx1 dovecot: managesieve-login: Disconnected (auth failed, 1 attempts in 3 secs): user=<admin@example.com>, method=PLAIN, rip=203.0.113.23, lip=192.0.2.1",
			ip:     "203.0.113.23",
			reason: "mail_brute_force",
			want:   map[string]string{"mta": "dovecot", "protocol": "managesieve", "auth_method": "plain", "target_user": "admin@example.com"},
		},
		{
			name:   "dovecot auth unknown user with session",
			line:   "Nov  2 10:22:04 mx1 dovecot: auth: passwd-file(test@example.com,203.0.113.24,<Xy1>): unknown user",
			ip:     "203.0.113.24",
			reason: "mail_brute_force",
			want:   map[string]string{"mta": "dovecot", "target_user": "test@example.com"},
		},
		{
			name:   "dovecot auth password mismatch",
			line:   "Nov  2 10:22:05 mx1 dovecot: auth: passwd(root,203.0.113.25): Password mismatch",
			ip:     "203.0.113.25",
			reason: "mail_brute_force",
			want:   map[string]string{"mta": "dovecot", "target_user": "root"},
		},
		{
			name:   "roundcube imap error",
			line:   "[02-Nov-2026 10:30:00 +0000]: <a1b2c3> IMAP Error: Login failed for admin@example.com against localhost from 203.0.113.30. AUTHENTICATE PLAIN: Authentication failed. in /usr/share/roundcube/program/lib/Roundcube/rcube_imap.php on line 211 (POST /?_task=login&_action=login)",
			ip:     "203.0.113.30",
			reason: "mail_brute_force",
			want:   map[string]string{"mta": "roundcube", "protocol": "roundcube", "auth_method": "plain", "target_user": "admin@example.com"},
		},
		{
			name:   "roundcube failed login",
			line:   "Nov  2 10:30:01 mx1 roundcube: <a1b2c3> Failed login for webmaster@example.com from 203.0.113.31 in session a1b2c3 (error: 0)",
			ip:     "203.0.113.31",
			reason: "mail_brute_force",
			want:   map[string]string{"mta": "roundcube", "protocol": "roundcube", "target_user": "webmaster@example.com"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ip, reason, d := parseMailLine(c.line)
			if ip != c.ip || reason != c.reason {
				t.Fatalf("got %q %q, want %q %q", ip, reason, c.ip, c.reason)
			}
			if !maps.Equal(d, c.want) {
				t.Errorf("details %v, want %v", d, c.want)
			}
		})
	}
}

func TestParseMailLineNoMatch(t *testing.T) {
	for _, line := range []string{
		"Nov  2 10:14:03 mx1 postfix/smtpd[23145]: connect from unknown[203.0.113.5]",
		"Nov  2 10:22:00 mx1 dovecot: imap-login: Login: user=<info@example.com>, method=PLAIN, rip=203.0.113.20, lip=192.0.2.1",
		"2026-11-02 10:20:11 1tAbCd-000123-Ef <= info@example.com H=(User) [203.0.113.11]:59618 P=esmtpsa A=dovecot_login:info@example.com",
		// Another address in text the client controls: not counted.
		"2026-11-02 10:20:11 dovecot_login authenticator failed for (x [8.8.8.8]:1: 535 y) [203.0.113.9]:5555: 535 Incorrect authentication data (set_id=a@b.c)",
		"2026-11-02 10:21:00 H=(a [8.8.8.8]) [203.0.113.13]:51234 F=<x@spammer.example> rejected RCPT <t@o.example>: relay not permitted",
		"[02-Nov-2026 10:30:00 +0000]: <a1> IMAP Error: Login failed for x against y from 8.8.8.8 against server from 203.0.113.9. AUTHENTICATE PLAIN: failed",
		"Nov  2 10:30:01 mx1 roundcube: <a1> Failed login for a from 8.8.8.8 in session from 203.0.113.9 in session abc",
	} {
		if ip, _, _ := parseMailLine(line); ip != "" {
			t.Errorf("%q matched (%s)", line, ip)
		}
	}
}

func TestMailRecordAttemptDetails(t *testing.T) {
	var mu sync.Mutex
	var events []map[string]string
	done := make(chan struct{}, 10)
	w := &MailWatcher{
		threshold: 3,
		window:    5 * time.Minute,
		attempts:  map[string][]time.Time{},
		banned:    map[string]bool{},
		whitelist: map[string]bool{},
		onBan:     func(ip, reason string, count int) {},
		onEvent: func(ip, eventType, severity string, d map[string]string) {
			mu.Lock()
			events = append(events, d)
			mu.Unlock()
			done <- struct{}{}
		},
	}
	line := "Nov  2 10:22:00 mx1 dovecot: imap-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<info@example.com>, method=PLAIN, rip=203.0.113.20, lip=192.0.2.1"
	w.processLine(line)
	w.processLine(line)
	for range 2 {
		<-done
	}
	mu.Lock()
	defer mu.Unlock()
	seen := map[string]bool{}
	for _, d := range events {
		seen[d["attempts"]] = true
		if d["target_user"] != "info@example.com" || d["protocol"] != "imap" {
			t.Errorf("details %v", d)
		}
	}
	if !seen["1"] || !seen["2"] {
		t.Errorf("attempts %v, want 1 and 2", seen)
	}
}

func TestEximAuthMethod(t *testing.T) {
	for name, want := range map[string]string{
		"dovecot_login": "login", "dovecot_plain": "plain", "plain_server": "plain",
		"login_server": "login", "cram_md5_server": "cram-md5", "myauth": "",
	} {
		if got := eximAuthMethod(name); got != want {
			t.Errorf("%s: %q, want %q", name, got, want)
		}
	}
}
