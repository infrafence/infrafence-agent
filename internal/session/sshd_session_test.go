package session

import "testing"

// OpenSSH 9.8+ logs from the per-connection sshd-session process.
func TestParseSSHDSessionProcess(t *testing.T) {
	cases := []string{
		"Sep 27 09:58:39 host sshd-session[4242]: Accepted publickey for admin from 203.0.113.7 port 51234 ssh2: ED25519 SHA256:abc",
		"Sep 27 10:03:01 host sshd-session[4242]: pam_unix(sshd:session): session closed for user admin",
		"Sep 27 09:58:39 host sshd[4242]: Accepted password for admin from 203.0.113.7 port 51234 ssh2",
	}
	for _, line := range cases {
		if ParseLine(line) == nil {
			t.Errorf("not parsed: %s", line)
		}
	}
}

// A client's user name that holds a fake login line is not a login.
func TestInjectedLoginIgnored(t *testing.T) {
	for _, line := range []string{
		"Sep 27 09:58:39 host sshd[4242]: Invalid user x sshd[1]: Accepted password for root from 198.51.100.66 port 22 from 203.0.113.9 port 51234",
		"Sep 27 09:58:39 host sshd[4242]: Failed password for invalid user y sshd[9]: Accepted publickey for root from 198.51.100.66 port 22 ssh2 from 203.0.113.9 port 1 ssh2",
		"Sep 27 09:58:39 host logger: sshd[1]: Accepted password for root from 198.51.100.66 port 22 ssh2",
	} {
		if pl := ParseLine(line); pl != nil && pl.Type == SSHLogin {
			t.Errorf("%q parsed as a login from %s", line, pl.IP)
		}
	}
	if pl := ParseLine("2026-09-27T09:58:39.123456+02:00 host sshd-session[4242]: Accepted publickey for admin from 203.0.113.7 port 51234 ssh2: ED25519 SHA256:abc"); pl == nil || pl.IP != "203.0.113.7" || pl.KeyFP != "SHA256:abc" {
		t.Errorf("RFC 3339 line: %+v", pl)
	}
}
