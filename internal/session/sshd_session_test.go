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
