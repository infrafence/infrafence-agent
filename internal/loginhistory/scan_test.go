package loginhistory

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

func init() { throttlePause = 0 }

func TestParseLine(t *testing.T) {
	cases := []struct {
		line string
		ip   string
		user string
		when time.Time
	}{
		{"Nov  1 09:14:02 web1 sshd[1234]: Accepted publickey for root from 198.51.100.7 port 52113 ssh2: ED25519 SHA256:abc",
			"198.51.100.7", "root", time.Date(2026, 11, 1, 9, 14, 2, 0, time.UTC)},
		{"Oct 20 23:59:59 web1 sshd[99]: Accepted password for deploy from 203.0.113.9 port 40000 ssh2",
			"203.0.113.9", "deploy", time.Date(2026, 10, 20, 23, 59, 59, 0, time.UTC)},
		{"2026-10-28T07:01:02.123456+01:00 web1 sshd-session[2201]: Accepted keyboard-interactive/pam for admin from 2001:db8::5 port 22 ssh2",
			"2001:db8::5", "admin", time.Date(2026, 10, 28, 6, 1, 2, 123456000, time.UTC)},
		{"2026-10-30T10:00:00+0100 web1 sshd[5]: Accepted publickey for ops from ::ffff:192.0.2.44 port 1 ssh2",
			"192.0.2.44", "ops", time.Date(2026, 10, 30, 9, 0, 0, 0, time.UTC)},
		// December lines in a file read in January belong to last year.
		{"Dec 31 23:00:00 h sshd[1]: Accepted publickey for root from 198.51.100.8 port 2 ssh2",
			"198.51.100.8", "root", time.Date(2025, 12, 31, 23, 0, 0, 0, time.UTC)},
	}
	for i, c := range cases {
		ref := now
		if i == 4 {
			ref = time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
		}
		l, ok := ParseLine(c.line, ref)
		if !ok || l.IP != c.ip || l.User != c.user || !l.Time.Equal(c.when) {
			t.Errorf("%q: got %+v %v", c.line, l, ok)
		}
	}
	for _, line := range []string{
		"Nov  1 09:14:02 web1 sshd[1234]: Failed password for root from 198.51.100.7 port 52113 ssh2",
		"Nov  1 09:14:02 web1 sshd[1234]: Accepted publickey for root from 127.0.0.1 port 52113 ssh2",
		"Nov  1 09:14:02 web1 sudo: Accepted publickey for root from 198.51.100.7 port 1 ssh2",
		"garbage sshd[1]: Accepted publickey for root from 198.51.100.7 port 1",
		// A client's user name holding a fake login: not the message start.
		"Nov  1 09:14:02 web1 sshd[1234]: Invalid user x sshd[1]: Accepted password for root from 198.51.100.66 port 22 from 203.0.113.9 port 4242",
		"Nov  1 09:14:02 web1 sshd[1234]: Failed password for invalid user y sshd[9]: Accepted publickey for root from 198.51.100.66 port 22 ssh2 from 203.0.113.9 port 4242 ssh2",
		"2026-11-01T09:14:02+00:00 web1 sshd[1234]: Connection closed by authenticating user z sshd[2]: Accepted password for a from 198.51.100.66 port 1 203.0.113.9 port 1 [preauth]",
		// Another program's tag.
		"Nov  1 09:14:02 web1 logger: sshd[1]: Accepted publickey for root from 198.51.100.7 port 1 ssh2",
	} {
		if l, ok := ParseLine(line, now); ok {
			t.Errorf("%q: parsed %+v", line, l)
		}
	}
}

func writeFile(t *testing.T, path, data string, mod time.Time) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mod, mod); err != nil {
		t.Fatal(err)
	}
}

func writeGz(t *testing.T, path, data string, mod time.Time) {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	_, _ = zw.Write([]byte(data))
	_ = zw.Close()
	writeFile(t, path, b.String(), mod)
}

// utmpRecord builds a glibc utmp record.
func utmpRecord(typ int16, line, user, host string, ip net.IP, at time.Time) []byte {
	rec := make([]byte, utmpSize)
	binary.NativeEndian.PutUint16(rec[0:2], uint16(typ))
	copy(rec[utOffLine:utOffLine+utLineLen], line)
	copy(rec[utOffUser:utOffUser+utUserLen], user)
	copy(rec[utOffHost:utOffHost+utHostLen], host)
	binary.NativeEndian.PutUint32(rec[utOffSec:], uint32(at.Unix()))
	if v4 := ip.To4(); v4 != nil {
		copy(rec[utOffAddr:], v4)
	} else if ip != nil {
		copy(rec[utOffAddr:], ip.To16())
	}
	return rec
}

func TestScanFiles(t *testing.T) {
	dir := t.TempDir()
	auth := filepath.Join(dir, "auth.log")
	writeFile(t, auth, strings.Join([]string{
		"Nov  2 08:00:00 web1 sshd[10]: Failed password for root from 203.0.113.50 port 1 ssh2",
		"Nov  2 08:00:01 web1 sshd[11]: Accepted publickey for root from 198.51.100.7 port 52113 ssh2: ED25519 SHA256:x",
		"Nov  3 08:00:01 web1 sshd[12]: Accepted password for deploy from 198.51.100.7 port 52114 ssh2",
		"Nov  3 08:00:02 web1 sshd[13]: Invalid user " + strings.Repeat("x", 2<<20) + " from 203.0.113.50 port 1",
		"Nov  3 08:00:03 web1 sshd[14]: Accepted publickey for after from 198.51.100.8 port 1 ssh2",
		"",
	}, "\n"), now)
	// Rotated, gzipped, 12 days old.
	writeGz(t, filepath.Join(dir, "auth.log.2.gz"),
		"Oct 22 10:00:00 web1 sshd[9]: Accepted publickey for backup from 192.0.2.10 port 1 ssh2\n", now.AddDate(0, 0, -12))
	// Older than 30 days: the file is not even opened.
	writeGz(t, filepath.Join(dir, "auth.log.4.gz"),
		"Sep 20 10:00:00 web1 sshd[9]: Accepted publickey for old from 192.0.2.99 port 1 ssh2\n", now.AddDate(0, 0, -40))
	// A line older than 30 days in a recent file is left out.
	writeFile(t, filepath.Join(dir, "secure-20261101"),
		"2026-09-01T10:00:00+00:00 h sshd[1]: Accepted publickey for old2 from 192.0.2.98 port 1 ssh2\n"+
			"2026-10-31T10:00:00+00:00 h sshd[1]: Accepted publickey for rhel from 192.0.2.20 port 1 ssh2\n", now.AddDate(0, 0, -2))
	// Not a regular file.
	_ = os.Symlink(auth, filepath.Join(dir, "auth.log.link"))

	var wtmp []byte
	wtmp = append(wtmp, utmpRecord(7, "pts/0", "root", "198.51.100.30", net.ParseIP("198.51.100.30"), now.Add(-48*time.Hour))...)
	wtmp = append(wtmp, utmpRecord(8, "pts/0", "", "", nil, now.Add(-47*time.Hour))...)    // DEAD_PROCESS
	wtmp = append(wtmp, utmpRecord(7, "tty1", "root", "", nil, now.Add(-46*time.Hour))...) // console
	wtmp = append(wtmp, utmpRecord(7, "pts/1", "ops", "2001:db8::7", net.ParseIP("2001:db8::7"), now.Add(-time.Hour))...)
	wtmp = append(wtmp, utmpRecord(7, "pts/2", "dns", "198.51.100.31", nil, now.Add(-2*time.Hour))...) // address only in ut_host
	wtmp = append(wtmp, utmpRecord(7, "pts/3", "old", "198.51.100.32", net.ParseIP("198.51.100.32"), now.AddDate(0, 0, -31))...)
	wtmp = append(wtmp, utmpRecord(7, "ftp4242", "web", "198.51.100.33", net.ParseIP("198.51.100.33"), now.Add(-time.Hour))...) // an FTP login
	wtmp = append(wtmp, 1, 2, 3)                                                                                                // a partial last record
	writeFile(t, filepath.Join(dir, "wtmp"), string(wtmp), now)
	writeFile(t, filepath.Join(dir, "btmp"), string(utmpRecord(6, "ssh:notty", "x", "203.0.113.50", net.ParseIP("203.0.113.50"), now)), now)

	journalLines := "-- Journal begins --\n2026-10-25T12:00:00+0000 web1 sshd[77]: Accepted publickey for root from 203.0.113.77 port 1 ssh2\n"
	lastCalled := false
	o := Options{
		AuthGlobs: []string{filepath.Join(dir, "auth.log*"), filepath.Join(dir, "secure*")},
		WtmpGlobs: []string{filepath.Join(dir, "wtmp*"), filepath.Join(dir, "btmp*")},
		Journal: func(context.Context) (io.ReadCloser, func(), error) {
			return io.NopCloser(strings.NewReader(journalLines)), func() {}, nil
		},
		Last: func(context.Context) string { lastCalled = true; return "" },
	}
	r := Scan(context.Background(), now, o)
	got := map[string][]string{}
	for _, l := range r.Logins {
		got[l.IP] = append(got[l.IP], l.User+"@"+l.Source)
	}
	want := map[string]string{
		"198.51.100.7":  "root@auth_log,deploy@auth_log",
		"198.51.100.8":  "after@auth_log",
		"192.0.2.10":    "backup@auth_log",
		"192.0.2.20":    "rhel@auth_log",
		"203.0.113.77":  "root@journal",
		"198.51.100.30": "root@wtmp",
		"2001:db8::7":   "ops@wtmp",
		"198.51.100.31": "dns@wtmp",
	}
	if len(got) != len(want) {
		t.Errorf("got %v", got)
	}
	for ip, w := range want {
		if strings.Join(got[ip], ",") != w {
			t.Errorf("%s: got %v, want %s", ip, got[ip], w)
		}
	}
	if lastCalled {
		t.Error("last ran although wtmp was read")
	}
	if strings.Join(r.Sources, ",") != "auth_log,journal,wtmp" || r.Truncated {
		t.Errorf("sources %v truncated %v", r.Sources, r.Truncated)
	}
}

func TestScanBounds(t *testing.T) {
	dir := t.TempDir()
	oldFile, oldTotal, oldWtmp := maxFileBytes, maxTotalBytes, maxWtmpBytes
	t.Cleanup(func() { maxFileBytes, maxTotalBytes, maxWtmpBytes = oldFile, oldTotal, oldWtmp })
	maxFileBytes, maxTotalBytes, maxWtmpBytes = 4096, 6000, 2*utmpSize

	var b strings.Builder
	// The old part of a large file (cut off), then the newest lines.
	b.WriteString("Nov  1 01:00:00 h sshd[1]: Accepted publickey for cut from 192.0.2.1 port 1 ssh2\n")
	for b.Len() < 8000 {
		b.WriteString("Nov  1 02:00:00 h sshd[2]: Failed password for root from 203.0.113.5 port 1 ssh2\n")
	}
	b.WriteString("Nov  3 01:00:00 h sshd[3]: Accepted publickey for kept from 192.0.2.2 port 1 ssh2\n")
	writeFile(t, filepath.Join(dir, "auth.log"), b.String(), now)
	writeFile(t, filepath.Join(dir, "auth.log.1"),
		strings.Repeat("Nov  1 03:00:00 h sshd[4]: Failed password for x from 203.0.113.6 port 1 ssh2\n", 100)+
			"Nov  1 04:00:00 h sshd[5]: Accepted publickey for second from 192.0.2.3 port 1 ssh2\n", now.Add(-time.Hour))

	var wtmp []byte
	for i, ip := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"} {
		wtmp = append(wtmp, utmpRecord(7, "pts/0", "u", ip, net.ParseIP(ip), now.Add(time.Duration(i-5)*time.Hour))...)
	}
	writeFile(t, filepath.Join(dir, "wtmp"), string(wtmp), now)

	r := Scan(context.Background(), now, Options{
		AuthGlobs: []string{filepath.Join(dir, "auth.log*")},
		WtmpGlobs: []string{filepath.Join(dir, "wtmp")},
	})
	ips := map[string]bool{}
	for _, l := range r.Logins {
		ips[l.IP] = true
	}
	if !ips["192.0.2.2"] || ips["192.0.2.1"] || ips["198.51.100.1"] || !ips["198.51.100.2"] || !ips["198.51.100.3"] {
		t.Errorf("logins %v", ips)
	}
	if !r.Truncated || r.Bytes > maxTotalBytes+3*utmpSize {
		t.Errorf("truncated %v bytes %d", r.Truncated, r.Bytes)
	}
}

func TestScanLast(t *testing.T) {
	out := "root     pts/0        198.51.100.7     2026-11-02T10:00:00+01:00 - 2026-11-02T11:00:00+01:00  (01:00)\n" +
		"ops      pts/1        0.0.0.0          2026-11-02T10:00:00+01:00 - crash\n" +
		"reboot   system boot  6.8.0            2026-11-01T10:00:00+01:00 - still running\n" +
		"deploy   pts/2        203.0.113.9      Mon Nov  2 10:00 - 11:00  (01:00)\n" +
		"web      ftpd4242     203.0.113.10     2026-11-02T10:00:00+01:00 - 2026-11-02T10:01:00+01:00\n" +
		"\nwtmp begins Sun Nov  1 00:00:00 2026\n"
	r := Scan(context.Background(), now, Options{Last: func(context.Context) string { return out }})
	if len(r.Logins) != 2 || r.Logins[0].IP != "198.51.100.7" || !r.Logins[0].Time.Equal(time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)) ||
		r.Logins[1].IP != "203.0.113.9" || !r.Logins[1].Time.Equal(now) || r.Logins[1].Source != "last" {
		t.Errorf("logins %+v", r.Logins)
	}
}

func TestStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssh-logins.json")
	s := NewStore(path)
	s.now = func() time.Time { return now }
	added := s.Apply(Result{Logins: []Login{
		{IP: "198.51.100.7", User: "root", Time: now.Add(-48 * time.Hour)},
		{IP: "198.51.100.7", User: "deploy", Time: now.Add(-24 * time.Hour)},
		{IP: "192.0.2.10", User: "backup", Time: now.AddDate(0, 0, -12)},
	}, Sources: []string{"auth_log"}}, now)
	if strings.Join(added, ",") != "192.0.2.10,198.51.100.7" {
		t.Errorf("added %v", added)
	}
	if s.Note("198.51.100.7", "root", now.Add(-time.Hour)) {
		t.Error("known address reported as new")
	}
	if !s.Note("203.0.113.1", "ops", now) {
		t.Error("new live address not reported as new")
	}
	if last, ok := s.LastLogin("198.51.100.7"); !ok || !last.Equal(now.Add(-time.Hour)) {
		t.Errorf("last login %v %v", last, ok)
	}
	if _, ok := s.LastLogin("203.0.113.200"); ok {
		t.Error("unknown address has a login")
	}
	// A rescan that finds the live login too does not count it twice.
	s.Apply(Result{Logins: []Login{
		{IP: "198.51.100.7", User: "root", Time: now.Add(-48 * time.Hour)},
		{IP: "198.51.100.7", User: "deploy", Time: now.Add(-24 * time.Hour)},
		{IP: "198.51.100.7", User: "root", Time: now.Add(-time.Hour)},
	}}, now)
	e := s.Entries(0)
	if len(e) != 3 || e[0].IP != "203.0.113.1" || !e[0].Live || e[0].Imported || e[1].IP != "198.51.100.7" ||
		e[1].Count != 3 || !e[1].Imported || !e[1].Live || strings.Join(e[1].Users, ",") != "root,deploy" ||
		!e[1].First.Equal(now.Add(-48*time.Hour)) {
		t.Errorf("entries %+v", e)
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("saved file: %v %v", fi, err)
	}
	// Loaded 20 days later: the 12-day-old login is now past 30 days.
	l := NewStore(path)
	l.now = func() time.Time { return now.AddDate(0, 0, 20) }
	if err := l.Load(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(l.IPs(), ","); got != "198.51.100.7,203.0.113.1" {
		t.Errorf("after load: %s", got)
	}
	if !l.ScannedAt().Equal(now) {
		t.Errorf("scanned at %v", l.ScannedAt())
	}
	if len(l.Entries(1)) != 1 {
		t.Error("limit not applied")
	}
}

func TestStoreBound(t *testing.T) {
	s := NewStore("")
	s.now = func() time.Time { return now }
	for i := 0; i < MaxEntries+50; i++ {
		ip := net.IPv4(198, 18, byte(i/256), byte(i%256)).String()
		s.Note(ip, "u", now.Add(-time.Duration(MaxEntries+50-i)*time.Minute))
	}
	if n := len(s.IPs()); n != MaxEntries {
		t.Errorf("%d entries", n)
	}
	if _, ok := s.LastLogin("198.18.0.0"); ok {
		t.Error("the oldest entry was kept")
	}
}
