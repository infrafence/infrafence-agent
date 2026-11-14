package audit

import (
	"bufio"
	"context"
	"io"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/infrafence/infrafence-agent/internal/loginhistory"
	"github.com/infrafence/infrafence-agent/internal/watcher"
)

// Bounds on the logs one audit reads (variables for the tests).
var (
	maxAuthFileBytes int64 = 32 << 20 // the newest part of each auth log file
	maxJournalBytes  int64 = 64 << 20
	maxWebFileBytes  int64 = 8 << 20 // the newest part of each access log
	maxWebTotalBytes int64 = 64 << 20
	maxWebFiles            = 50
	maxLineBytes           = 64 << 10
)

// Window is how far back the logs are read.
const Window = reportWindowHours * time.Hour

// counter counts attacks per address.
type counter struct {
	total int
	byIP  map[string]int
}

func newCounter() *counter { return &counter{byIP: map[string]int{}} }

func (c *counter) add(ip string) {
	c.total++
	c.byIP[ip]++
}

// sshCounter counts failed SSH logins, the way an administrator would:
// each "Failed <method> for ..." line is one attempt; a connection that
// was refused before any password was tried ("Invalid user", "not allowed
// because", "ROOT LOGIN REFUSED") is one attempt when its sshd process
// logged no "Failed" line. The other lines the SSH watcher matches (PAM's
// copy of a failure, the disconnect that follows it) add the address but
// no attempt. Addresses only scanning the port (preauth) are not counted.
type sshCounter struct {
	*counter
	pending  map[string]string // sshd tag -> address of a refused user, until a Failed line
	failed   map[string]bool   // sshd tags with a Failed line
	ips      map[string]bool
	accepted map[string]bool // addresses with a successful login
}

func newSSHCounter() *sshCounter {
	return &sshCounter{counter: newCounter(), pending: map[string]string{}, failed: map[string]bool{}, ips: map[string]bool{}, accepted: map[string]bool{}}
}

var refusedMarkers = []string{"nvalid user ", "llegal user ", " not allowed because ", "ROOT LOGIN REFUSED"}

func (s *sshCounter) line(line string) {
	if l, ok := loginhistory.ParseLine(line, time.Now()); ok {
		// Someone who logs in is the server's people, not an attacker,
		// even after a mistyped password: never listed.
		s.accepted[l.IP] = true
		return
	}
	ip, reason := watcher.MatchSSH(line)
	if ip == "" || reason != "brute_force_ssh" {
		return
	}
	s.ips[ip] = true
	tag, msg, ok := loginhistory.SyslogMessage(line)
	if !ok {
		tag, msg = "", line
	}
	if strings.HasPrefix(msg, "Failed ") {
		s.add(ip)
		s.failed[tag] = true
		delete(s.pending, tag)
		return
	}
	for _, m := range refusedMarkers {
		if strings.Contains(msg, m) {
			if tag == "" {
				s.add(ip)
			} else if !s.failed[tag] {
				s.pending[tag] = ip
			}
			return
		}
	}
}

func (s *sshCounter) finish() {
	for _, ip := range s.pending {
		s.add(ip)
	}
	s.pending = map[string]string{}
	for ip := range s.accepted {
		s.total -= s.byIP[ip]
		delete(s.byIP, ip)
		delete(s.ips, ip)
	}
	// An address seen only in PAM or disconnect lines attacked too.
	for ip := range s.ips {
		if _, ok := s.byIP[ip]; !ok {
			s.byIP[ip] = 0
		}
	}
}

// scanLines feeds every line of r newer than since to fn, stopping at ctx.
func scanLines(ctx context.Context, r io.Reader, since, ref time.Time, timeOf func(string, time.Time) (time.Time, bool), fn func(string)) {
	br := bufio.NewReaderSize(r, 64<<10)
	for n := 0; ; n++ {
		if n%4096 == 0 && ctx.Err() != nil {
			return
		}
		line, err := readLine(br)
		if line != "" {
			if t, ok := timeOf(line, ref); ok && !t.Before(since) {
				fn(line)
			}
		}
		if err != nil {
			return
		}
	}
}

// readLine returns the next line; a line longer than maxLineBytes is
// skipped whole ("" returned), so one oversized request or user name can't
// end the reading of the rest of the log.
func readLine(br *bufio.Reader) (string, error) {
	var buf []byte
	tooLong := false
	for {
		chunk, isPrefix, err := br.ReadLine()
		if !tooLong {
			if len(buf)+len(chunk) > maxLineBytes {
				tooLong, buf = true, nil
			} else {
				buf = append(buf, chunk...)
			}
		}
		if err != nil || !isPrefix {
			if tooLong {
				return "", err
			}
			return string(buf), err
		}
	}
}

// openTail opens path read-only and positions it at most max bytes from
// its end, on a line boundary. A device, a FIFO or a directory is refused;
// it is opened without blocking first, so a FIFO with no writer can't hang
// the audit.
func openTail(path string, max int64) (io.ReadCloser, time.Time, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, time.Time{}, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, time.Time{}, os.ErrInvalid
	}
	if info.Size() > max {
		if _, err := f.Seek(info.Size()-max, io.SeekStart); err != nil {
			_ = f.Close()
			return nil, time.Time{}, err
		}
		br := bufio.NewReader(f)
		_, _ = br.ReadString('\n') // drop the partial first line
		return struct {
			io.Reader
			io.Closer
		}{io.LimitReader(br, max), f}, info.ModTime(), nil
	}
	return f, info.ModTime(), nil
}

// authFiles are the auth log files read when there is no journal: the
// current one and the previous rotation when it changed within the window.
func authFiles(path string, since time.Time) []string {
	files := []string{path}
	if info, err := os.Stat(path + ".1"); err == nil && info.ModTime().After(since) {
		files = append([]string{path + ".1"}, files...)
	}
	return files
}

// topIPs returns the most active addresses of both counters, at most
// maxTopIPs, largest first (then by address, for a stable report).
func topIPs(ssh, web *counter) []TopIP {
	var all []TopIP
	for ip, n := range ssh.byIP {
		if n > 0 {
			all = append(all, TopIP{IP: ip, Count: n, Kind: "ssh"})
		}
	}
	for ip, n := range web.byIP {
		all = append(all, TopIP{IP: ip, Count: n, Kind: "web"})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Count != all[j].Count {
			return all[i].Count > all[j].Count
		}
		if all[i].IP != all[j].IP {
			return all[i].IP < all[j].IP
		}
		return all[i].Kind < all[j].Kind
	})
	if len(all) > maxTopIPs*3 {
		all = all[:maxTopIPs*3] // the privacy filter may drop some; Collect trims to maxTopIPs
	}
	if all == nil {
		all = []TopIP{}
	}
	return all
}

// webTime adapts watcher.AccessLogTime to scanLines.
func webTime(line string, _ time.Time) (time.Time, bool) { return watcher.AccessLogTime(line) }
