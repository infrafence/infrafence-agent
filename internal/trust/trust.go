// Package trust places and removes the domain verification file of the
// "Monitored by InfraFence" badge: <docroot>/.well-known/infrafence-verification.txt,
// which the dashboard fetches over the internet to check that a domain is
// served by this server.
//
// The agent runs as root in other people's document roots, so every step
// works relative to a directory opened without following a symlink: the
// document root itself (refused if any part of its path is a symlink),
// .well-known (refused if it is a symlink) and the file (a symlink or a file
// without our header is never replaced). The file is written to a temporary
// file in .well-known and renamed over, with the owner of the document root
// and mode 0644; .well-known is created (0755, same owner) only when it is
// missing, and removed again only when this package created it and it is
// empty.
package trust

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	// Header is the first line of every file this package writes; a file
	// without it is someone else's and is never replaced or removed.
	Header = "# infrafence-verification"
	// WellKnown and FileName make up the path under the document root.
	WellKnown = ".well-known"
	FileName  = "infrafence-verification.txt"

	// maxFile bounds what is read of an existing file.
	maxFile = 64 << 10
)

// Failure reasons, reported to the dashboard as is.
const (
	ReasonNoDocRoot   = "no_document_root"
	ReasonFileExists  = "file_exists"
	ReasonUnsafePath  = "unsafe_path"
	ReasonInvalid     = "invalid_request"
	ReasonAmbiguous   = "ambiguous_document_root"
	ReasonWriteFailed = "write_failed"
)

// Error is a failure with the reason to report.
type Error struct {
	Reason string
	Err    error
}

func (e *Error) Error() string { return e.Reason + ": " + e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

func fail(reason string, format string, args ...any) error {
	return &Error{Reason: reason, Err: fmt.Errorf(format, args...)}
}

// ReasonOf returns the reason of err (ReasonWriteFailed for an error that
// carries none).
func ReasonOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ReasonWriteFailed
}

var (
	tokenRe  = regexp.MustCompile(`^ifv_[0-9a-f]{32}$`)
	domainRe = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

// ValidToken reports whether t has the dashboard's token format.
func ValidToken(t string) bool { return tokenRe.MatchString(t) }

// NormDomain lowercases d and drops a trailing dot; "" when d is not a
// plain host name (a wildcard, an address, a port, anything else).
func NormDomain(d string) string {
	d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
	if len(d) > 253 || !domainRe.MatchString(d) {
		return ""
	}
	return d
}

// Site is a site a hosting panel or the web server configuration declares:
// its exact names (server_name, ServerName/ServerAlias, the panel's domain)
// and its document root.
type Site struct {
	Names []string
	Root  string
}

// Match returns the document root serving domain: the one of the sites
// that declare exactly that name, else the one of those that declare its
// www. counterpart (example.com <-> www.example.com). Wildcards, regular
// expressions and default servers never match: only a name equal to the
// domain counts. When the sites declaring the name have different document
// roots, none is chosen (ReasonAmbiguous): another account's alias must not
// receive the token. Otherwise the reason is ReasonNoDocRoot.
func Match(domain string, sites []Site) (root, reason string) {
	domain = NormDomain(domain)
	if domain == "" {
		return "", ReasonInvalid
	}
	alt := "www." + domain
	if rest, ok := strings.CutPrefix(domain, "www."); ok {
		alt = rest
	}
	for _, want := range []string{domain, alt} {
		found := ""
		for _, s := range sites {
			if s.Root == "" || s.Root == found {
				continue
			}
			for _, n := range s.Names {
				if NormDomain(n) != want {
					continue
				}
				if found != "" {
					return "", ReasonAmbiguous
				}
				found = s.Root
				break
			}
		}
		if found != "" {
			return found, ""
		}
	}
	return "", ReasonNoDocRoot
}

// Path is the verification file of root.
func Path(root string) string { return filepath.Join(root, WellKnown, FileName) }

// Content is the file for tokens: the header, then one token per line,
// sorted.
func Content(tokens []string) []byte {
	t := append([]string(nil), tokens...)
	sort.Strings(t)
	var b bytes.Buffer
	b.WriteString(Header + "\n")
	for _, s := range t {
		b.WriteString(s + "\n")
	}
	return b.Bytes()
}

// dir is a directory held open, with its owner.
type dir struct {
	fd       int
	uid, gid int
}

func (d dir) close() { unix.Close(d.fd) }

// openRoot opens the document root one path element at a time from /, each
// relative to the one before and without following a symlink: a symlink
// anywhere in the path is refused, and nothing swapped in meanwhile can
// redirect the open.
func openRoot(root string) (dir, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
		return dir{}, fail(ReasonUnsafePath, "%q is not a clean absolute path", root)
	}
	const flags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	fd, err := unix.Open("/", flags, 0)
	if err != nil {
		return dir{}, fail(ReasonWriteFailed, "open /: %v", err)
	}
	for _, name := range strings.Split(root[1:], "/") {
		next, err := unix.Openat(fd, name, flags, 0)
		unix.Close(fd)
		if errors.Is(err, unix.ENOENT) {
			return dir{}, fail(ReasonNoDocRoot, "%s does not exist", root)
		}
		if err != nil {
			// ELOOP: a symlink; ENOTDIR: not a directory.
			return dir{}, fail(ReasonUnsafePath, "%s: %s is not a plain directory: %v", root, name, err)
		}
		fd = next
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return dir{}, fail(ReasonWriteFailed, "stat %s: %v", root, err)
	}
	return dir{fd: fd, uid: int(st.Uid), gid: int(st.Gid)}, nil
}

// openWellKnown opens .well-known in root, creating it when create is set
// and it is missing. A symlink or anything but a directory is refused.
func openWellKnown(root dir, create bool) (d dir, created bool, err error) {
	open := func() (int, error) {
		return unix.Openat(root.fd, WellKnown, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	}
	fd, err := open()
	if errors.Is(err, unix.ENOENT) && create {
		if err := unix.Mkdirat(root.fd, WellKnown, 0o755); err != nil {
			return dir{}, false, fail(ReasonWriteFailed, "create %s: %v", WellKnown, err)
		}
		created = true
		if fd, err = open(); err == nil {
			// Still the empty directory made just now (owned by us, no
			// entries), not one swapped in by the site's owner meanwhile:
			// only then is it given to the owner.
			var st unix.Stat_t
			if err = unix.Fstat(fd, &st); err == nil && (int(st.Uid) != os.Geteuid() || !emptyDir(fd)) {
				unix.Close(fd)
				return dir{}, false, fail(ReasonUnsafePath, "%s was replaced while it was created", WellKnown)
			}
		}
		if err == nil {
			if err = unix.Fchown(fd, root.uid, root.gid); err == nil {
				err = unix.Fchmod(fd, 0o755) // whatever the umask
			}
			if err != nil {
				unix.Close(fd)
			}
		}
		if err != nil {
			unix.Unlinkat(root.fd, WellKnown, unix.AT_REMOVEDIR)
			return dir{}, false, fail(ReasonWriteFailed, "set up %s: %v", WellKnown, err)
		}
	}
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return dir{}, false, err
		}
		// ELOOP: a symlink; ENOTDIR: a file.
		return dir{}, false, fail(ReasonUnsafePath, "%s is not a plain directory: %v", WellKnown, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return dir{}, false, fail(ReasonWriteFailed, "stat %s: %v", WellKnown, err)
	}
	return dir{fd: fd, uid: int(st.Uid), gid: int(st.Gid)}, created, nil
}

// emptyDir reports whether the directory open at fd has no entries (read
// through a duplicate, so fd's own offset is untouched). Not the link count:
// btrfs counts 1 for every directory.
func emptyDir(fd int) bool {
	dup, err := unix.Dup(fd)
	if err != nil {
		return false
	}
	f := os.NewFile(uintptr(dup), WellKnown)
	defer f.Close()
	names, err := f.Readdirnames(1)
	return len(names) == 0 && err == io.EOF
}

// readOurs reads the verification file in wk. exists is false when there
// is none; ours is false when there is one without our header (a symlink,
// a directory, anything else counts as not ours).
func readOurs(wk dir) (data []byte, exists, ours bool, err error) {
	// Only a regular file is opened (never a device or a FIFO).
	var lst unix.Stat_t
	if err := unix.Fstatat(wk.fd, FileName, &lst, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return nil, false, false, nil
	} else if err != nil {
		return nil, true, false, err
	}
	if lst.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, true, false, nil
	}
	fd, err := unix.Openat(wk.fd, FileName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, false, false, nil
	}
	if err != nil {
		return nil, true, false, nil // ELOOP: swapped for a symlink
	}
	f := os.NewFile(uintptr(fd), FileName)
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, true, false, err
	}
	if !st.Mode().IsRegular() {
		return nil, true, false, nil
	}
	data, err = io.ReadAll(io.LimitReader(f, maxFile+1))
	if err != nil {
		return nil, true, false, err
	}
	if len(data) > maxFile {
		return nil, true, false, nil
	}
	line, _, _ := bufio.NewReader(bytes.NewReader(data)).ReadLine()
	return data, true, string(line) == Header, nil
}

// Place writes the verification file of root with tokens (at least one).
// createdDir reports whether .well-known was created now. Nothing is
// written when the file already has exactly this content.
func Place(root string, tokens []string) (createdDir bool, err error) {
	if len(tokens) == 0 {
		return false, fail(ReasonInvalid, "no token")
	}
	for _, t := range tokens {
		if !ValidToken(t) {
			return false, fail(ReasonInvalid, "invalid token")
		}
	}
	r, err := openRoot(root)
	if err != nil {
		return false, err
	}
	defer r.close()
	wk, created, err := openWellKnown(r, true)
	if err != nil {
		return false, err
	}
	defer wk.close()
	// From here on, a failure leaves a .well-known created now in place
	// only if something else was put in it meanwhile.
	undoDir := func() {
		if created {
			unix.Unlinkat(r.fd, WellKnown, unix.AT_REMOVEDIR)
		}
	}

	want := Content(tokens)
	data, exists, ours, err := readOurs(wk)
	if err != nil {
		undoDir()
		return false, fail(ReasonWriteFailed, "read %s: %v", Path(root), err)
	}
	if exists && !ours {
		return false, fail(ReasonFileExists, "%s exists and was not written by InfraFence", Path(root))
	}
	if exists && bytes.Equal(data, want) {
		return created, nil
	}
	if err := writeAt(wk, r.uid, r.gid, want); err != nil {
		undoDir()
		return false, fail(ReasonWriteFailed, "write %s: %v", Path(root), err)
	}
	return created, nil
}

// writeAt replaces the verification file in wk atomically: a new file
// beside it, then a rename.
func writeAt(wk dir, uid, gid int, data []byte) error {
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := "." + FileName + "." + hex.EncodeToString(rnd[:])
	fd, err := unix.Openat(wk.fd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), tmp)
	_, err = f.Write(data)
	if err == nil {
		err = unix.Fchown(fd, uid, gid)
	}
	if err == nil {
		err = unix.Fchmod(fd, 0o644)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = unix.Renameat(wk.fd, tmp, wk.fd, FileName)
	}
	if err != nil {
		unix.Unlinkat(wk.fd, tmp, 0)
	}
	return err
}

// Remove deletes the verification file of root, if it is ours, and then
// .well-known if removeDir is set (this package created it) and it is
// empty. A root, .well-known or file that is gone is not an error; a
// foreign file is left alone (ReasonFileExists).
func Remove(root string, removeDir bool) error {
	r, err := openRoot(root)
	if err != nil {
		if ReasonOf(err) == ReasonNoDocRoot {
			return nil // the site is gone, and the file with it
		}
		return err
	}
	defer r.close()
	wk, _, err := openWellKnown(r, false)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	_, exists, ours, err := readOurs(wk)
	if err == nil && exists && !ours {
		err = fail(ReasonFileExists, "%s was replaced by a file InfraFence did not write; left in place", Path(root))
	}
	if err == nil && exists {
		if uerr := unix.Unlinkat(wk.fd, FileName, 0); uerr != nil && !errors.Is(uerr, unix.ENOENT) {
			err = fail(ReasonWriteFailed, "remove %s: %v", Path(root), uerr)
		}
	}
	wk.close()
	if err != nil {
		return err
	}
	if removeDir {
		// Fails (ENOTEMPTY) when anything else is in it: then it stays.
		unix.Unlinkat(r.fd, WellKnown, unix.AT_REMOVEDIR)
	}
	return nil
}
