package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/infrafence/infrafence-agent/internal/api"
	"github.com/infrafence/infrafence-agent/internal/malware"
	"github.com/infrafence/infrafence-agent/internal/panel"
	"github.com/infrafence/infrafence-agent/internal/preflight"
)

// A malware scan asked from the panel covers one site's document root, and
// only when that directory belongs to the site's account: after resolving
// symlinks it must sit inside the account's home (or, on Plesk, inside
// /var/www/vhosts/<domain>) and be owned by the account's uid. A document
// root its owner pointed elsewhere (a symlink to /, /etc, another account)
// is refused. The directory is opened once, without following a symlink,
// and checked again by device and inode right before the walk, which
// follows no symlink either (malware.WebRoot.Strict).

// panelLookupUser returns an account's home and uid; replaced in tests.
var panelLookupUser = func(name string) (home string, uid int, err error) {
	u, err := user.Lookup(name)
	if err != nil {
		return "", 0, err
	}
	id, err := strconv.Atoi(u.Uid)
	if err != nil {
		return "", 0, err
	}
	return u.HomeDir, id, nil
}

// scanRoot is a document root checked for a panel scan and held open.
type scanRoot struct {
	path, domain string
	f            *os.File
	dev, ino     uint64
}

// openScanRoot checks that s's document root may be scanned for its
// account and opens it.
func openScanRoot(s preflight.Site) (*scanRoot, error) {
	if s.Account == "" || s.DocumentRoot == "" {
		return nil, errors.New("the site has no account or document root")
	}
	target, err := filepath.EvalSymlinks(s.DocumentRoot)
	if err != nil {
		return nil, err
	}
	if reason := systemTree(target); reason != "" {
		return nil, fmt.Errorf("%s is %s", target, reason)
	}
	home, uid, err := panelLookupUser(s.Account)
	if err != nil {
		return nil, fmt.Errorf("account %s: %w", s.Account, err)
	}
	var trees []string
	if p, err := filepath.EvalSymlinks(home); err == nil && home != "" {
		trees = append(trees, p)
	}
	if panelInfo.panelID == "plesk" {
		if p, err := filepath.EvalSymlinks("/var/www/vhosts/" + s.Domain); err == nil {
			trees = append(trees, p)
		}
	}
	inside := false
	for _, tree := range trees {
		if tree != "/" && target != tree && within(target, tree) {
			inside = true
		}
	}
	if !inside {
		return nil, fmt.Errorf("%s is outside the home of %s", target, s.Account)
	}
	f, err := os.OpenFile(target, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	sys, ok := st.Sys().(*syscall.Stat_t)
	if err != nil || !ok {
		f.Close()
		return nil, errors.New("cannot read the owner")
	}
	if int(sys.Uid) != uid {
		f.Close()
		return nil, fmt.Errorf("%s is owned by uid %d, not by %s", target, sys.Uid, s.Account)
	}
	return &scanRoot{path: target, domain: s.Domain, f: f, dev: uint64(sys.Dev), ino: sys.Ino}, nil
}

// verify: the path still leads, without a symlink, to the directory that
// was checked and opened (nothing was swapped since).
func (r *scanRoot) verify() error {
	if p, err := filepath.EvalSymlinks(r.path); err != nil || p != r.path {
		return fmt.Errorf("%s changed since it was checked", r.path)
	}
	st, err := os.Lstat(r.path)
	if err != nil {
		return err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.IsDir() || uint64(sys.Dev) != r.dev || sys.Ino != r.ino {
		return fmt.Errorf("%s is no longer the directory that was checked", r.path)
	}
	return nil
}

func (r *scanRoot) Close() { r.f.Close() }

// scannable reports whether a panel scan of s would be accepted.
func scannable(s preflight.Site) bool {
	r, err := openScanRoot(s)
	if err != nil {
		return false
	}
	r.Close()
	return true
}

// panelScan queues a malware scan of one site's document root.
func panelScan(path, actor string) panel.Response {
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return panel.Fail(panel.ErrUnknownPath, "%s does not exist", path)
	}
	var site *preflight.Site
	for _, s := range cachedSites(panelInfo.panelID) {
		if s.DocumentRoot == "" {
			continue
		}
		if p, err := filepath.EvalSymlinks(s.DocumentRoot); err == nil && p == target {
			site = &s
			break
		}
	}
	if site == nil {
		return panel.Fail(panel.ErrUnknownPath, "%s is not the document root of a site on this server", path)
	}
	root, err := openScanRoot(*site)
	if err != nil {
		return panel.Fail(panel.ErrNotScannable, "%v", err)
	}
	if !panelClaimScan() {
		root.Close()
		return panel.Fail(panel.ErrScanRunning, "a malware scan is already running")
	}
	log.Printf("[panel] malware scan of %s (%s) by %s", root.path, site.Account, actor)
	go func() {
		defer root.Close()
		panelStartScan(malware.StrictWebRootAt(root.path, root.domain), root.verify)
	}()
	reported := panelReport([]api.EventRequest{panelEventFor("panel_scan", actor, map[string]string{
		"path": root.path, "domain": root.domain, "account": site.Account,
	})})
	return panel.OK(map[string]any{"path": root.path, "queued": true, "reported": reported})
}
