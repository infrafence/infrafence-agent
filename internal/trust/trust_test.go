package trust

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const (
	tokA = "ifv_0123456789abcdef0123456789abcdef"
	tokB = "ifv_fedcba9876543210fedcba9876543210"
)

// docroot is a fresh document root; the temporary directory's own path is
// resolved first (on macOS it sits behind the /var symlink).
func docroot(t *testing.T) string {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "site")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

func owner(t *testing.T, p string) (uint32, uint32, os.FileMode) {
	t.Helper()
	st, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	sys := st.Sys().(*syscall.Stat_t)
	return sys.Uid, sys.Gid, st.Mode()
}

func reason(err error) string {
	if err == nil {
		return ""
	}
	return ReasonOf(err)
}

func TestMatch(t *testing.T) {
	sites := []Site{
		{Names: []string{"_"}, Root: "/var/www/default"},
		{Names: []string{"*.example.com", "~^(.+)\\.example\\.com$"}, Root: "/var/www/wild"},
		{Names: []string{"example.com"}}, // a redirect block: no root
		{Names: []string{"www.example.com"}, Root: "/var/www/example"},
		{Names: []string{"Shop.Example.org."}, Root: "/var/www/shop"},
		{Names: []string{"www.blog.example.net"}, Root: "/var/www/blog-www"},
		{Names: []string{"blog.example.net"}, Root: "/var/www/blog"},
	}
	for domain, want := range map[string]string{
		"example.com":          "/var/www/example", // via www., the bare block has no root
		"www.example.com":      "/var/www/example",
		"shop.example.org":     "/var/www/shop", // case and trailing dot
		"www.shop.example.org": "/var/www/shop",
		"blog.example.net":     "/var/www/blog", // exact beats www.
		"www.blog.example.net": "/var/www/blog-www",
		"other.example.com":    "", // only a wildcard declares it
		"a.example.com":        "",
		"_":                    "",
		"*.example.com":        "",
		"localhost":            "",
	} {
		got, why := Match(domain, sites)
		if got != want || (want == "") != (why != "") {
			t.Errorf("Match(%q) = %q, %q; want %q", domain, got, why, want)
		}
	}
	// The same root declared twice (panel and web server): one match.
	same := []Site{{Names: []string{"dup.example.com"}, Root: "/a"}, {Names: []string{"dup.example.com"}, Root: "/a"}}
	if got, why := Match("dup.example.com", same); got != "/a" || why != "" {
		t.Errorf("same root twice: %q %q", got, why)
	}
	// Two different roots declare the name: none is chosen.
	two := []Site{{Names: []string{"dup.example.com"}, Root: "/a"}, {Names: []string{"www.dup.example.com", "dup.example.com"}, Root: "/b"}}
	if got, why := Match("dup.example.com", two); got != "" || why != ReasonAmbiguous {
		t.Errorf("two roots: %q %q", got, why)
	}
	if got, why := Match("bad..name", nil); got != "" || why != ReasonInvalid {
		t.Errorf("invalid: %q %q", got, why)
	}
}

func TestPlaceWritesAtomicallyWithOwner(t *testing.T) {
	root := docroot(t)
	if os.Geteuid() == 0 {
		// As root the owner is really changed: give the site to someone else.
		if err := os.Chown(root, 4321, 4322); err != nil {
			t.Fatal(err)
		}
	}
	uid, gid, _ := owner(t, root)
	created, err := Place(root, []string{tokB, tokA})
	if err != nil || !created {
		t.Fatalf("Place: created=%v err=%v", created, err)
	}
	data, _ := os.ReadFile(Path(root))
	if want := Header + "\n" + tokA + "\n" + tokB + "\n"; string(data) != want {
		t.Fatalf("content %q, want %q", data, want)
	}
	fu, fg, fm := owner(t, Path(root))
	if fu != uid || fg != gid || fm.Perm() != 0o644 || !fm.IsRegular() {
		t.Errorf("file %d:%d %v, want %d:%d 0644", fu, fg, fm, uid, gid)
	}
	du, dg, dm := owner(t, filepath.Join(root, WellKnown))
	if du != uid || dg != gid || dm.Perm() != 0o755 || !dm.IsDir() {
		t.Errorf(".well-known %d:%d %v, want %d:%d 0755", du, dg, dm, uid, gid)
	}
	// Nothing but the file: the temporary file was renamed over it.
	entries, _ := os.ReadDir(filepath.Join(root, WellKnown))
	if len(entries) != 1 || entries[0].Name() != FileName {
		t.Errorf(".well-known holds %v", entries)
	}

	// The same tokens again: nothing is rewritten.
	before, _ := os.Stat(Path(root))
	if created, err := Place(root, []string{tokA, tokB}); err != nil || created {
		t.Fatalf("second Place: created=%v err=%v", created, err)
	}
	after, _ := os.Stat(Path(root))
	if !os.SameFile(before, after) {
		t.Error("identical content was rewritten")
	}
	// Different tokens: replaced by a new file (rename), not edited in place.
	if _, err := Place(root, []string{tokA}); err != nil {
		t.Fatal(err)
	}
	replaced, _ := os.Stat(Path(root))
	if os.SameFile(before, replaced) {
		t.Error("file edited in place instead of replaced")
	}
	if data, _ := os.ReadFile(Path(root)); string(data) != Header+"\n"+tokA+"\n" {
		t.Errorf("content %q", data)
	}
}

func TestPlaceKeepsExistingWellKnown(t *testing.T) {
	root := docroot(t)
	wk := filepath.Join(root, WellKnown)
	os.Mkdir(wk, 0o750)
	os.WriteFile(filepath.Join(wk, "security.txt"), []byte("Contact: x\n"), 0o644)
	created, err := Place(root, []string{tokA})
	if err != nil || created {
		t.Fatalf("created=%v err=%v", created, err)
	}
	if _, _, m := owner(t, wk); m.Perm() != 0o750 {
		t.Errorf("existing .well-known changed to %v", m)
	}
	// Removed: the file goes, the directory and its other content stay.
	if err := Remove(root, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(Path(root)); !os.IsNotExist(err) {
		t.Error("file not removed")
	}
	if _, err := os.Stat(filepath.Join(wk, "security.txt")); err != nil {
		t.Error("other file in .well-known lost")
	}
}

func TestRemoveCleansCreatedWellKnownOnlyWhenEmpty(t *testing.T) {
	root := docroot(t)
	if _, err := Place(root, []string{tokA}); err != nil {
		t.Fatal(err)
	}
	if err := Remove(root, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, WellKnown)); !os.IsNotExist(err) {
		t.Error("created and empty .well-known not removed")
	}

	// Created by the agent, but the site put something else in it since.
	if _, err := Place(root, []string{tokA}); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(root, WellKnown, "acme-challenge")
	os.Mkdir(other, 0o755)
	if err := Remove(root, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Error(".well-known removed with someone else's content")
	}
	if _, err := os.Lstat(Path(root)); !os.IsNotExist(err) {
		t.Error("file not removed")
	}

	// Already gone (file, .well-known, the whole site): not an error.
	if err := Remove(root, true); err != nil {
		t.Errorf("file gone: %v", err)
	}
	if err := Remove(filepath.Join(root, "nope"), true); err != nil {
		t.Errorf("site gone: %v", err)
	}
}

func TestForeignFileKept(t *testing.T) {
	root := docroot(t)
	wk := filepath.Join(root, WellKnown)
	os.Mkdir(wk, 0o755)
	foreign := "some-other-verification\n"
	os.WriteFile(Path(root), []byte(foreign), 0o644)
	if _, err := Place(root, []string{tokA}); reason(err) != ReasonFileExists {
		t.Fatalf("Place over a foreign file: %v", err)
	}
	if err := Remove(root, true); reason(err) != ReasonFileExists {
		t.Fatalf("Remove of a foreign file: %v", err)
	}
	if data, _ := os.ReadFile(Path(root)); string(data) != foreign {
		t.Errorf("foreign file changed: %q", data)
	}
	// A header further down does not make it ours.
	os.WriteFile(Path(root), []byte("x\n"+Header+"\n"), 0o644)
	if _, err := Place(root, []string{tokA}); reason(err) != ReasonFileExists {
		t.Errorf("header on line 2: %v", err)
	}
	// A FIFO is not opened (that would block) and not replaced.
	os.Remove(Path(root))
	if err := syscall.Mkfifo(Path(root), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Place(root, []string{tokA}); reason(err) != ReasonFileExists {
		t.Errorf("FIFO: %v", err)
	}
	if fi, err := os.Lstat(Path(root)); err != nil || fi.Mode()&os.ModeNamedPipe == 0 {
		t.Error("FIFO replaced")
	}
}

func TestSymlinksRefused(t *testing.T) {
	outside := docroot(t) // must stay untouched
	check := func(name string) {
		t.Helper()
		entries, _ := os.ReadDir(outside)
		if len(entries) != 0 {
			t.Errorf("%s: wrote outside the document root: %v", name, entries)
		}
	}

	// The document root itself is a symlink.
	base := filepath.Dir(docroot(t))
	link := filepath.Join(base, "link")
	os.Symlink(outside, link)
	if _, err := Place(link, []string{tokA}); reason(err) != ReasonUnsafePath {
		t.Errorf("symlinked docroot: %v", err)
	}
	check("symlinked docroot")

	// A directory above it is a symlink.
	if err := os.Mkdir(filepath.Join(outside, "pub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Place(filepath.Join(link, "pub"), []string{tokA}); reason(err) != ReasonUnsafePath {
		t.Errorf("symlinked parent: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(outside, "pub", WellKnown)); !os.IsNotExist(err) {
		t.Error("symlinked parent: .well-known created")
	}
	os.Remove(filepath.Join(outside, "pub"))

	// .well-known is a symlink.
	root := docroot(t)
	os.Symlink(outside, filepath.Join(root, WellKnown))
	if _, err := Place(root, []string{tokA}); reason(err) != ReasonUnsafePath {
		t.Errorf("symlinked .well-known: %v", err)
	}
	if err := Remove(root, true); reason(err) != ReasonUnsafePath {
		t.Errorf("Remove through a symlinked .well-known: %v", err)
	}
	check("symlinked .well-known")

	// The file is a symlink (to a file we wrote elsewhere): never replaced.
	root = docroot(t)
	os.Mkdir(filepath.Join(root, WellKnown), 0o755)
	target := filepath.Join(filepath.Dir(root), "target.txt")
	os.WriteFile(target, []byte(Header+"\n"), 0o600)
	os.Symlink(target, Path(root))
	if _, err := Place(root, []string{tokA}); reason(err) != ReasonFileExists {
		t.Errorf("symlinked file: %v", err)
	}
	if err := Remove(root, false); reason(err) != ReasonFileExists {
		t.Errorf("Remove of a symlinked file: %v", err)
	}
	if data, _ := os.ReadFile(target); string(data) != Header+"\n" {
		t.Errorf("symlink target changed: %q", data)
	}
	if fi, err := os.Lstat(Path(root)); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Error("symlink replaced")
	}
}

func TestPlaceRefusesBadInput(t *testing.T) {
	root := docroot(t)
	for _, toks := range [][]string{nil, {"ifv_short"}, {tokA, "ifv_0123456789ABCDEF0123456789ABCDEF"}, {tokA + "\nextra"}} {
		if _, err := Place(root, toks); reason(err) != ReasonInvalid {
			t.Errorf("Place(%q): %v", toks, err)
		}
	}
	for _, r := range []string{"relative/path", "/", root + "/../site", ""} {
		if _, err := Place(r, []string{tokA}); err == nil || !strings.Contains(err.Error(), "path") {
			t.Errorf("Place in %q: %v", r, err)
		}
	}
	if _, err := Place(filepath.Join(root, "missing"), []string{tokA}); reason(err) != ReasonNoDocRoot {
		t.Errorf("missing docroot: %v", err)
	}
	if entries, _ := os.ReadDir(root); len(entries) != 0 {
		t.Errorf("bad input wrote %v", entries)
	}
}
