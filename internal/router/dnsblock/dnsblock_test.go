package dnsblock

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidDomain(t *testing.T) {
	for _, d := range []string{"evil.example.com", "a-b.io", "x_y.example.net", "xn--bcher-kva.example"} {
		if !ValidDomain(d) {
			t.Errorf("%s refused", d)
		}
	}
	for _, d := range []string{"com", "co.uk", "-a.com", "a..com", "1.2.3.4", "a b.com", "evil.com/", "*.evil.com", strings.Repeat("a", 64) + ".com"} {
		if ValidDomain(d) {
			t.Errorf("%s accepted", d)
		}
	}
}

func TestIndex(t *testing.T) {
	var b indexBuilder
	b.add("evil.example.com", CatC2)
	b.add("miner.example.net", CatMiner)
	b.add("evil.example.com", CatMalware) // duplicate
	ix := b.build()
	if ix.Len() != 2 {
		t.Fatalf("len = %d", ix.Len())
	}
	if d, c := ix.Lookup("A.Sub.Evil.Example.COM."); d != "evil.example.com" || c != CatC2 {
		t.Errorf("lookup = %q %v", d, c)
	}
	if d, _ := ix.Lookup("example.com"); d != "" {
		t.Errorf("parent matched: %q", d)
	}
	if d, c := ix.Lookup("miner.example.net"); d == "" || c != CatMiner {
		t.Errorf("miner = %q %v", d, c)
	}
	var nilIx *Index
	if d, _ := nilIx.Lookup("x.com"); d != "" {
		t.Error("nil index matched")
	}
}

func TestBlocker(t *testing.T) {
	state := t.TempDir()
	conf := t.TempDir()
	restarts := 0
	now := time.Unix(1_000_000, 0)
	b := New(state)
	b.ConfDirs = func() []string { return []string{conf} }
	b.Restart = func() error { restarts++; return nil }
	b.Probe = func(bool) error { return nil }
	b.Now = func() time.Time { return now }
	b.Protected = []string{"dash.infrafence.com"}
	list := "# comment\nevil.example.com c2\nBAD LINE here\nminer.example.net miner\ninfrafence.com\nsub.dash.infrafence.com\nthird.example.org\nfourth.example.org\n"
	n, err := b.Load(strings.NewReader(list), 3, 0, false)
	if err != nil || n != 3 {
		t.Fatalf("Load = %d, %v", n, err)
	}
	if c, dropped := b.Count(); c != 3 || dropped != 1 {
		t.Errorf("count = %d dropped %d", c, dropped)
	}
	data, _ := os.ReadFile(filepath.Join(state, "block.conf"))
	if !strings.Contains(string(data), "local=/evil.example.com/\n") || strings.Contains(string(data), "infrafence.com") || !strings.Contains(string(data), "local=/use-application-dns.net/") {
		t.Errorf("list:\n%s", data)
	}
	// Learning: nothing in the conf-dir, no restart.
	if on, err := b.Apply(); on || err != nil || restarts != 0 {
		t.Errorf("learning apply = %v %v restarts=%d", on, err, restarts)
	}
	b.SetFull(true)
	if on, err := b.Apply(); !on || err != nil || restarts != 1 {
		t.Errorf("full apply = %v %v restarts=%d", on, err, restarts)
	}
	if _, err := os.Stat(filepath.Join(conf, FileName)); err != nil {
		t.Errorf("not linked: %v", err)
	}
	// A new list within MinRestart waits; after it, it is linked again.
	b.Load(strings.NewReader("other.example.com\n"), 0, 0, false)
	if on, _ := b.Apply(); restarts != 1 {
		t.Errorf("restarted too soon (on=%v)", on)
	}
	now = now.Add(6 * time.Minute)
	if on, _ := b.Apply(); !on || restarts != 2 {
		t.Errorf("relink: on=%v restarts=%d", on, restarts)
	}
	got, _ := os.ReadFile(filepath.Join(conf, FileName))
	if !strings.Contains(string(got), "other.example.com") {
		t.Errorf("conf-dir has the old list:\n%s", got)
	}
	// Back to Learning: removed.
	now = now.Add(6 * time.Minute)
	b.SetFull(false)
	if on, _ := b.Apply(); on || restarts != 3 {
		t.Errorf("unlink: on=%v restarts=%d", on, restarts)
	}
	if _, err := os.Stat(filepath.Join(conf, FileName)); err == nil {
		t.Error("still linked")
	}
	if err := b.Remove(); err != nil {
		t.Error(err)
	}
}

func TestConfDirsIn(t *testing.T) {
	dir := t.TempDir()
	cd := filepath.Join("/tmp", "ifr-test-"+filepath.Base(dir))
	os.MkdirAll(cd, 0o755)
	defer os.RemoveAll(cd)
	f := filepath.Join(dir, "dnsmasq.conf.cfg01411c")
	os.WriteFile(f, []byte("# auto-generated\nconf-dir="+cd+",*.conf\nconf-dir=/etc/elsewhere\n"), 0o644)
	got := confDirsIn(f)
	if len(got) != 1 || got[0] != cd {
		t.Errorf("confDirsIn = %v", got)
	}
}

func TestAdopt(t *testing.T) {
	state, conf := t.TempDir(), t.TempDir()
	newB := func() *Blocker {
		b := New(state)
		b.ConfDirs = func() []string { return []string{conf} }
		b.Restart = func() error { return nil }
		b.Probe = func(bool) error { return nil }
		return b
	}
	b := newB()
	if b.Adopt() {
		t.Fatal("adopted nothing")
	}
	b.Load(strings.NewReader("evil.example.com c2\nbad.example.net\n"), 0, 0, false)
	b.SetFull(true)
	b.Apply()
	// A restarted agent takes the list and its link over.
	b2 := newB()
	restarts := 0
	b2.Restart = func() error { restarts++; return nil }
	if !b2.Adopt() {
		t.Fatal("not adopted")
	}
	if d, c := b2.Index().Lookup("x.evil.example.com"); d != "evil.example.com" || c != CatC2 {
		t.Errorf("adopted index: %q %v", d, c)
	}
	if n, _ := b2.Count(); n != 2 {
		t.Errorf("count = %d", n)
	}
	b2.SetFull(true)
	if on, _ := b2.Apply(); !on || restarts != 0 {
		t.Errorf("adopted apply: on=%v restarts=%d", on, restarts)
	}
}

func TestLoadRejectsBadLists(t *testing.T) {
	b := New(t.TempDir())
	b.ConfDirs = func() []string { return nil }
	if _, err := b.Load(strings.NewReader("good.example.com\n"), 0, 0, false); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"html":   "<html><body>Please log in to the hotel Wi-Fi</body></html>\n",
		"empty":  "",
		"shared": "github.io\namazonaws.com\ncom\n",
	} {
		if _, err := b.Load(strings.NewReader(body), 0, 0, false); !errors.Is(err, ErrTooFew) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := b.Load(strings.NewReader("a.example.com\n"), 0, 10, false); !errors.Is(err, ErrTooFew) {
		t.Errorf("below the announced count: %v", err)
	}
	if d, _ := b.Index().Lookup("good.example.com"); d == "" {
		t.Error("the good list was replaced")
	}
	// A line longer than the buffer is skipped, not fatal; subdomains of
	// shared platforms can be listed.
	long := strings.Repeat("x", 10000)
	n, err := b.Load(strings.NewReader(long+"\nevil.github.io\nlast.example.org"), 0, 0, false)
	if err != nil || n != 2 {
		t.Errorf("long line: n=%d err=%v", n, err)
	}
}

func TestUnhealthyDnsmasqRollsBack(t *testing.T) {
	state, conf := t.TempDir(), t.TempDir()
	b := New(state)
	b.ConfDirs = func() []string { return []string{conf} }
	restarts := 0
	b.Restart = func() error { restarts++; return nil }
	b.Probe = func(blocked bool) error {
		if blocked {
			return errors.New("timeout")
		}
		return nil
	}
	b.Load(strings.NewReader("evil.example.com\n"), 0, 0, false)
	b.SetFull(true)
	on, err := b.Apply()
	if on || !errors.Is(err, ErrUnhealthy) || restarts != 2 {
		t.Fatalf("apply = %v %v restarts=%d", on, err, restarts)
	}
	if _, err := os.Stat(filepath.Join(conf, FileName)); err == nil {
		t.Error("list left in the conf-dir")
	}
	// Not retried with the same list.
	b.Now = func() time.Time { return time.Now().Add(time.Hour) }
	if on, _ := b.Apply(); on || restarts != 2 {
		t.Errorf("retried: on=%v restarts=%d", on, restarts)
	}
	// No conf-dir: never reported as active.
	b2 := New(t.TempDir())
	b2.ConfDirs = func() []string { return nil }
	b2.Restart = func() error { return nil }
	b2.Probe = func(bool) error { return nil }
	b2.Load(strings.NewReader("evil.example.com\n"), 0, 0, false)
	b2.SetFull(true)
	if on, err := b2.Apply(); on || err == nil {
		t.Errorf("no conf-dir: on=%v err=%v", on, err)
	}
}

func TestEmptyListAllowed(t *testing.T) {
	state, conf := t.TempDir(), t.TempDir()
	b := New(state)
	b.ConfDirs = func() []string { return []string{conf} }
	b.Restart = func() error { return nil }
	b.Probe = func(bool) error { return nil }
	b.Load(strings.NewReader("evil.example.com\n"), 0, 0, false)
	b.SetFull(true)
	if on, _ := b.Apply(); !on {
		t.Fatal("not linked")
	}
	// The router lost InfraFence Home: an announced empty list.
	n, err := b.Load(strings.NewReader("# InfraFence Home is not included\n"), 0, 0, true)
	if err != nil || n != 0 {
		t.Fatalf("empty list: %d %v", n, err)
	}
	b.Now = func() time.Time { return time.Now().Add(time.Hour) }
	if on, err := b.Apply(); on || err != nil {
		t.Errorf("empty list linked: on=%v err=%v", on, err)
	}
	if _, err := os.Stat(filepath.Join(conf, FileName)); err == nil {
		t.Error("empty list in the conf-dir")
	}
	if d, _ := b.Index().Lookup("evil.example.com"); d != "" {
		t.Error("old list still matched")
	}
	b.Load(strings.NewReader("evil.example.com\n"), 0, 0, false)
	if err := b.Clear(); err != nil || b.Index().Len() != 0 {
		t.Errorf("clear: %v", err)
	}
}
