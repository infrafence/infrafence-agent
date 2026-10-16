package preflight

import (
	"strings"
	"testing"
	"time"
)

func TestRunUsesAFixedEnvironment(t *testing.T) {
	t.Setenv("LD_PRELOAD", "/tmp/evil.so")
	t.Setenv("PATH", "/tmp/evil:/usr/bin")
	out, err := hostEnv{}.Run("/usr/bin/env")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Fields(out); len(got) != 2 || got[0] != "PATH=/usr/sbin:/usr/bin:/sbin:/bin" || got[1] != "LC_ALL=C" {
		t.Errorf("environment: %q", out)
	}
}

func TestRunKillsTheProcessGroupOnTimeout(t *testing.T) {
	saved := runTimeout
	runTimeout = 300 * time.Millisecond
	defer func() { runTimeout = saved }()
	start := time.Now()
	// A grandchild keeps the output pipe open, like mysql under plesk db.
	_, err := hostEnv{}.Run("/bin/sh", "-c", "sleep 30 & sleep 30")
	if err == nil {
		t.Error("no error after the timeout")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("returned after %s", d)
	}
}
