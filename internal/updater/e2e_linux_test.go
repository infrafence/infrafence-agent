//go:build linux && updatee2e

package updater

// Real update against the published v1.0.28 release. Run only inside a
// disposable container as root (it replaces /usr/local/bin/infrafence-agent):
//
//	GOOS=linux GOARCH=amd64 go test -c -tags updatee2e -o e2e.test ./internal/updater
//	docker run --rm -v "$PWD":/w ubuntu:24.04 sh -c 'apt-get update -qq && apt-get install -y -qq ca-certificates >/dev/null && cd /w/internal/updater && /w/e2e.test -test.v'

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func TestRealUpdateToSignedRelease(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root in a disposable container")
	}
	if err := os.MkdirAll("/etc/infrafence", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(targetPath, []byte("#!/bin/sh\necho old agent\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	var events []string
	report := func(eventType, severity string, details map[string]string) {
		events = append(events, eventType+":"+details["reason"])
	}
	// The dashboard's address is ignored: the official release is used.
	CheckAndUpdate("1.0.27", "1.0.28", "https://evil.example/agent", report)

	sums, err := os.ReadFile("testdata/v1.0.28-checksums.txt")
	if err != nil {
		t.Fatal(err)
	}
	var want string
	for _, l := range strings.Split(string(sums), "\n") {
		if f := strings.Fields(l); len(f) == 2 && f[1] == "infrafence-agent-linux-amd64" {
			want = f[0]
		}
	}
	got, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(got)
	if hex.EncodeToString(sum[:]) != want {
		t.Fatalf("installed binary is not the signed v1.0.28 (events %v)", events)
	}
	if b, _ := os.ReadFile(backupPath); string(b) != "#!/bin/sh\necho old agent\n" {
		t.Fatal("previous binary not kept as backup")
	}
	if _, err := os.Stat(targetPath + ".new"); err == nil {
		t.Fatal("staging file left behind")
	}
	t.Logf("events: %v", events)
}
