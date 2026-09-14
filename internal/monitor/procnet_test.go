package monitor

import (
	"os"
	"path/filepath"
	"testing"
)

func writeProcNetFixture(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "net_fixture")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	return path
}

// procNetFixtureHeader is the header line /proc/net/{tcp,udp} always starts
// with; parseProcNet skips it unconditionally.
const procNetFixtureHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

func TestParseProcNet(t *testing.T) {
	// 127.0.0.1:80 (local) <-> 8.8.8.8:443 (remote), state 01 = ESTABLISHED
	content := procNetFixtureHeader +
		"   0: 0100007F:0050 08080808:01BB 01 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n"
	path := writeProcNetFixture(t, content)

	entries, err := parseProcNet(path)
	if err != nil {
		t.Fatalf("parseProcNet error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	e := entries[0]
	if e.LocalIP.String() != "127.0.0.1" || e.LocalPort != 80 {
		t.Errorf("unexpected local addr: %s:%d", e.LocalIP, e.LocalPort)
	}
	if e.RemoteIP.String() != "8.8.8.8" || e.RemotePort != 443 {
		t.Errorf("unexpected remote addr: %s:%d", e.RemoteIP, e.RemotePort)
	}
	if e.State != TCPEstablished {
		t.Errorf("expected state ESTABLISHED (%#x), got %#x", TCPEstablished, e.State)
	}
}

func TestParseProcNet_SkipsMalformedLines(t *testing.T) {
	content := procNetFixtureHeader +
		"garbage line with too few fields\n" +
		"   0: 0100007F:0050 08080808:01BB 01 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n"
	path := writeProcNetFixture(t, content)

	entries, err := parseProcNet(path)
	if err != nil {
		t.Fatalf("parseProcNet error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected malformed line to be skipped, got %d entries", len(entries))
	}
}

func TestParseProcNet_MissingFile(t *testing.T) {
	if _, err := parseProcNet(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Fatalf("expected error for missing file")
	}
}
