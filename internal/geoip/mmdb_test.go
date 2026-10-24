package geoip

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/infrafence/infrafence-agent/internal/geoip/mmdbtest"
)

// A tree whose two branches lead to the same node at every level: 2^32
// networks from 32 nodes. Refused at once, by the download check and by
// the extraction from a file installed by hand.
func TestSharedNodesAreRefused(t *testing.T) {
	const n = 32
	var tree bytes.Buffer
	for i := uint32(0); i < n; i++ {
		next := i + 1
		if i == n-1 {
			next = n + 16 // the data record
		}
		mmdbtest.Put24(&tree, next)
		mmdbtest.Put24(&tree, next)
	}
	data := mmdbtest.Assemble("DBIP-Country-Lite", n, tree.Bytes(), mmdbtest.CountryRecord("US"), time.Now())

	start := time.Now()
	if _, err := Check(data); err == nil || !strings.Contains(err.Error(), "share nodes") {
		t.Fatalf("Check = %v", err)
	}
	path := filepath.Join(t.TempDir(), "x.mmdb")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	l := New(path) // Open does not walk the tree
	if _, err := l.ExtractCIDRs("US"); err == nil {
		t.Fatal("ExtractCIDRs walked a tree with shared nodes")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("took %s", d)
	}
}

// A metadata array claiming 16 million entries in a few bytes: refused
// before maxminddb allocates it.
func TestOversizedMetadataIsRefused(t *testing.T) {
	good, _ := mmdbtest.Build("DBIP-Country-Lite", mmdbtest.Anchors, time.Now())
	bomb := bytes.Replace(good, []byte("\x01\x04\x42en"), []byte("\x1f\x04\xff\xff\xff\x42en"), 1)
	if bytes.Equal(bomb, good) {
		t.Fatal("test database layout changed")
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if _, err := Check(bomb); err == nil {
		t.Fatal("Check accepted the metadata")
	}
	path := filepath.Join(t.TempDir(), "x.mmdb")
	_ = os.WriteFile(path, bomb, 0o644)
	if _, err := Open(path); err == nil {
		t.Fatal("Open accepted the metadata")
	}
	runtime.ReadMemStats(&after)
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 16<<20 {
		t.Fatalf("allocated %d MB", grew>>20)
	}
}

func TestCheckMetadataOfRealLayouts(t *testing.T) {
	for _, typ := range []string{"DBIP-Country-Lite", "GeoLite2-Country"} {
		data, _ := mmdbtest.Build(typ, mmdbtest.Anchors, time.Now())
		if err := checkMetadata(data); err != nil {
			t.Errorf("%s: %v", typ, err)
		}
	}
	if p := os.Getenv("GEOIP_BENCH_DB"); p != "" {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Check(data); err != nil {
			t.Fatalf("real database: %v", err)
		}
	}
}
