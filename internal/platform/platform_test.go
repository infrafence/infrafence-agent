package platform

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectServer(t *testing.T) {
	info := Detect(t.TempDir(), nil)
	if info.Kind != KindServer {
		t.Fatalf("kind %q, want server", info.Kind)
	}
}

func TestDetectOPNsense(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, opnsenseCore)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	// Shape of /usr/local/opnsense/version/core on 26.7.
	core := `{"product_abi":"26.7","product_arch":"amd64","product_copyright_owner":"Deciso B.V.",
"product_email":"project@opnsense.org","product_hash":"abc","product_id":"opnsense","product_name":"OPNsense",
"product_nickname":"Xenial Xerus","product_series":"26.7","product_version":"26.7.1\u0007","product_website":"https://opnsense.org/"}`
	if err := os.WriteFile(p, []byte(core), 0o644); err != nil {
		t.Fatal(err)
	}
	info := Detect(root, func() string { return "14.3-RELEASE-p4" })
	if info.Kind != KindOPNsense || info.Product != "OPNsense" || info.Version != "26.7.1" || info.Series != "26.7" || info.Kernel != "14.3-RELEASE-p4" {
		t.Fatalf("got %+v", info)
	}
}

func TestDetectBrokenCore(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, opnsenseCore)
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	_ = os.WriteFile(p, []byte("not json"), 0o644)
	if Detect(root, nil).Kind != KindServer {
		t.Fatal("broken metadata must not turn on appliance mode")
	}
}
