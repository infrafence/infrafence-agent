package updater

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"testing"
)

func TestEmbeddedKeyIsTheRepositoryKey(t *testing.T) {
	root, err := os.ReadFile("../../cosign.pub")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.TrimSpace(root), bytes.TrimSpace(releaseKeyPEM)) {
		t.Fatal("internal/updater/release_key.pub differs from cosign.pub: keep them identical")
	}
	if _, err := releaseKey(); err != nil {
		t.Fatal(err)
	}
}

// A real release: checksums.txt of v1.0.28 and its cosign signature, made in CI.
func TestRealReleaseSignature(t *testing.T) {
	sig, err := os.ReadFile("testdata/v1.0.28-checksums.txt.sig")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("testdata/v1.0.28-checksums.txt")
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyRelease(data, string(sig)); err != nil {
		t.Fatalf("real release rejected: %v", err)
	}
	data[0] ^= 1
	if verifyRelease(data, string(sig)) == nil {
		t.Fatal("a modified file passed the signature check")
	}
}

func TestSignatureChecks(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	data := []byte("agent binary")
	h := sha256.Sum256(data)
	raw, _ := ecdsa.SignASN1(rand.Reader, key, h[:])
	sig := base64.StdEncoding.EncodeToString(raw)

	cases := []struct {
		name string
		pub  *ecdsa.PublicKey
		data []byte
		sig  string
		ok   bool
	}{
		{"valid", &key.PublicKey, data, sig + "\n", true},
		{"other key", &other.PublicKey, data, sig, false},
		{"other file", &key.PublicKey, []byte("evil binary"), sig, false},
		{"not base64", &key.PublicKey, data, "%%%", false},
		{"empty", &key.PublicKey, data, "", false},
	}
	for _, c := range cases {
		if err := verifyWith(c.pub, c.data, c.sig); (err == nil) != c.ok {
			t.Errorf("%s: err=%v, want ok=%v", c.name, err, c.ok)
		}
	}
}

func TestOfficialBase(t *testing.T) {
	got, err := officialBase("1.0.29")
	if err != nil || got != "https://github.com/infrafence/infrafence-agent/releases/download/v1.0.29" {
		t.Fatalf("got %q, %v", got, err)
	}
	for _, v := range []string{"", "v1.0.29", "1.0", "1.0.29-rc1", "1.0.29/../../evil", "1.0.29?x=1", "../1.0.29"} {
		if _, err := officialBase(v); err == nil {
			t.Errorf("%q accepted as a release version", v)
		}
	}
}
