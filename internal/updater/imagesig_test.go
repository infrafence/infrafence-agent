package updater

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeImage struct {
	manifest   []byte
	payload    []byte // signed payload served as the signature layer
	servedBlob []byte // what the registry returns for the payload digest (tampering)
	signer     *ecdsa.PrivateKey
	noSig      bool
}

func digestOf(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

func payloadFor(repo, digest string) []byte {
	return []byte(fmt.Sprintf(`{"critical":{"identity":{"docker-reference":%q},"image":{"docker-manifest-digest":%q},"type":"cosign container image signature"},"optional":null}`, repo, digest))
}

func serveRegistry(t *testing.T, img fakeImage) {
	t.Helper()
	h := sha256.Sum256(img.payload)
	sig, _ := ecdsa.SignASN1(rand.Reader, img.signer, h[:])
	sigManifest, _ := json.Marshal(map[string]any{
		"layers": []map[string]any{{
			"mediaType":   simpleSigningType,
			"digest":      digestOf(img.payload),
			"annotations": map[string]string{cosignSigAnnotation: base64.StdEncoding.EncodeToString(sig)},
		}},
	})
	blob := img.payload
	if img.servedBlob != nil {
		blob = img.servedBlob
	}
	base := "/v2/" + imageRepoPath
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token":
			_, _ = w.Write([]byte(`{"token":"t"}`))
		case r.URL.Path == base+"/manifests/1.2.3":
			_, _ = w.Write(img.manifest)
		case strings.HasPrefix(r.URL.Path, base+"/manifests/sha256-") && !img.noSig:
			if r.URL.Path != base+"/manifests/sha256-"+strings.TrimPrefix(digestOf(img.manifest), "sha256:")+".sig" {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(sigManifest)
		case r.URL.Path == base+"/blobs/"+digestOf(img.payload):
			_, _ = w.Write(blob)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	old := registryURL
	registryURL = srv.URL
	t.Cleanup(func() { registryURL = old })
}

func TestImageSignature(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	manifest := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`)
	d := digestOf(manifest)

	cases := []struct {
		name string
		img  fakeImage
		ok   bool
	}{
		{"valid", fakeImage{manifest: manifest, payload: payloadFor(imageRepo, d), signer: key}, true},
		{"signed by another key", fakeImage{manifest: manifest, payload: payloadFor(imageRepo, d), signer: other}, false},
		{"signature for another digest", fakeImage{manifest: manifest, payload: payloadFor(imageRepo, "sha256:"+strings.Repeat("0", 64)), signer: key}, false},
		{"signature for another image", fakeImage{manifest: manifest, payload: payloadFor("docker.io/evil/agent", d), signer: key}, false},
		{"payload swapped by the registry", fakeImage{manifest: manifest, payload: payloadFor(imageRepo, d), servedBlob: payloadFor(imageRepo, d+" "), signer: key}, false},
		{"unsigned image", fakeImage{manifest: manifest, payload: payloadFor(imageRepo, d), signer: key, noSig: true}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			serveRegistry(t, c.img)
			got, err := verifiedImageWith(&key.PublicKey, "1.2.3")
			if (err == nil) != c.ok {
				t.Fatalf("err=%v, want ok=%v", err, c.ok)
			}
			if c.ok && got != imageRepo+"@"+d {
				t.Fatalf("got %s, want the pinned digest", got)
			}
		})
	}
}

func TestImageVersionMustBePlain(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for _, v := range []string{"latest", "1.2.3/../x", "1.2"} {
		if _, err := verifiedImageWith(&key.PublicKey, v); err == nil {
			t.Errorf("%q accepted", v)
		}
	}
}
