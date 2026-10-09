package updater

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const pinned = imageRepo + "@sha256:" + "ab" + "cd0000000000000000000000000000000000000000000000000000000000"

// fakeCluster serves GET/PATCH of one DaemonSet over TLS, with the pod's
// service account files pointing at it.
func fakeCluster(t *testing.T, containers string) *[]string {
	t.Helper()
	var mu sync.Mutex
	var patches []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/apis/apps/v1/namespaces/ns/daemonsets/agent" || r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(`{"spec":{"template":{"spec":{"containers":` + containers + `}}}}`))
		case http.MethodPatch:
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			patches = append(patches, string(b))
			mu.Unlock()
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	tok, ca := filepath.Join(dir, "token"), filepath.Join(dir, "ca.crt")
	_ = os.WriteFile(tok, []byte("tok\n"), 0o600)
	_ = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	u, _ := url.Parse(srv.URL)
	host, port, _ := net.SplitHostPort(u.Host)

	oldTok, oldCA := saTokenPath, saCAPath
	saTokenPath, saCAPath = tok, ca
	t.Cleanup(func() { saTokenPath, saCAPath = oldTok, oldCA })
	t.Setenv("KUBERNETES_SERVICE_HOST", host)
	t.Setenv("KUBERNETES_SERVICE_PORT", port)
	t.Setenv("POD_NAMESPACE", "ns")
	t.Setenv("DAEMONSET_NAME", "agent")
	return &patches
}

func withImageCheck(t *testing.T, f func(string) (string, error)) {
	old := verifyImage
	verifyImage = f
	t.Cleanup(func() { verifyImage = old })
}

func events(list *[]string) EventReporter {
	return func(eventType, _ string, d map[string]string) { *list = append(*list, eventType+":"+d["reason"]) }
}

func TestK8sUpdatePinsTheVerifiedImage(t *testing.T) {
	patches := fakeCluster(t, `[{"name":"log-shipper","image":"fluent/fluent-bit:3"},{"name":"infrafence-agent","image":"ghcr.io/infrafence/infrafence-agent:1.0.27"}]`)
	withImageCheck(t, func(v string) (string, error) { return pinned, nil })
	var ev []string
	K8sRollingUpdate("1.0.27", "1.0.29", events(&ev))

	if len(*patches) != 1 {
		t.Fatalf("%d patches, want 1 (events %v)", len(*patches), ev)
	}
	var p struct {
		Spec struct {
			Template struct {
				Metadata struct {
					Annotations map[string]string `json:"annotations"`
				} `json:"metadata"`
				Spec struct {
					Containers []map[string]string `json:"containers"`
				} `json:"spec"`
			} `json:"template"`
		} `json:"spec"`
	}
	if err := json.Unmarshal([]byte((*patches)[0]), &p); err != nil {
		t.Fatal(err)
	}
	c := p.Spec.Template.Spec.Containers
	if len(c) != 1 || c[0]["name"] != "infrafence-agent" || c[0]["image"] != pinned {
		t.Fatalf("patched containers %v, want only infrafence-agent pinned to the digest", c)
	}
	if p.Spec.Template.Metadata.Annotations["infrafence.com/target-version"] != "1.0.29" {
		t.Fatal("target-version annotation missing")
	}
}

func TestK8sUpdateRefusesAnUnsignedImage(t *testing.T) {
	patches := fakeCluster(t, `[{"name":"infrafence-agent","image":"ghcr.io/infrafence/infrafence-agent:1.0.27"}]`)
	withImageCheck(t, func(v string) (string, error) { return "", errors.New("no valid InfraFence signature") })
	var ev []string
	K8sRollingUpdate("1.0.27", "1.0.29", events(&ev))
	if len(*patches) != 0 {
		t.Fatal("DaemonSet patched with an unverified image")
	}
	if len(ev) != 1 || ev[0] != "update_failed:image_signature_invalid" {
		t.Fatalf("events %v", ev)
	}
}

func TestK8sUpdateLeavesPrivateRegistriesAlone(t *testing.T) {
	patches := fakeCluster(t, `[{"name":"infrafence-agent","image":"registry.example.com/mirror/infrafence-agent:1.0.27"}]`)
	withImageCheck(t, func(v string) (string, error) { return pinned, nil })
	var ev []string
	K8sRollingUpdate("1.0.27", "1.0.29", events(&ev))
	if len(*patches) != 0 {
		t.Fatal("a DaemonSet using a private registry was switched to ghcr.io")
	}
	if len(ev) != 1 || !strings.HasPrefix(ev[0], "update_available") {
		t.Fatalf("events %v", ev)
	}
}

func TestImageRepository(t *testing.T) {
	for in, want := range map[string]string{
		"ghcr.io/infrafence/infrafence-agent:1.0.27":         imageRepo,
		"ghcr.io/infrafence/infrafence-agent@sha256:abc":     imageRepo,
		"ghcr.io/infrafence/infrafence-agent":                imageRepo,
		"localhost:5000/infrafence-agent:1":                  "localhost:5000/infrafence-agent",
		"ghcr.io/infrafence/infrafence-agent-evil:1.0.27":    "ghcr.io/infrafence/infrafence-agent-evil",
		"ghcr.io/infrafence/infrafence-agent:1@sha256:abc12": imageRepo,
	} {
		if got := imageRepository(in); got != want {
			t.Errorf("%s: got %s, want %s", in, got, want)
		}
	}
}
