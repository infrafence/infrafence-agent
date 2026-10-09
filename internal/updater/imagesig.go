package updater

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Container images are signed in CI with cosign (key pair, classic format: a
// "sha256-<digest>.sig" tag whose layer is the signed payload). Before a
// Kubernetes update the agent resolves the release's image digest, checks
// that signature with the release key built into the agent, and pins the
// DaemonSet to that exact digest — never to a tag the registry could move.
const (
	imageRepo     = "ghcr.io/infrafence/infrafence-agent"
	imageRepoPath = "infrafence/infrafence-agent"
)

// registryURL is the registry API base; a variable for tests.
var registryURL = "https://ghcr.io"

const (
	manifestAccept = "application/vnd.oci.image.index.v1+json," +
		"application/vnd.docker.distribution.manifest.list.v2+json," +
		"application/vnd.oci.image.manifest.v1+json," +
		"application/vnd.docker.distribution.manifest.v2+json"
	simpleSigningType   = "application/vnd.dev.cosign.simplesigning.v1+json"
	cosignSigAnnotation = "dev.cosignproject.cosign/signature"
	maxManifestSize     = 1 << 20
)

// verifiedImage returns "ghcr.io/infrafence/infrafence-agent@sha256:…" for
// the given release version, only if the image carries a valid InfraFence
// signature for exactly that digest.
func verifiedImage(version string) (string, error) {
	pub, err := releaseKey()
	if err != nil {
		return "", err
	}
	return verifiedImageWith(pub, version)
}

func verifiedImageWith(pub *ecdsa.PublicKey, version string) (string, error) {
	if !versionPattern.MatchString(version) {
		return "", fmt.Errorf("not a release version: %q", version)
	}
	reg := &registry{client: &http.Client{Timeout: 30 * time.Second}}
	if err := reg.login(); err != nil {
		return "", err
	}

	// The digest is computed from the manifest bytes, not taken from a header.
	manifest, err := reg.get("/manifests/"+version, manifestAccept, maxManifestSize)
	if err != nil {
		return "", fmt.Errorf("image %s: %w", version, err)
	}
	sum := sha256.Sum256(manifest)
	digest := "sha256:" + hex.EncodeToString(sum[:])

	sigManifest, err := reg.get("/manifests/sha256-"+hex.EncodeToString(sum[:])+".sig", manifestAccept, maxManifestSize)
	if err != nil {
		return "", fmt.Errorf("image %s has no signature: %w", version, err)
	}
	var m struct {
		Layers []struct {
			MediaType   string            `json:"mediaType"`
			Digest      string            `json:"digest"`
			Annotations map[string]string `json:"annotations"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(sigManifest, &m); err != nil {
		return "", fmt.Errorf("signature manifest: %w", err)
	}
	for _, l := range m.Layers {
		sig := l.Annotations[cosignSigAnnotation]
		if l.MediaType != simpleSigningType || sig == "" || !strings.HasPrefix(l.Digest, "sha256:") {
			continue
		}
		payload, err := reg.get("/blobs/"+l.Digest, "", maxTextSize)
		if err != nil {
			continue
		}
		ps := sha256.Sum256(payload)
		if "sha256:"+hex.EncodeToString(ps[:]) != l.Digest {
			continue
		}
		if verifyWith(pub, payload, sig) != nil {
			continue
		}
		var p struct {
			Critical struct {
				Identity struct {
					DockerReference string `json:"docker-reference"`
				} `json:"identity"`
				Image struct {
					DockerManifestDigest string `json:"docker-manifest-digest"`
				} `json:"image"`
				Type string `json:"type"`
			} `json:"critical"`
		}
		if json.Unmarshal(payload, &p) != nil {
			continue
		}
		if p.Critical.Type == "cosign container image signature" &&
			p.Critical.Identity.DockerReference == imageRepo &&
			p.Critical.Image.DockerManifestDigest == digest {
			return imageRepo + "@" + digest, nil
		}
	}
	return "", fmt.Errorf("image %s (%s): no valid InfraFence signature", version, digest)
}

type registry struct {
	client *http.Client
	token  string
}

// login gets an anonymous pull token (public image).
func (r *registry) login() error {
	body, err := r.fetch(registryURL+"/token?scope=repository:"+imageRepoPath+":pull", "", maxTextSize)
	if err != nil {
		return fmt.Errorf("registry token: %w", err)
	}
	var t struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &t); err != nil || t.Token == "" {
		return fmt.Errorf("registry token: unexpected answer")
	}
	r.token = t.Token
	return nil
}

func (r *registry) get(path, accept string, limit int64) ([]byte, error) {
	return r.fetch(registryURL+"/v2/"+imageRepoPath+path, accept, limit)
}

func (r *registry) fetch(url, accept string, limit int64) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if r.token != "" {
		req.Header.Set("Authorization", "Bearer "+r.token)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("answer larger than %d bytes", limit)
	}
	return data, nil
}
