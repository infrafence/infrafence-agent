package updater

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// IsKubernetes returns true if the agent is running inside a Kubernetes pod.
func IsKubernetes() bool {
	_, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token")
	return err == nil
}

// K8sRollingUpdate updates the agent's own DaemonSet to a new release: the
// image of that version must carry a valid InfraFence signature, and the
// agent container is pinned to that exact digest (the pods are then replaced
// by Kubernetes' rolling update). A DaemonSet using another registry (a
// private mirror) is left alone: its owner updates the Helm release.
func K8sRollingUpdate(currentVersion, latestVersion string, reportEvent EventReporter) {
	if os.Getenv("DISABLE_K8S_AUTO_UPDATE") == "true" {
		return
	}

	namespace := os.Getenv("POD_NAMESPACE")
	daemonsetName := os.Getenv("DAEMONSET_NAME")

	if namespace == "" || daemonsetName == "" {
		log.Printf("[updater] K8s rolling update skipped: POD_NAMESPACE or DAEMONSET_NAME not set")
		return
	}

	// Don't re-patch if we already triggered this version
	if data, err := os.ReadFile(updateAttemptMarker); err == nil {
		if markerVersion := string(data); markerVersion == latestVersion {
			return
		}
	}

	details := map[string]string{
		"current_version": currentVersion,
		"target_version":  latestVersion,
		"method":          "k8s_rolling_update",
		"daemonset":       fmt.Sprintf("%s/%s", namespace, daemonsetName),
	}
	fail := func(reason string, err error) {
		log.Printf("[updater] K8s update to %s not done (%s): %v", latestVersion, reason, err)
		reportEvent("update_failed", "high", mergeDetails(details, map[string]string{"reason": reason, "error": err.Error()}))
	}

	image, err := verifyImage(latestVersion)
	if err != nil {
		fail("image_signature_invalid", err)
		return
	}
	details["image"] = image

	api, err := newK8sAPI()
	if err != nil {
		fail("k8s_api_unavailable", err)
		return
	}
	dsPath := fmt.Sprintf("/apis/apps/v1/namespaces/%s/daemonsets/%s", namespace, daemonsetName)
	body, err := api.do(http.MethodGet, dsPath, "", nil)
	if err != nil {
		fail("k8s_api_error", err)
		return
	}
	container, current, err := agentContainer(body)
	if err != nil {
		log.Printf("[updater] K8s automatic update skipped: %v — update the Helm release to %s", err, latestVersion)
		reportEvent("update_available", "info", mergeDetails(details, map[string]string{"note": err.Error()}))
		os.WriteFile(updateAttemptMarker, []byte(latestVersion), 0644)
		return
	}

	log.Printf("[updater] K8s mode: %s -> %s (daemonset %s/%s, container %s: %s -> %s)",
		currentVersion, latestVersion, namespace, daemonsetName, container, current, image)
	reportEvent("update_started", "info", details)

	patch, err := json.Marshal(map[string]any{
		"spec": map[string]any{
			"template": map[string]any{
				"metadata": map[string]any{
					"annotations": map[string]string{
						"infrafence.com/updated-at":     time.Now().UTC().Format(time.RFC3339),
						"infrafence.com/target-version": latestVersion,
					},
				},
				"spec": map[string]any{
					"containers": []map[string]string{{"name": container, "image": image}},
				},
			},
		},
	})
	if err != nil {
		fail("k8s_patch_failed", err)
		return
	}
	if _, err := api.do(http.MethodPatch, dsPath, "application/strategic-merge-patch+json", patch); err != nil {
		fail("k8s_patch_failed", err)
		return
	}

	log.Printf("[updater] K8s rolling update triggered — pods will restart with the signed %s image", latestVersion)
	reportEvent("update_completed", "info", details)

	// Write marker so we don't keep patching every heartbeat
	os.WriteFile(updateAttemptMarker, []byte(latestVersion), 0644)
}

// agentContainer finds, in a DaemonSet (JSON), the container running the
// official agent image; another image (private registry) is an error.
func agentContainer(daemonset []byte) (name, image string, err error) {
	var ds struct {
		Spec struct {
			Template struct {
				Spec struct {
					Containers []struct {
						Name  string `json:"name"`
						Image string `json:"image"`
					} `json:"containers"`
				} `json:"spec"`
			} `json:"template"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(daemonset, &ds); err != nil {
		return "", "", fmt.Errorf("daemonset: %w", err)
	}
	var seen []string
	for _, c := range ds.Spec.Template.Spec.Containers {
		if imageRepository(c.Image) == imageRepo {
			return c.Name, c.Image, nil
		}
		seen = append(seen, c.Image)
	}
	return "", "", fmt.Errorf("the DaemonSet doesn't use %s (images: %s)", imageRepo, strings.Join(seen, ", "))
}

// imageRepository strips the tag or digest: "ghcr.io/a/b:1.0" → "ghcr.io/a/b".
func imageRepository(image string) string {
	if i := strings.Index(image, "@"); i >= 0 {
		image = image[:i]
	}
	if i := strings.LastIndex(image, ":"); i > strings.LastIndex(image, "/") {
		image = image[:i]
	}
	return image
}

// Service account files and the image check; variables for tests.
var (
	saTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	saCAPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	verifyImage = verifiedImage
)

// k8sAPI talks to the cluster API with the pod's service account.
type k8sAPI struct {
	base   string
	token  string
	client *http.Client
}

func newK8sAPI() (*k8sAPI, error) {
	token, err := os.ReadFile(saTokenPath)
	if err != nil {
		return nil, err
	}
	caCert, err := os.ReadFile(saCAPath)
	if err != nil {
		return nil, err
	}
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, fmt.Errorf("K8s API host/port not found in env")
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caCert)
	return &k8sAPI{
		base:  "https://" + net.JoinHostPort(host, port),
		token: strings.TrimSpace(string(token)),
		client: &http.Client{
			Timeout:   15 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
		},
	}, nil
}

func (k *k8sAPI) do(method, path, contentType string, body []byte) ([]byte, error) {
	req, err := http.NewRequest(method, k.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+k.token)
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := k.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestSize))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %.200s", resp.StatusCode, data)
	}
	return data, nil
}
