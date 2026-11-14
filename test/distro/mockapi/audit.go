package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// The free server audit (audit.sh, `infrafence-agent audit`): release
// signatures made with a throwaway key, and the dashboard's report
// endpoint.

// releaseSigner signs the served binary as the release workflow does
// (cosign sign-blob: base64 of an ECDSA P-256 ASN.1 signature of its
// SHA-256), with a key made for this run. Its public key is written to
// pubPath for the test to put in a copy of audit.sh.
func releaseSigner(bin []byte, pubPath string) (sig string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("signing key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		log.Fatalf("public key: %v", err)
	}
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644); err != nil {
		log.Fatalf("write public key: %v", err)
	}
	h := sha256.Sum256(bin)
	s, err := ecdsa.SignASN1(rand.Reader, key, h[:])
	if err != nil {
		log.Fatalf("sign: %v", err)
	}
	return base64.StdEncoding.EncodeToString(s)
}

// auditStore keeps the reports posted, as the dashboard would (the last
// one is enough for the tests).
type auditStore struct {
	mu      sync.Mutex
	reports int
	last    json.RawMessage
	invalid int
}

const auditToken = "Tk7p3QxV9mZr2LcY8bNw4HsJ6aDf1GeK5uQo"

// handleAuditReport is POST /api/v1/audit/report: no auth, a JSON body of
// at most 256 KB, 201 with a token and the link (the token in its
// fragment). GET /audit-state counts what was received, /audit-last is
// the last report.
func (a *auditStore) handleAuditReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 256<<10+1))
	if err != nil || len(body) > 256<<10 || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") || !json.Valid(body) {
		a.mu.Lock()
		a.invalid++
		a.mu.Unlock()
		http.Error(w, `{"error":"invalid report"}`, http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	a.reports++
	a.last = body
	a.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"token":      auditToken,
		"url":        "http://" + r.Host + "/tools/server-audit/r#" + auditToken,
		"expires_at": time.Now().Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339),
	})
}

// handleLast returns the last report received, as it was received.
func (a *auditStore) handleLast(w http.ResponseWriter, _ *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.last == nil {
		http.NotFound(w, nil)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(a.last)
}

func (a *auditStore) handleState(w http.ResponseWriter, _ *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"reports": a.reports, "invalid": a.invalid, "last": a.last})
}
