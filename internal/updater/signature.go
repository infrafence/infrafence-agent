package updater

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Releases are signed in CI with cosign (sign-blob, ECDSA P-256). The public
// key ships inside the agent, so a new binary is installed only if it was
// signed by InfraFence — whatever server it was downloaded from or whatever
// address the dashboard sent. Same key as cosign.pub at the repository root.
//
//go:embed release_key.pub
var releaseKeyPEM []byte

// Official releases; the only source of updates.
const releaseBase = "https://github.com/infrafence/infrafence-agent/releases/download"

var versionPattern = regexp.MustCompile(`^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,6}$`)

// officialBase returns the download address of an official release, or an
// error for anything that isn't a plain x.y.z version.
func officialBase(version string) (string, error) {
	if !versionPattern.MatchString(version) {
		return "", fmt.Errorf("not a release version: %q", version)
	}
	return releaseBase + "/v" + version, nil
}

func releaseKey() (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(releaseKeyPEM)
	if block == nil {
		return nil, errors.New("release key: no PEM block")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("release key: %w", err)
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("release key: %T, want ECDSA", k)
	}
	return pub, nil
}

// verifyRelease checks a cosign sign-blob signature (base64 ASN.1 ECDSA over
// the SHA-256 of the data) against the embedded release key.
func verifyRelease(data []byte, sigB64 string) error {
	pub, err := releaseKey()
	if err != nil {
		return err
	}
	return verifyWith(pub, data, sigB64)
}

func verifyWith(pub *ecdsa.PublicKey, data []byte, sigB64 string) error {
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigB64))
	if err != nil {
		return fmt.Errorf("signature: %w", err)
	}
	h := sha256.Sum256(data)
	if !ecdsa.VerifyASN1(pub, h[:], sig) {
		return errors.New("signature does not match the InfraFence release key")
	}
	return nil
}
