package updater

import (
	"os"
	"testing"
)

// Real registry check; runs only with INFRAFENCE_NETWORK_TESTS=1.
func TestRealImageSignature(t *testing.T) {
	if os.Getenv("INFRAFENCE_NETWORK_TESTS") != "1" {
		t.Skip("set INFRAFENCE_NETWORK_TESTS=1 to check the published v1.0.28 image")
	}
	got, err := verifiedImage("1.0.28")
	if err != nil {
		t.Fatal(err)
	}
	if want := "ghcr.io/infrafence/infrafence-agent@sha256:7c2ab97662b0c7e2b78daf40d702a9a3e9d5eb596a4c9b988abf9e0da9ef9fb8"; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
	if _, err := verifiedImage("0.0.1"); err == nil {
		t.Fatal("a version that doesn't exist was accepted")
	}
}
