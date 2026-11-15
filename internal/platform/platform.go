// Package platform tells what kind of host the agent runs on. The Linux
// agent never asks it: only the FreeBSD build dispatches on it, to the
// appliance run loop (OPNsense) instead of the server one.
package platform

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Kind values, also sent to the dashboard as the register/heartbeat "kind".
const (
	KindServer   = "server"
	KindOPNsense = "opnsense"
)

// Info describes the host.
type Info struct {
	Kind    string `json:"kind"`
	Product string `json:"product,omitempty"` // "OPNsense", "OPNsense Business Edition"
	Version string `json:"version,omitempty"` // "26.7.1"
	Series  string `json:"series,omitempty"`  // "26.7"
	Kernel  string `json:"kernel,omitempty"`  // freebsd-version -k
	Arch    string `json:"arch"`
	ABI     string `json:"abi,omitempty"` // "FreeBSD:14:amd64"
}

// opnsenseCore is the product metadata OPNsense keeps on every install.
const opnsenseCore = "/usr/local/opnsense/version/core"

// Detect reads the host under root ("/" in production, a fixture directory
// in tests). kernel is called for the kernel version (nil: none).
func Detect(root string, kernel func() string) Info {
	info := Info{Kind: KindServer, Arch: runtime.GOARCH}
	data, err := os.ReadFile(filepath.Join(root, opnsenseCore))
	if err != nil {
		return info
	}
	var core struct {
		Name    string `json:"product_name"`
		Version string `json:"product_version"`
		Series  string `json:"product_series"`
		ABI     string `json:"product_abi"`
		Arch    string `json:"product_arch"`
	}
	if json.Unmarshal(data, &core) != nil {
		return info
	}
	info.Kind = KindOPNsense
	info.Product = clean(core.Name, 64)
	if info.Product == "" {
		info.Product = "OPNsense"
	}
	info.Version = clean(core.Version, 32)
	info.Series = clean(core.Series, 16)
	if info.Series == "" {
		if i := strings.IndexByte(info.Version, '.'); i > 0 {
			if j := strings.IndexByte(info.Version[i+1:], '.'); j > 0 {
				info.Series = info.Version[:i+1+j]
			}
		}
	}
	info.ABI = clean(core.ABI, 32)
	if kernel != nil {
		info.Kernel = clean(kernel(), 64)
	}
	return info
}

// FreeBSDKernel runs freebsd-version -k (the running kernel's version).
func FreeBSDKernel() string {
	out, err := exec.Command("/bin/freebsd-version", "-k").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// IsOPNsense: the host is an OPNsense firewall.
func IsOPNsense() bool {
	_, err := os.Stat(opnsenseCore)
	return err == nil
}

// clean keeps printable ASCII, at most n bytes: the values go into the
// dashboard as they are.
func clean(s string, n int) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(s) {
		if r < 0x20 || r > 0x7e {
			continue
		}
		b.WriteRune(r)
		if b.Len() >= n {
			break
		}
	}
	return b.String()
}
