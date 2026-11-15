//go:build freebsd

package config

// On FreeBSD (OPNsense) third-party configuration lives under /usr/local.
func init() { defaultPath = "/usr/local/etc/infrafence/config.json" }
