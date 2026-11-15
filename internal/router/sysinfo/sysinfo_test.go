package sysinfo

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectFromFiles(t *testing.T) {
	root := t.TempDir()
	Root = root
	defer func() { Root = "" }()
	w := func(p, s string) {
		os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o755)
		os.WriteFile(filepath.Join(root, p), []byte(s), 0o755)
	}
	w("/etc/openwrt_release", "DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='24.10.8'\nDISTRIB_TARGET='mediatek/filogic'\nDISTRIB_ARCH='aarch64_cortex-a53'\nDISTRIB_DESCRIPTION='OpenWrt 24.10.8 r29233'\n")
	w("/tmp/sysinfo/board_name", "glinet,gl-mt3000\n")
	w("/tmp/sysinfo/model", "GL.iNet GL-MT3000\n")
	w("/sbin/fw4", "#!/bin/sh\n")
	w("/bin/opkg", "")
	w("/proc/meminfo", "MemTotal:         245432 kB\nMemFree: 1 kB\n")
	w("/etc/init.d/adblock", "")
	w("/etc/rc.d/S99adblock", "")
	w("/etc/init.d/banip", "") // installed, not enabled
	in := Detect()
	if in.Version != "24.10.8" || in.Arch != "aarch64_cortex-a53" || in.Target != "mediatek/filogic" || in.Release != "OpenWrt 24.10.8 r29233" {
		t.Errorf("release: %+v", in)
	}
	if in.Board != "glinet,gl-mt3000" || in.Model != "GL.iNet GL-MT3000" || in.Vendor != "glinet" {
		t.Errorf("board: %+v", in)
	}
	if in.Firewall != "fw4" || in.PackageManager != "opkg" || in.MemTotal != 245432*1024 {
		t.Errorf("fw/pm/mem: %+v", in)
	}
	if len(in.Coexisting) != 1 || in.Coexisting[0] != "adblock" {
		t.Errorf("coexisting = %v", in.Coexisting)
	}
}

func TestDefaultCaps(t *testing.T) {
	if b, _, d := DefaultCaps(128 << 20); b != 20000 || d != 100000 {
		t.Errorf("128 MB: %d %d", b, d)
	}
	if b, _, d := DefaultCaps(512 << 20); b != 100000 || d != 300000 {
		t.Errorf("512 MB: %d %d", b, d)
	}
}

func TestDnsmasqVersion(t *testing.T) {
	v := dnsmasqVersion("Dnsmasq version 2.85  Copyright (c) 2000-2021 Simon Kelley\nCompile time options: IPv6 GNU-getopt no-DBus UBus\n")
	if v != "2.85" || !OldDnsmasq(v) || OldDnsmasq("2.93") || OldDnsmasq("2.86rc1") || OldDnsmasq("") {
		t.Errorf("version %q", v)
	}
}
