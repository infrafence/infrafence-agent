#!/bin/sh
# InfraFence router agent installer for OpenWrt and GL.iNet routers.
#
#   wget -qO- https://pkg.infrafence.com/router-install.sh | sh -s -- --token <install token>
#   (or INFRAFENCE_TOKEN=<install token> in the environment)
#
# Checks the router (OpenWrt release, package manager, architecture, free
# flash and RAM, firewall), adds the InfraFence package feed and its
# signing keys, installs infrafence-router (+ luci-app-infrafence when
# LuCI is installed) through opkg or apk, and enrols the router. Nothing
# is changed when a check fails.
set -eu

DEFAULT_FEED=https://pkg.infrafence.com/openwrt
FEED=${INFRAFENCE_FEED:-$DEFAULT_FEED}
# The InfraFence feed keys, pinned here (deploy/pkg-keygen.sh writes them at
# launch): the usign key fingerprint (opkg) and the SHA-256 of the apk key.
# The default feed is refused until they are set; another feed (--feed)
# trusts the key it serves over HTTPS on first use.
USIGN_FP=""
APK_KEY_SHA256=""
TOKEN=${INFRAFENCE_TOKEN:-}
SERVER=""
NAME=""
NO_LUCI=0

say() { echo "infrafence: $*"; }
die() { echo "infrafence: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
	case $1 in
	--token) TOKEN=${2:-}; shift 2 ;;
	--server) SERVER=${2:-}; shift 2 ;;
	--name) NAME=${2:-}; shift 2 ;;
	--feed) FEED=${2:-}; shift 2 ;;
	--no-luci) NO_LUCI=1; shift ;;
	*) die "unknown option $1" ;;
	esac
done

case $FEED in
https://*) ;;
http://*) [ "${INFRAFENCE_ALLOW_HTTP_FEED:-}" = 1 ] || die "the feed must use https: $FEED" ;;
*) die "invalid feed URL: $FEED" ;;
esac
case $FEED in *[!A-Za-z0-9:/._~%-]*) die "invalid feed URL: $FEED" ;; esac
FEED=${FEED%/}
if [ "$FEED" = "$DEFAULT_FEED" ]; then
	[ -n "$USIGN_FP" ] && [ -n "$APK_KEY_SHA256" ] || die "this installer has no pinned feed keys yet (the InfraFence feed is not published)"
else
	USIGN_FP=""
	APK_KEY_SHA256=""
	say "feed $FEED: its signing key is trusted as served (not pinned)"
fi

[ "$(id -u)" = 0 ] || die "run as root"
[ -f /etc/openwrt_release ] || die "this is not an OpenWrt (or GL.iNet) router"
. /etc/openwrt_release
release=${DISTRIB_RELEASE:-unknown}
arch=${DISTRIB_ARCH:-}

if command -v apk >/dev/null 2>&1; then
	pm=apk
	feed_rel=25.12
	[ -n "$arch" ] || arch=$(apk --print-arch)
elif command -v opkg >/dev/null 2>&1; then
	pm=opkg
	feed_rel=24.10
	[ -n "$arch" ] || arch=$(opkg print-architecture | awk '$1 == "arch" && $2 != "all" && $2 != "noarch" {a = $2} END {print a}')
else
	die "neither apk nor opkg found"
fi
[ -n "$arch" ] || die "cannot tell the package architecture"

case $arch in
mips_24kc | mips_mips32 | mipsel_24kc | mipsel_74kc | mipsel_mips32 | x86_64 | \
	arm_cortex-a7 | arm_cortex-a7_neon-vfpv4 | arm_cortex-a7_vfpv4 | arm_cortex-a8_vfpv3 | arm_cortex-a9_neon | arm_cortex-a9_vfpv3-d16 | arm_cortex-a15_neon-vfpv4 | \
	aarch64_cortex-a53 | aarch64_cortex-a72 | aarch64_cortex-a76 | aarch64_generic) ;;
*) die "architecture $arch is not supported yet" ;;
esac

# Resources: the package needs ~3.5 MB of flash, the agent ~10-25 MB of RAM.
free_kb=$(df -k /overlay 2>/dev/null | awk 'NR == 2 {print $4}')
[ -n "$free_kb" ] || free_kb=$(df -k / | awk 'NR == 2 {print $4}')
mem_kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
[ "${free_kb:-0}" -ge 4096 ] || die "only ${free_kb} kB free on flash, 4 MB needed (see infrafence.com/docs/routers for small devices)"
[ "${mem_kb:-0}" -ge 100000 ] || die "only $((mem_kb / 1024)) MB of RAM, 128 MB needed"

if [ -x /sbin/fw4 ]; then
	fwgen=fw4
elif [ -x /sbin/fw3 ]; then
	fwgen=fw3
	if ! command -v ipset >/dev/null 2>&1; then
		say "fw3 (iptables) firewall without ipset: installing ipset and kmod-ipt-ipset so bans can be enforced"
		$pm update >/dev/null 2>&1 || true
		if [ $pm = opkg ]; then opkg install ipset kmod-ipt-ipset >/dev/null 2>&1 || say "could not install ipset: the agent will detect and report only"; fi
	fi
else
	fwgen=none
	say "no fw3/fw4 firewall: the agent will detect and report only"
fi
say "OpenWrt $release, $arch, $pm, firewall $fwgen, $((free_kb / 1024)) MB free flash, $((mem_kb / 1024)) MB RAM"

fetch() { # url file
	if command -v uclient-fetch >/dev/null 2>&1; then uclient-fetch -q -O "$2" "$1"; else wget -q -O "$2" "$1"; fi
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
if [ $pm = opkg ]; then
	fetch "$FEED/keys/usign.pub" "$tmp/usign.pub" || die "cannot download the feed key from $FEED"
	fp=$(usign -F -p "$tmp/usign.pub") || die "invalid feed key"
	[ -z "$USIGN_FP" ] || [ "$fp" = "$USIGN_FP" ] || die "the feed key ($fp) is not InfraFence's ($USIGN_FP)"
	mkdir -p /etc/opkg/keys
	cp "$tmp/usign.pub" "/etc/opkg/keys/$fp"
	line="src/gz infrafence $FEED/$feed_rel/$arch"
	conf=/etc/opkg/customfeeds.conf
	touch "$conf"
	grep -v '^src/gz infrafence ' "$conf" >"$tmp/feeds" || true
	echo "$line" >>"$tmp/feeds"
	cat "$tmp/feeds" >"$conf"
	opkg update >/dev/null 2>&1 || say "opkg update reported errors (other feeds unreachable?)"
	opkg list | grep -q '^infrafence-router ' || die "the InfraFence feed could not be read (signature or network)"
	pkgs="infrafence-keyring infrafence-router"
	[ $NO_LUCI = 0 ] && [ -d /www/luci-static ] && pkgs="$pkgs luci-app-infrafence"
	opkg install $pkgs
else
	fetch "$FEED/keys/apk.pem" "$tmp/apk.pem" || die "cannot download the feed key from $FEED"
	if [ -n "$APK_KEY_SHA256" ]; then
		sum=$(sha256sum "$tmp/apk.pem" | cut -d' ' -f1)
		[ "$sum" = "$APK_KEY_SHA256" ] || die "the feed key ($sum) is not InfraFence's ($APK_KEY_SHA256)"
	fi
	mkdir -p /etc/apk/keys /etc/apk/repositories.d
	cp "$tmp/apk.pem" /etc/apk/keys/infrafence-feed.pem
	echo "$FEED/$feed_rel/$arch/packages.adb" >/etc/apk/repositories.d/infrafence.list
	apk update >/dev/null 2>&1 || say "apk update reported errors (other feeds unreachable?)"
	pkgs="infrafence-keyring infrafence-router"
	[ $NO_LUCI = 0 ] && [ -d /www/luci-static ] && pkgs="$pkgs luci-app-infrafence"
	apk add $pkgs
fi

if [ -n "$TOKEN" ]; then
	# On stdin, not on the agent's command line.
	set -- register --token-file -
	[ -n "$SERVER" ] && set -- "$@" --server "$SERVER"
	[ -n "$NAME" ] && set -- "$@" --name "$NAME"
	printf '%s\n' "$TOKEN" | /usr/sbin/infrafence-router "$@"
	/etc/init.d/infrafence restart
	say "installed and enrolled; the router starts in Learning mode (switch it to Full protection in the dashboard)"
else
	say "installed; enrol it from LuCI (Services > InfraFence) or with: infrafence-router register --token <token>"
fi
