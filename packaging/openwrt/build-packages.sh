#!/usr/bin/env bash
# Builds the OpenWrt packages and the signed package feeds of the router
# agent from the binaries of build-binaries.sh:
#
#   OUT/24.10/<arch>/  .ipk + Packages, Packages.gz, Packages.sig (opkg, usign)
#   OUT/25.12/<arch>/  .apk + packages.adb (apk v3, signed with an EC key)
#
# Packages: infrafence-router (the agent), luci-app-infrafence (LuCI page),
# infrafence-keyring (the feed's public keys).
#
# Usage: packaging/openwrt/build-packages.sh BINDIR VERSION OUT
# Keys (never committed; CI secrets in production, throwaway keys in tests):
#   USIGN_SEC   usign secret key   (owrtpkg keygen)
#   USIGN_PUB   usign public key
#   APK_SEC     EC P-256 private key, PEM (openssl ecparam -name prime256v1 -genkey -noout)
#   APK_PUB     its public key, PEM
# ARCHES limits the OpenWrt architectures built (space separated).
# Needs Go and Docker (apk-tools 3 from the Alpine image).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
bindir=$(cd "${1:?binary directory}" && pwd)
version=${2:?version}
out=${3:?output directory}
mkdir -p "$out"
out=$(cd "$out" && pwd)
: "${USIGN_SEC:?}" "${USIGN_PUB:?}" "${APK_SEC:?}" "${APK_PUB:?}"
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$repo" log -1 --format=%ct 2>/dev/null || date +%s)}
ALPINE_IMAGE=${ALPINE_IMAGE:-alpine:3.23}

# Package version: "1.2.3" -> "1.2.3-r1"; a development version
# ("1.2.3-rc1-4-gabc", "1.2.3-test") becomes "1.2.3_git<epoch>-r1", which
# both opkg and apk order correctly.
base=${version%%-*}
if ! [[ $base =~ ^[0-9]+(\.[0-9]+){1,3}$ ]]; then
  echo "bad version: $version" >&2; exit 1
fi
pkgver=$base
[ "$version" != "$base" ] && pkgver="${base}_git${SOURCE_DATE_EPOCH}"
pkgver="$pkgver-r1"

# GOARCH -> OpenWrt package architectures it runs on.
archmap() {
  case $1 in
    mips) echo "mips_24kc mips_mips32" ;;
    mipsle) echo "mipsel_24kc mipsel_74kc mipsel_mips32" ;;
    arm) echo "arm_cortex-a7 arm_cortex-a7_neon-vfpv4 arm_cortex-a7_vfpv4 arm_cortex-a8_vfpv3 arm_cortex-a9_neon arm_cortex-a9_vfpv3-d16 arm_cortex-a15_neon-vfpv4" ;;
    arm64) echo "aarch64_cortex-a53 aarch64_cortex-a72 aarch64_cortex-a76 aarch64_generic" ;;
    amd64) echo "x86_64" ;;
  esac
}
want=" ${ARCHES:-} "

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
owrtpkg="$work/owrtpkg"
(cd "$repo" && go build -o "$owrtpkg" ./packaging/openwrt/owrtpkg)
fp=$("$owrtpkg" fingerprint -pub "$USIGN_PUB")

# Data trees.
agent_root() { # GOARCH
  local r="$work/root-agent-$1"
  [ -d "$r" ] && { echo "$r"; return; }
  mkdir -p "$r/usr/sbin" "$r/lib/apk/packages"
  cp -R "$here/files/." "$r/"
  install -m 0755 "$bindir/infrafence-router-linux-$1" "$r/usr/sbin/infrafence-router"
  echo /etc/config/infrafence >"$r/lib/apk/packages/infrafence-router.conffiles"
  echo "$r"
}
luci_root="$work/root-luci"; mkdir -p "$luci_root"; cp -R "$here/luci/." "$luci_root/"
key_root="$work/root-keyring"
mkdir -p "$key_root/etc/opkg/keys" "$key_root/etc/apk/keys"
cp "$USIGN_PUB" "$key_root/etc/opkg/keys/$fp"
cp "$APK_PUB" "$key_root/etc/apk/keys/infrafence-feed.pem"

control() { # name arch depends description
  local d="$work/ctl-$1-$2"
  rm -rf "$d"; mkdir -p "$d"
  cat >"$d/control" <<EOF
Package: $1
Version: $pkgver
${3:+Depends: $3
}Source: https://github.com/infrafence/infrafence-agent
SourceName: $1
License: Apache-2.0
Section: net
SourceDateEpoch: $SOURCE_DATE_EPOCH
Maintainer: InfraFence <support@infrafence.com>
Architecture: $2
Description:  $4
EOF
  if [ "$1" = infrafence-router ]; then
    echo /etc/config/infrafence >"$d/conffiles"
    cp "$here/scripts/postinst" "$here/scripts/prerm" "$here/scripts/postrm" "$d/"
  fi
  echo "$d"
}

AGENT_DESC="InfraFence security agent for OpenWrt and GL.iNet routers: blocks known attackers and malicious domains, reports infected LAN devices to the InfraFence dashboard."
LUCI_DESC="LuCI page for the InfraFence router agent (enrolment, status, settings)."
KEY_DESC="Public keys of the InfraFence OpenWrt package feed."

# apk v3 packages are made in one container run (apk-tools 3 from Alpine),
# as root so the files are recorded root-owned, from copies of the trees.
apkjobs="$work/apk-jobs.sh"
echo 'set -eu' >"$apkjobs"
q() { case $1 in *"'"*) echo "no single quotes allowed: $1" >&2; exit 1 ;; esac; printf "'%s'" "$1"; }
mkapk() { # name arch depends description root outfile scripts(yes/no)
  local line="apk mkpkg --info $(q "name:$1") --info $(q "version:$pkgver") --info $(q "description:$4") --info $(q "arch:$2")"
  line="$line --info license:Apache-2.0 --info $(q "origin:$1") --info url:https://infrafence.com --info $(q "maintainer:InfraFence <support@infrafence.com>")"
  [ -n "$3" ] && line="$line --info $(q "depends:$3")"
  if [ "$7" = yes ]; then
    line="$line --script post-install:/build/scripts/postinst --script pre-deinstall:/build/scripts/prerm --script post-deinstall:/build/scripts/postrm --script post-upgrade:/build/scripts/postinst"
  fi
  echo "$line --files /build/$(basename "$5") --output $(q "$6") --sign-key /keys/apk.sec" >>"$apkjobs"
}
mkndx() { # dir
  echo "apk mkndx --allow-untrusted --sign-key /keys/apk.sec --description $(q "InfraFence $pkgver") --output $(q "$1/packages.adb") $(q "$1")/*.apk" >>"$apkjobs"
}

built=0
for goarch in mips mipsle arm arm64 amd64; do
  [ -f "$bindir/infrafence-router-linux-$goarch" ] || continue
  for arch in $(archmap "$goarch"); do
    if [ "$want" != "  " ] && [[ $want != *" $arch "* ]]; then continue; fi
    root=$(agent_root "$goarch")
    # opkg (24.10 and older, GL.iNet)
    d="$out/24.10/$arch"; mkdir -p "$d"
    "$owrtpkg" ipk -root "$root" -control "$(control infrafence-router "$arch" "libc, ca-bundle" "$AGENT_DESC")" -out "$d/infrafence-router_${pkgver}_${arch}.ipk"
    "$owrtpkg" ipk -root "$luci_root" -control "$(control luci-app-infrafence all "luci-base, infrafence-router" "$LUCI_DESC")" -out "$d/luci-app-infrafence_${pkgver}_all.ipk"
    "$owrtpkg" ipk -root "$key_root" -control "$(control infrafence-keyring all "" "$KEY_DESC")" -out "$d/infrafence-keyring_${pkgver}_all.ipk"
    "$owrtpkg" index -dir "$d"
    "$owrtpkg" sign -sec "$USIGN_SEC" -m "$d/Packages"
    "$owrtpkg" verify -pub "$USIGN_PUB" -m "$d/Packages" >/dev/null
    # apk (25.12)
    a="$out/25.12/$arch"; mkdir -p "$a"
    mkapk infrafence-router "$arch" "ca-bundle" "$AGENT_DESC" "$root" "$a/infrafence-router-$pkgver.apk" yes
    mkapk luci-app-infrafence noarch "luci-base infrafence-router" "$LUCI_DESC" "$luci_root" "$a/luci-app-infrafence-$pkgver.apk" no
    mkapk infrafence-keyring noarch "" "$KEY_DESC" "$key_root" "$a/infrafence-keyring-$pkgver.apk" no
    mkndx "$a"
    built=$((built + 1))
  done
done
[ "$built" -gt 0 ] || { echo "no architecture built" >&2; exit 1; }

mkdir -p "$work/keys" "$work/scripts"
cp "$APK_SEC" "$work/keys/apk.sec"
cp "$here/scripts/"* "$work/scripts/"
docker run --rm -v "$work:/work:ro" -v "$out:$out" "$ALPINE_IMAGE" sh -c "
  set -e
  mkdir -p /build && cp -R /work/root-* /work/scripts /build/ && cp -R /work/keys /keys
  chown -R 0:0 /build && chmod -R go-w /build
  sh /work/apk-jobs.sh
  chown -R $(id -u):$(id -g) '$out'
"
# The public keys, for the installer (router-install.sh) to add.
mkdir -p "$out/keys"
cp "$USIGN_PUB" "$out/keys/usign.pub"
cp "$APK_PUB" "$out/keys/apk.pem"
echo "built $built architectures, version $pkgver, usign key $fp -> $out"
