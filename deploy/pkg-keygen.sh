#!/usr/bin/env bash
# Creates the three signing key pairs of the edge packages, once, at launch:
#
#   OpenWrt usign (Ed25519)  signs the opkg indexes (Packages.sig)
#   OpenWrt apk (EC P-256)   signs the .apk packages and packages.adb
#   OPNsense pkg (RSA 4096)  signs the FreeBSD pkg repository
#
#   deploy/pkg-keygen.sh OUTDIR
#
# The private keys are written to OUTDIR only (mode 0600, OUTDIR must be
# outside the repository and must not exist yet); they are never printed.
# The public keys are copied into the repository, the installers' pins
# (USIGN_FP, APK_KEY_SHA256, KEY_SHA256) are updated, and the script prints
# the commands that store the private keys as GitHub secrets. Delete OUTDIR
# afterwards (keep an offline backup if you want one).
#
# Needs Go and OpenSSL. NO_REPO=1: only create the keys and print the pins.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd -P)
out=${1:?usage: $0 OUTDIR (outside the repository, must not exist)}
[ ! -e "$out" ] || { echo "$out already exists: refusing to overwrite keys" >&2; exit 1; }
umask 077
mkdir -p "$out"
out=$(cd "$out" && pwd -P)
case $out/ in "$repo"/*)
  rmdir "$out"
  echo "OUTDIR must be outside the repository ($repo)" >&2; exit 1 ;;
esac
command -v openssl >/dev/null || { echo "openssl is needed" >&2; exit 1; }
command -v go >/dev/null || { echo "go is needed" >&2; exit 1; }
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

# OpenWrt usign.
(cd "$repo" && go run ./packaging/openwrt/owrtpkg keygen \
  -sec "$out/openwrt-usign.sec" -pub "$out/usign.pub" -c "InfraFence OpenWrt feed")
usign_fp=$(cd "$repo" && go run ./packaging/openwrt/owrtpkg fingerprint -pub "$out/usign.pub")
# OpenWrt apk.
openssl ecparam -name prime256v1 -genkey -noout -out "$out/openwrt-apk.sec" 2>/dev/null
openssl ec -in "$out/openwrt-apk.sec" -pubout -out "$out/apk.pem" 2>/dev/null
# OPNsense pkg repository.
openssl genrsa -out "$out/opnsense-repo.key" 4096 2>/dev/null
openssl rsa -in "$out/opnsense-repo.key" -pubout -out "$out/infrafence-repo.pub" 2>/dev/null
chmod 0600 "$out"/*.sec "$out"/*.key
chmod 0644 "$out"/*.pub "$out"/*.pem
apk_sha=$(sha256 "$out/apk.pem")
repo_sha=$(sha256 "$out/infrafence-repo.pub")

pin() { # file var value: set VAR="..." on its own line
  local f=$1
  [ -f "$f" ] || return 1
  grep -q "^$2=" "$f" || { echo "no $2= line in $f" >&2; return 1; }
  sed "s|^$2=.*|$2=\"$3\"|" "$f" >"$f.tmp" && cat "$f.tmp" >"$f" && rm -f "$f.tmp"
}

if [ "${NO_REPO:-}" != 1 ]; then
  umask 022
  mkdir -p "$repo/packaging/openwrt/keys"
  cp "$out/usign.pub" "$out/apk.pem" "$repo/packaging/openwrt/keys/"
  pin "$repo/packaging/openwrt/router-install.sh" USIGN_FP "$usign_fp"
  pin "$repo/packaging/openwrt/router-install.sh" APK_KEY_SHA256 "$apk_sha"
  if [ -d "$repo/packaging/opnsense" ]; then
    cp "$out/infrafence-repo.pub" "$repo/packaging/opnsense/"
    pin "$repo/packaging/opnsense/opnsense-install.sh" KEY_SHA256 "$repo_sha"
    opn_note="packaging/opnsense/infrafence-repo.pub, KEY_SHA256 in packaging/opnsense/opnsense-install.sh"
  else
    opn_note="packaging/opnsense/ is not in this checkout: copy $out/infrafence-repo.pub there and set KEY_SHA256 by hand"
  fi
fi

cat <<EOF

Keys created in $out (private keys mode 0600, not printed).

Public, into the repository${NO_REPO:+ (NO_REPO=1: not done, copy them by hand)}:
  packaging/openwrt/keys/usign.pub        usign fingerprint   USIGN_FP=$usign_fp
  packaging/openwrt/keys/apk.pem          sha256              APK_KEY_SHA256=$apk_sha
  packaging/opnsense/infrafence-repo.pub  sha256              KEY_SHA256=$repo_sha
  ${opn_note:-}

Private, as secrets of the GitHub environment "release" (then delete $out):
  gh secret set OPENWRT_USIGN_KEY --env release --repo infrafence/infrafence-agent < "$out/openwrt-usign.sec"
  gh secret set OPENWRT_APK_KEY   --env release --repo infrafence/infrafence-agent < "$out/openwrt-apk.sec"
  gh secret set OPNSENSE_REPO_KEY --env release --repo infrafence/infrafence-agent < "$out/opnsense-repo.key"

Server (pinned keys checked by pkg-publish.sh), root-owned, mode 0644:
  /etc/infrafence/pkg-keys/usign.pub, apk.pem, infrafence-repo.pub   (the three public files above)
EOF
