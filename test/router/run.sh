#!/usr/bin/env bash
# End-to-end test of the router agent on real OpenWrt images in QEMU (real
# kernel, procd, fw4/fw3, dnsmasq, opkg/apk), driven over the serial
# console (boot.exp, guest.sh):
#
#   install from a signed test feed through router-install.sh, register
#   against the mock dashboard (test/distro/mockapi), receive bans, C2 and
#   domain lists in Learning mode, a LAN device (network namespace on
#   br-lan) reaching a C2 address and looking up listed domains, switch to
#   Full protection (drops, dnsmasq NXDOMAIN), firewall reload, ruleset
#   flush (watchdog), reboot, clean uninstall.
#
# Needs Docker (QEMU runs in a container, nothing touches the host) and Go.
# Usage: test/router/run.sh [target...]   (default: all)
# Images are cached in $CACHE (default ~/.cache/infrafence-router-test).
set -uo pipefail
cd "$(dirname "$0")/../.."
repo=$(pwd)

# target | release | kind | image file (under releases/<release>/targets/...) | package arch
MATRIX="
x86-24.10|24.10.8|x86|x86/64/openwrt-24.10.8-x86-64-generic-ext4-combined.img.gz|x86_64
x86-25.12|25.12.6|x86|x86/64/openwrt-25.12.6-x86-64-generic-ext4-combined.img.gz|x86_64
malta-le-24.10|24.10.8|malta|malta/le/openwrt-24.10.8-malta-le-rootfs-ext4.img.gz|mipsel_24kc
x86-21.02-fw3|21.02.7|x86|x86/64/openwrt-21.02.7-x86-64-generic-ext4-combined.img.gz|x86_64
"
CACHE=${CACHE:-$HOME/.cache/infrafence-router-test}
mkdir -p "$CACHE"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

arch=$(docker info --format '{{.Architecture}}')
case "$arch" in aarch64|arm64) hostarch=arm64 ;; *) hostarch=amd64 ;; esac
version=$(git describe --tags --always 2>/dev/null | sed 's/^v//')
case $version in [0-9]*) ;; *) version=0.0.0-$version ;; esac

echo "=== build"
packaging/openwrt/build-binaries.sh "$work/bin" "${version%%-*}-test" >/dev/null || exit 1
rm -f "$work/bin/infrafence-router-linux-"{mips,arm,arm64}
CGO_ENABLED=0 GOOS=linux GOARCH=$hostarch go build -o "$work/mockapi" ./test/distro/mockapi || exit 1
go build -o "$work/owrtpkg" ./packaging/openwrt/owrtpkg || exit 1
mkdir -p "$work/keys"
"$work/owrtpkg" keygen -sec "$work/keys/usign.sec" -pub "$work/keys/usign.pub" -c "InfraFence TEST feed"
openssl ecparam -name prime256v1 -genkey -noout -out "$work/keys/apk.sec" 2>/dev/null
openssl ec -in "$work/keys/apk.sec" -pubout -out "$work/keys/apk.pub" 2>/dev/null
USIGN_SEC=$work/keys/usign.sec USIGN_PUB=$work/keys/usign.pub APK_SEC=$work/keys/apk.sec APK_PUB=$work/keys/apk.pub \
  ARCHES="x86_64 mipsel_24kc" packaging/openwrt/build-packages.sh "$work/bin" "${version%%-*}-test" "$work/feed" | tail -1 || exit 1
cp packaging/openwrt/router-install.sh test/router/guest.sh "$work/feed/"
cp test/router/boot.exp "$work/"
docker build -q -t infrafence-router-qemu test/router >/dev/null || exit 1

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
fetch() { # release path: download once into $CACHE, checked against OpenWrt's sha256sums
  local f="$CACHE/$(basename "$2")" dir sums want
  dir=$(dirname "$2")
  sums="$CACHE/sha256sums-$1-${dir//\//-}"
  [ -s "$sums" ] || curl -fsSL -o "$sums" "https://downloads.openwrt.org/releases/$1/targets/$dir/sha256sums" || return 1
  want=$(grep " \*\{0,1\}$(basename "$2")\$" "$sums" | cut -d' ' -f1)
  if [ ! -s "$f" ] || [ "$(sha256 "$f")" != "$want" ]; then
    curl -fsSL -o "$f.part" "https://downloads.openwrt.org/releases/$1/targets/$2" || return 1
    mv "$f.part" "$f"
  fi
  [ -n "$want" ] && [ "$(sha256 "$f")" = "$want" ] || { echo "checksum mismatch: $f" >&2; return 1; }
  echo "$f"
}

kvm=()
[ -e /dev/kvm ] && [ "$hostarch" = amd64 ] && kvm=(--device /dev/kvm)
want=("$@")
results=()
status=0
while IFS='|' read -r name rel kind img parch; do
  [ -z "$name" ] && continue
  if [ ${#want[@]} -gt 0 ] && [[ ! " ${want[*]} " == *" $name "* ]]; then continue; fi
  echo "=== $name"
  image=$(fetch "$rel" "$img") || { results+=("RESULT target=$name download=fail"); status=1; continue; }
  if [ "$kind" = malta ]; then
    kernel=$(fetch "$rel" "malta/le/openwrt-$rel-malta-le-vmlinux.elf") || { results+=("RESULT target=$name download=fail"); status=1; continue; }
    qemu="qemu-system-mipsel -M malta -m 256 -nographic -kernel /img/$(basename "$kernel") -drive file=/tmp/disk.img,format=raw -append {root=/dev/sda rootwait console=ttyS0,38400} -nic user,model=pcnet"
  else
    accel=""
    [ ${#kvm[@]} -gt 0 ] && accel="-enable-kvm -cpu host"
    qemu="qemu-system-x86_64 -M pc -m 256 $accel -nographic -drive file=/tmp/disk.img,format=raw,if=virtio -nic user,model=virtio-net-pci"
  fi
  log="$work/$name.log"
  start=$(date +%s)
  echo "$qemu" >"$work/$name.qemu"
  docker run --rm ${kvm[@]+"${kvm[@]}"} -v "$work:/work" -v "$CACHE:/img:ro" infrafence-router-qemu bash -c "
    set -e
    # OpenWrt pads its images: gzip warns about trailing garbage (exit 2).
    gunzip -c /img/$(basename "$image") >/tmp/disk.img 2>/dev/null || [ -s /tmp/disk.img ]
    /work/mockapi -addr 127.0.0.1:8080 -binary /work/bin/infrafence-router-linux-amd64 -feed /work/feed >/work/$name.mockapi.log 2>&1 &
    sleep 1
    expect /work/boot.exp $name /work/$name.qemu
  " >"$log" 2>&1
  rc=$?
  secs=$(( $(date +%s) - start ))
  tr -d '\r' <"$log" | grep -E '^(CHECK|RESULT|agent RSS|dnsmasq RSS)' | sed "s/^/  /"
  pass=$(tr -d '\r' <"$log" | grep -c '^CHECK .* PASS')
  fail=$(tr -d '\r' <"$log" | grep -c '^CHECK .* FAIL')
  phases=$(tr -d '\r' <"$log" | grep -c '^RESULT ')
  if [ "$rc" != 0 ] || [ "$fail" != 0 ] || [ "$phases" != 3 ]; then status=1; fi
  results+=("RESULT target=$name pass=$pass fail=$fail phases=$phases/3 exit=$rc time=${secs}s")
  [ -n "${LOGDIR:-}" ] && mkdir -p "$LOGDIR" && cp "$log" "$work/$name.mockapi.log" "$LOGDIR/"
done <<<"$MATRIX"
echo "=== summary"
printf '%s\n' "${results[@]}"
exit $status
