#!/usr/bin/env bash
# Distribution test matrix. For each distribution: a privileged container
# with systemd as PID 1, the packages and logging a default server install
# has (rsyslog only where the distribution installs it), then
# test/distro/inside.sh — real install.sh, SSH brute force from another
# network namespace, detection, firewall ban, blocked connection, clean
# uninstall. Needs Docker. Usage: test/distro/run.sh [distro...]
set -uo pipefail
cd "$(dirname "$0")/../.."

# name | image | package manager | rsyslog in a default server install
MATRIX="
ubuntu-20.04|ubuntu:20.04|apt|yes
ubuntu-22.04|ubuntu:22.04|apt|yes
ubuntu-24.04|ubuntu:24.04|apt|yes
debian-12|debian:12|apt|no
debian-13|debian:13|apt|no
rocky-8|rockylinux/rockylinux:8|dnf|yes
rocky-9|rockylinux/rockylinux:9|dnf|yes
almalinux-8|almalinux:8|dnf|yes
almalinux-9|almalinux:9|dnf|yes
centos-stream-9|quay.io/centos/centos:stream9|dnf|yes
oracle-9|oraclelinux:9|dnf|yes
fedora-41|fedora:41|dnf|no
fedora-42|fedora:42|dnf|no
amazonlinux-2023|amazonlinux:2023|dnf|no
"

# PLATFORM=linux/amd64 tests x86-64 images on an ARM machine (emulated).
if [ -n "${PLATFORM:-}" ]; then
  goarch=${PLATFORM#linux/}
else
  arch=$(docker info --format '{{.Architecture}}')
  case "$arch" in aarch64|arm64) goarch=arm64 ;; *) goarch=amd64 ;; esac
fi
plat=(--platform "linux/$goarch")
work=$(mktemp -d)
version=$(git describe --tags --always 2>/dev/null | sed 's/^v//')
CGO_ENABLED=0 GOOS=linux GOARCH=$goarch go build -ldflags "-s -w -X main.version=${version}-test" -o "$work/agent" ./cmd/infrafence-agent || exit 1
CGO_ENABLED=0 GOOS=linux GOARCH=$goarch go build -o "$work/mockapi" ./test/distro/mockapi || exit 1
cp install.sh test/distro/inside.sh "$work/"

want=("$@")
results=()
status=0
while IFS='|' read -r name image pm rsyslog; do
  [ -z "$name" ] && continue
  if [ ${#want[@]} -gt 0 ] && [[ ! " ${want[*]} " == *" $name "* ]]; then continue; fi
  echo "=== $name ($image, $goarch)"

  if [ "$pm" = apt ]; then
    pkgs="systemd systemd-sysv openssh-server openssh-client iproute2 curl ca-certificates procps"
    [ "$rsyslog" = yes ] && pkgs="$pkgs rsyslog"
    prep="export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq --no-install-recommends $pkgs"
  else
    pkgs="systemd openssh-server openssh-clients iproute procps-ng findutils"
    [ "$rsyslog" = yes ] && pkgs="$pkgs rsyslog"
    prep="(dnf install -y -q --allowerasing $pkgs curl || yum install -y -q $pkgs curl) && (command -v curl || dnf install -y -q curl-minimal)"
  fi
  tag="infrafence-distro:$name-$goarch"
  printf 'FROM %s\nRUN %s >/dev/null 2>&1 && (systemctl enable rsyslog 2>/dev/null || true) && (systemctl mask systemd-logind getty@tty1 console-getty 2>/dev/null || true)\nCMD ["/sbin/init"]\n' \
    "$image" "$prep" >"$work/Dockerfile"
  if ! docker build "${plat[@]}" -q -t "$tag" "$work" >/dev/null 2>"$work/build.err"; then
    echo "image build failed:"; tail -5 "$work/build.err"
    results+=("RESULT distro=$name build=fail"); status=1; continue
  fi

  cid=$(docker run "${plat[@]}" -d --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
        --tmpfs /run --tmpfs /run/lock -v "$work:/distro:ro" "$tag")
  # Wait for systemd.
  for _ in $(seq 1 30); do
    docker exec "$cid" systemctl is-system-running 2>/dev/null | grep -qE 'running|degraded' && break
    sleep 1
  done
  out=$(docker exec -e DISTRO="$name" "$cid" bash /distro/inside.sh 2>&1)
  rc=$?
  echo "$out" | grep -v '^RESULT' | tail -40
  line=$(echo "$out" | grep '^RESULT' | tail -1)
  [ -n "$line" ] || line="RESULT distro=$name error=no-result"
  results+=("$line arch=$goarch")
  [ $rc -eq 0 ] || status=1
  docker rm -f "$cid" >/dev/null
done <<<"$MATRIX"

echo
echo "================ summary ================"
printf '%s\n' "${results[@]}"
exit $status
