#!/usr/bin/env bash
# Runs internal/firewall integration tests against real iptables (nf_tables
# and legacy backends, with and without ipset) in disposable privileged
# containers. Needs Docker. Nothing on the host firewall is touched.
set -euo pipefail
cd "$(dirname "$0")/.."

arch=$(docker info --format '{{.Architecture}}')
case "$arch" in aarch64|arm64) goarch=arm64 ;; *) goarch=amd64 ;; esac
bin=$(mktemp -d)/fw.test
GOOS=linux GOARCH=$goarch go test -c -tags integration -o "$bin" ./internal/firewall

status=0
for backend in nft legacy; do
  for ipset in yes no; do
    echo "=== backend=$backend ipset=$ipset"
    pkgs="iptables iproute2"
    [ "$ipset" = yes ] && pkgs="$pkgs ipset"
    if ! docker run --rm --privileged -v "$bin:/fw.test:ro" debian:12 bash -c "
      set -e
      apt-get update -qq >/dev/null && apt-get install -y -qq $pkgs >/dev/null 2>&1
      update-alternatives --set iptables /usr/sbin/iptables-$backend >/dev/null
      ip netns add cl
      ip link add veth0 type veth peer name veth1
      ip link set veth1 netns cl
      ip addr add 203.0.113.1/24 dev veth0 && ip link set veth0 up
      ip netns exec cl ip addr add 203.0.113.2/24 dev veth1
      ip netns exec cl ip link set veth1 up
      ip netns exec cl ip link set lo up
      INFRAFENCE_FW_IT=1 /fw.test -test.v -test.run TestFirewallIntegration
    "; then
      status=1
    fi
  done
done
exit $status
