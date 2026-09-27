#!/usr/bin/env bash
# Hardening fixes against real sshd, nginx and Apache in throwaway containers.
set -euo pipefail
cd "$(dirname "$0")/.."

GOARCH=$(docker version --format '{{.Server.Arch}}')
CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH" go test -tags integration -c -o /tmp/remediation.test ./internal/remediation/

images=("$@")
[ ${#images[@]} -eq 0 ] && images=(debian:12 ubuntu:24.04)
for img in "${images[@]}"; do
  {
    echo "=== $img"
    docker run --rm -v /tmp/remediation.test:/remediation.test:ro "$img" bash -c '
      set -e
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -qq >/dev/null
      apt-get install -y -qq openssh-server nginx apache2 >/dev/null 2>&1
      sed -i "s/^Listen 80$/Listen 8080/" /etc/apache2/ports.conf
      mkdir -p /run/sshd
      service ssh start >/dev/null; service nginx start >/dev/null; service apache2 start >/dev/null
      REMEDIATION_INTEGRATION=1 /remediation.test -test.v -test.run TestRealHost
    '
  }
done
