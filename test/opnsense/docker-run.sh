#!/usr/bin/env bash
# Runs run.sh in a container (for hosts without QEMU, e.g. macOS). Builds
# the FreeBSD amd64 agent and a mockapi for the container's architecture.
#   test/opnsense/docker-run.sh /path/OPNsense-26.7-nano-amd64.img.bz2 [WORKDIR]
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
img=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
work=${2:-$(mktemp -d)}
mkdir -p "$work/bin"
work=$(cd "$work" && pwd)
arch=$(docker info --format '{{.Architecture}}')
case $arch in aarch64|arm64) garch=arm64 ;; *) garch=amd64 ;; esac
(cd "$repo" && CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.version=${AGENT_VERSION:-1.0.44}" -o "$work/bin/infrafence-agent" ./cmd/infrafence-agent)
(cd "$repo" && CGO_ENABLED=0 GOOS=linux GOARCH=$garch go build -trimpath -o "$work/bin/mockapi" ./test/distro/mockapi)
docker build -q -t infrafence-opnsense-e2e "$here" > /dev/null
docker run --rm --name infrafence-opnsense-e2e \
	-v "$repo:/src:ro" -v "$img:/img/$(basename "$img"):ro" -v "$work:/work" \
	-e OPN_IMG="/img/$(basename "$img")" -e AGENT_BIN=/work/bin/infrafence-agent -e MOCKAPI=/work/bin/mockapi \
	-e AGENT_VERSION="${AGENT_VERSION:-1.0.44}" -e HOLD="${HOLD:-}" -e OPN_MEM="${OPN_MEM:-2048}" \
	infrafence-opnsense-e2e /src/test/opnsense/run.sh /work
