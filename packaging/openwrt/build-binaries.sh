#!/usr/bin/env bash
# Builds the router agent for every OpenWrt architecture it supports.
# Usage: packaging/openwrt/build-binaries.sh OUTDIR VERSION
# Output: OUTDIR/infrafence-router-linux-{mips,mipsle,arm,arm64,amd64}
set -euo pipefail
cd "$(dirname "$0")/../.."
out=${1:?output directory}
ver=${2:?version}
mkdir -p "$out"
# GOARCH|extra env: MIPS without an FPU needs softfloat (most router SoCs
# have none and the kernel's FPU emulation is slow or missing).
for t in "mips|GOMIPS=softfloat" "mipsle|GOMIPS=softfloat" "arm|GOARM=7" "arm64|" "amd64|"; do
  arch=${t%%|*}; extra=${t#*|}
  env CGO_ENABLED=0 GOOS=linux GOARCH="$arch" $extra go build -trimpath \
    -ldflags "-s -w -buildid= -X main.version=$ver" \
    -o "$out/infrafence-router-linux-$arch" ./cmd/infrafence-router
done
ls -l "$out"
