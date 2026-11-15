# QEMU + expect for the OpenWrt end-to-end test (test/router/run.sh).
FROM debian:trixie
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      qemu-system-x86 qemu-system-mips qemu-utils expect ca-certificates curl jq procps >/dev/null \
 && rm -rf /var/lib/apt/lists/*
