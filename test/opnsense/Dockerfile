# Runner for run.sh where QEMU is not installed (macOS): docker-run.sh.
FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
	qemu-system-x86 qemu-utils python3 bzip2 curl ca-certificates \
	&& rm -rf /var/lib/apt/lists/*
