#!/usr/bin/env bash
# OPNsense soak test on a remote Docker host, over SSH.
#
#   test/opnsense/soak-remote.sh TARGET start [DAYS]   prepare, upload, start (default 7 days)
#   test/opnsense/soak-remote.sh TARGET status         container state, last health lines
#   test/opnsense/soak-remote.sh TARGET stop           stop and remove the container (data kept)
#   test/opnsense/soak-remote.sh TARGET cleanup        stop, remove the image and the soak directory
#
# TARGET is an SSH destination (root@host) or "local" (this machine's
# Docker, for a test run). Everything the soak needs is built or downloaded
# HERE and uploaded: the remote host builds and downloads nothing.
#
# On the remote host the soak only ever touches:
#   - the container "infrafence-opnsense-soak" and the image
#     "infrafence-opnsense-soak:1" (both labelled org.infrafence.soak)
#   - the directory SOAK_DIR (default /srv/opnsense-soak, marked by a
#     .infrafence-opnsense-soak file; cleanup refuses a directory without it)
# The container has no network at all (--network none): the OPNsense VM uses
# QEMU's user-mode networking to reach a mock dashboard and a file server on
# the container's own loopback, and nothing else (no Internet, no host
# network, no published ports, no Docker network, no iptables rule). Hard
# limits: --cpus=3, --memory=6g (no swap), the OOM killer picks it first,
# nice 19 and idle I/O class, read-only root, no capabilities.
#
# Environment: SOAK_DIR, OPN_IMG (local nano image .img.bz2; downloaded and
# checked against the pinned SHA-256 when unset), SOAK_TICK_SECONDS (600),
# SOAK_VM_MEM (4096), SOAK_REBOOT_HOURS (24), SOAK_RELOAD_HOURS (6),
# SOAK_CPUS (3), SOAK_MEMORY (6g), AGENT_VERSION; for a short test run
# SOAK_MINUTES and SOAK_REBOOT_MINUTES override the days and hours.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
TARGET=${1:-}
CMD=${2:-}
[ -n "$TARGET" ] && [ -n "$CMD" ] || { sed -n '2,8p' "$0" >&2; exit 2; }
DAYS=${3:-7}
case $DAYS in *[!0-9]*|"") echo "DAYS must be a number" >&2; exit 2 ;; esac
NAME=infrafence-opnsense-soak
IMAGE=infrafence-opnsense-soak:1
SOAK_DIR=${SOAK_DIR:-/srv/opnsense-soak}
case $SOAK_DIR in /*) ;; *) echo "SOAK_DIR must be absolute" >&2; exit 2 ;; esac
case $SOAK_DIR in /|/srv|/home|/root|/var|/var/lib|/var/lib/docker*|/etc*|/usr*) echo "refusing SOAK_DIR=$SOAK_DIR" >&2; exit 2 ;; esac
OPN_SHA256=28d5e2f37e40d87468a924e3006ef10e2ddc6de485b85333d9e3958c84d0cb9d
OPN_URL=https://pkg.opnsense.org/releases/26.7/OPNsense-26.7-nano-amd64.img.bz2
ET_URL=https://rules.emergingthreats.net/open/suricata-8.0/emerging.rules.tar.gz
CACHE=${SOAK_CACHE:-$HOME/.cache/infrafence-opnsense-soak}

# rsh SCRIPT ARGS...: run a bash script on the target, as root (sudo if needed).
rsh() {
	local script=$1; shift
	if [ "$TARGET" = local ]; then
		bash -s -- "$@" <<< "$script"
	else
		# ssh joins its arguments into one command line: quote them.
		local args
		args=$(printf '%q ' "$@")
		# shellcheck disable=SC2029
		ssh -o BatchMode=yes "$TARGET" "if [ \"\$(id -u)\" = 0 ]; then exec bash -s -- $args; else exec sudo bash -s -- $args; fi" <<< "$script"
	fi
}
upload() { # upload SRC DEST_DIR
	if [ "$TARGET" = local ]; then
		cp -R "$1" "$2/"
	else
		rsync -a --partial --progress "$1" "$TARGET:$2/" || scp -q "$1" "$TARGET:$2/"
	fi
}

REMOTE_LIB='
set -euo pipefail
NAME=infrafence-opnsense-soak
IMAGE=infrafence-opnsense-soak:1
exists() { docker container inspect "$NAME" > /dev/null 2>&1; }
labelled() { [ "$(docker container inspect -f "{{index .Config.Labels \"org.infrafence.soak\"}}" "$NAME" 2> /dev/null)" = opnsense ]; }
'

preflight() {
	rsh "$REMOTE_LIB"'
	D=$1
	echo "host: $(hostname) $(uname -m), $(getconf _NPROCESSORS_ONLN) CPUs, $(awk "/MemAvailable/ {printf \"%d MB available\", \$2/1024}" /proc/meminfo 2>/dev/null || echo "memory ?")"
	command -v docker > /dev/null || { echo "docker not found" >&2; exit 1; }
	docker info --format "docker {{.ServerVersion}}, cgroup v{{.CgroupVersion}}" || exit 1
	if exists; then
		labelled || { echo "a container named $NAME exists and is not ours: refusing" >&2; exit 1; }
		echo "the soak container already exists (use status, or stop first)" >&2; exit 1
	fi
	p=$D; while [ ! -d "$p" ]; do p=$(dirname "$p"); done
	free=$(df -Pm "$p" | awk "NR==2 {print \$4}")
	echo "free disk at $p: $free MB"
	[ "$free" -ge 15000 ] || { echo "less than 15 GB free at $p" >&2; exit 1; }
	if [ -d "$D" ] && [ ! -e "$D/.infrafence-opnsense-soak" ] && [ -n "$(ls -A "$D")" ]; then
		echo "$D exists, is not empty and is not a soak directory: refusing" >&2; exit 1
	fi
	mkdir -p "$D/payload"
	touch "$D/.infrafence-opnsense-soak"
	# Through sudo: the SSH user uploads into it.
	if [ -n "${SUDO_USER:-}" ]; then chown "$SUDO_USER" "$D" "$D/payload"; fi
	uname -m
	' "$SOAK_DIR" | tee /dev/stderr | tail -1
}

stage() { # stage STAGEDIR ARCH(docker platform arch)
	local st=$1 arch=$2
	mkdir -p "$CACHE" "$st"
	if [ -z "${OPN_IMG:-}" ]; then
		OPN_IMG=$CACHE/OPNsense-26.7-nano-amd64.img.bz2
		if [ ! -f "$OPN_IMG" ]; then
			curl -fL -o "$OPN_IMG.part" "$OPN_URL"
			mv "$OPN_IMG.part" "$OPN_IMG"
		fi
	fi
	echo "$OPN_SHA256  $OPN_IMG" | shasum -a 256 -c - > /dev/null || { echo "OPNsense image checksum mismatch" >&2; exit 1; }
	if [ ! -f "$CACHE/emerging.rules.tar.gz" ] || [ -z "$(find "$CACHE/emerging.rules.tar.gz" -mtime -2)" ]; then
		curl -fsS -o "$CACHE/emerging.rules.tar.gz" "$ET_URL"
	fi
	tar -tzf "$CACHE/emerging.rules.tar.gz" rules/emerging-attack_response.rules > /dev/null
	(cd "$repo" && CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.version=${AGENT_VERSION:-1.0.44}" -o "$st/infrafence-agent" ./cmd/infrafence-agent)
	(cd "$repo" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -o "$st/mockapi" ./test/distro/mockapi)
	# No extended attributes (macOS adds them; FreeBSD tar refuses them).
	COPYFILE_DISABLE=1 tar --no-xattrs -C "$repo/packaging" -cf "$st/packaging.tar" opnsense
	cp "$here/console.py" "$here/soak-inside.sh" "$here/soak-vm-health.sh" "$here/soak-vm-workload.sh" "$st/"
	cp "$OPN_IMG" "$st/opnsense.img.bz2"
	cp "$CACHE/emerging.rules.tar.gz" "$st/"
	chmod 755 "$st"/*.sh "$st/console.py" "$st/infrafence-agent" "$st/mockapi"
	docker build -q --platform "linux/$arch" -t "$IMAGE" -f "$here/Dockerfile" "$here" > /dev/null
	[ "$TARGET" = local ] || docker save "$IMAGE" | gzip > "$st/image.tar.gz"
}

case $CMD in
start)
	echo "== preflight on $TARGET"
	harch=$(preflight)
	case $harch in x86_64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) echo "unsupported host arch $harch" >&2; exit 1 ;; esac
	st=$(mktemp -d)
	trap 'rm -rf "$st"' EXIT
	echo "== building and staging ($arch)"
	stage "$st" "$arch"
	echo "== uploading to $TARGET:$SOAK_DIR/payload"
	for f in "$st"/*; do
		[ "$(basename "$f")" = image.tar.gz ] && continue
		upload "$f" "$SOAK_DIR/payload"
	done
	if [ "$TARGET" != local ]; then
		upload "$st/image.tar.gz" "$SOAK_DIR"
		rsh "$REMOTE_LIB"'docker load -q -i "$1/image.tar.gz" && rm -f "$1/image.tar.gz"' "$SOAK_DIR"
	fi
	echo "== starting the soak container ($DAYS days)"
	rsh "$REMOTE_LIB"'
	D=$1
	# The container runs as root without capabilities: it can only write
	# into a directory root owns (uploads through sudo left it to the user).
	[ "$(uname -s)" = Linux ] && chown root "$D"
	docker run -d --name "$NAME" --label org.infrafence.soak=opnsense \
		--network none \
		--cpus "$3" --memory "$4" --memory-swap "$4" --oom-score-adj 1000 --pids-limit 512 \
		--read-only --tmpfs /tmp:rw,size=256m --cap-drop ALL --security-opt no-new-privileges \
		--restart unless-stopped --log-opt max-size=10m --log-opt max-file=3 \
		-e SOAK_DAYS="$2" -e SOAK_TICK_SECONDS="$5" -e SOAK_VM_MEM="$6" -e SOAK_REBOOT_HOURS="$7" -e SOAK_RELOAD_HOURS="$8" -e AGENT_VERSION="$9" -e SOAK_MINUTES="${10}" -e SOAK_REBOOT_MINUTES="${11}" \
		-v "$D:/work" -v "$D/payload:/opt/soak:ro" \
		"$IMAGE" /opt/soak/soak-inside.sh > /dev/null
	docker ps --filter "name=^${NAME}$" --format "{{.Names}}  {{.Status}}"
	' "$SOAK_DIR" "$DAYS" "${SOAK_CPUS:-3}" "${SOAK_MEMORY:-6g}" "${SOAK_TICK_SECONDS:-600}" "${SOAK_VM_MEM:-4096}" "${SOAK_REBOOT_HOURS:-24}" "${SOAK_RELOAD_HOURS:-6}" "${AGENT_VERSION:-1.0.44}" "${SOAK_MINUTES:-0}" "${SOAK_REBOOT_MINUTES:-0}"
	echo "started: health in $SOAK_DIR/health.log (every ${SOAK_TICK_SECONDS:-600} s); first boot and install take about 30-60 min under emulation"
	;;
status)
	rsh "$REMOTE_LIB"'
	D=$1
	docker ps -a --filter "name=^${NAME}$" --format "{{.Names}}  {{.Status}}" | grep . || echo "no soak container"
	docker stats --no-stream --format "cpu {{.CPUPerc}}  memory {{.MemUsage}}" "$NAME" 2> /dev/null || true
	[ -e "$D/done" ] && echo "soak finished"
	echo "--- soak.log"; tail -n 8 "$D/logs/soak.log" 2> /dev/null || true
	echo "--- health.log ($(cat "$D/health.log" 2> /dev/null | wc -l | tr -d " ") lines)"; tail -n 3 "$D/health.log" 2> /dev/null || true
	' "$SOAK_DIR"
	;;
stop)
	rsh "$REMOTE_LIB"'
	if exists; then
		labelled || { echo "$NAME is not ours: refusing" >&2; exit 1; }
		docker stop -t 240 "$NAME" > /dev/null && docker rm "$NAME" > /dev/null && echo "stopped and removed $NAME (data kept in $1)"
	else
		echo "no soak container"
	fi
	' "$SOAK_DIR"
	;;
cleanup)
	rsh "$REMOTE_LIB"'
	D=$1
	if exists; then
		labelled || { echo "$NAME is not ours: refusing" >&2; exit 1; }
		docker stop -t 240 "$NAME" > /dev/null; docker rm "$NAME" > /dev/null
	fi
	if docker image inspect "$IMAGE" > /dev/null 2>&1; then docker rmi "$IMAGE" > /dev/null && echo "removed image $IMAGE"; fi
	if [ -d "$D" ]; then
		[ -e "$D/.infrafence-opnsense-soak" ] || { echo "$D is not a soak directory: not removed" >&2; exit 1; }
		rm -rf -- "$D" && echo "removed $D"
	fi
	' "$SOAK_DIR"
	;;
*)
	echo "unknown command $CMD (start, status, stop, cleanup)" >&2
	exit 2
	;;
esac
