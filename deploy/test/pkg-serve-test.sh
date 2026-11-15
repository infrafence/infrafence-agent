#!/usr/bin/env bash
# shellcheck disable=SC2015,SC2016 # "test && ok || ko"; publisher scripts run in the container
# Serves what pkg-publish.sh publishes through a container set up like the
# live one (nginx:1.27-alpine, read-only, the web root bind-mounted
# read-only at /usr/share/nginx/html, the default.conf the coordinator
# described plus deploy/nginx-pkg-additions.conf) and checks that a new
# release and a rollback are served at once, without restarting nginx.
#
# Layouts:
#   outside+mount  releases in a sibling directory, also bind-mounted read-only
#                  at the same path in the container (recommended)
#   inside         releases in WEB/.releases (one bind mount, as today)
#   outside-only   releases outside, NOT mounted: shows the links do not resolve
#
#   deploy/test/pkg-serve-test.sh       (needs Docker and curl)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
deploy=$(cd "$here/.." && pwd)
img=infrafence-pkg-publish-test
docker build -q -t "$img" - >/dev/null <<'EOF'
FROM python:3.13-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssl && rm -rf /var/lib/apt/lists/*
EOF
docker pull -q nginx:1.27-alpine >/dev/null

base=$(mktemp -d)
base=$(cd "$base" && pwd -P)
cids=()
cleanup() {
  for c in "${cids[@]}"; do docker rm -f "$c" >/dev/null 2>&1 || true; done
  # Files written by the publish container may be root-owned on Linux.
  docker run --rm -v "$base:$base" "$img" rm -rf -- "$base/srv" >/dev/null 2>&1 || true
  rm -rf -- "$base"
}
trap cleanup EXIT
pass=0 fail=0
ok() { pass=$((pass + 1)); echo "ok   $*"; }
ko() { fail=$((fail + 1)); echo "FAIL $*"; }

# The live config as described (root, autoindex off, dotfiles denied,
# try_files), with the additions inserted after the dotfile rule.
cat >"$base/default.conf" <<EOF
server {
    listen 80;
    server_name pkg.infrafence.com;
    root /usr/share/nginx/html;
    index index.html;
    autoindex off;
    location ~ /\. { deny all; }
$(cat "$deploy/nginx-pkg-additions.conf")
    location / { try_files \$uri \$uri/ =404; }
}
EOF

# Runs bash commands in the publisher's container with the fixture helpers.
publisher() { # web releases commands
  docker run --rm -v "$deploy:/deploy:ro" -v "$base:$base" \
    -e work="$base/srv/keys" -e PKG_KEYS_DIR="$base/srv/pinned" -e PKG_WWW="$1" -e PKG_RELEASES="$2" \
    "$img" bash -euo pipefail -c ". /deploy/test/lib.sh; $3"
}
get() { # port path -> status body
  curl -s -o "$base/body" -w '%{http_code}' "http://127.0.0.1:$1$2" || true
}
header() { # port path name
  curl -s -D - -o /dev/null "http://127.0.0.1:$1$2" | tr -d '\r' | awk -v h="$2" -v n="$3" 'tolower($1) == tolower(n) ":" {sub(/^[^:]*: /, ""); print}'
}

scenario() { # name web releases extra-mount(yes/no)
  local name=$1 web=$2 rel=$3 mount=$4 port cid
  echo "=== $name"
  docker run --rm -v "$base:$base" "$img" rm -rf -- "$base/srv" >/dev/null 2>&1 || true
  mkdir -p "$base/srv/keys" "$base/srv/pinned" "$web" "$rel"
  local -a mounts=(-v "$web:/usr/share/nginx/html:ro")
  [ "$mount" = yes ] && mounts+=(-v "$rel:$rel:ro")
  cid=$(docker run -d --read-only --tmpfs /var/cache/nginx --tmpfs /var/run --tmpfs /tmp \
    "${mounts[@]}" -v "$base/default.conf:/etc/nginx/conf.d/default.conf:ro" -p 127.0.0.1::80 nginx:1.27-alpine)
  cids+=("$cid")
  port=$(docker port "$cid" 80/tcp | head -n1 | sed 's/.*://')
  for _ in $(seq 50); do [ "$(get "$port" /nope)" = 404 ] && break; sleep 0.2; done

  publisher "$web" "$rel" '
    make_keys
    d=$(mktemp -d)
    openwrt_tree "$d" 1.0.1 x86_64 mipsel_24kc
    tar -C "$d" -czf "$d/ow.tgz" openwrt
    bash /deploy/pkg-publish.sh publish openwrt 1.0.1 < "$d/ow.tgz" >/dev/null
    site_tree "$d"
    (cd "$d/site" && sha256sum index.html router-install.sh) > "$PKG_KEYS_DIR/site.sha256"
    tar -C "$d" -czf "$d/site.tgz" site
    bash /deploy/pkg-publish.sh publish site 1.0.1 < "$d/site.tgz" >/dev/null'

  if [ "$name" = outside-only ]; then
    [ "$(get "$port" /openwrt/24.10/x86_64/Packages)" = 404 ] &&
      ok "$name: as expected, the release links do not resolve without the releases mount" ||
      ko "$name: served without the releases mount?"
    return
  fi

  [ "$(get "$port" /openwrt/24.10/x86_64/Packages)" = 200 ] && grep -q 'Version: 1.0.1-r1' "$base/body" &&
    ok "$name: 1.0.1 index served" || ko "$name: 1.0.1 index"
  [ "$(header "$port" /openwrt/24.10/x86_64/Packages Cache-Control)" = no-cache ] &&
    ok "$name: index is no-cache" || ko "$name: index Cache-Control"
  [ "$(header "$port" /openwrt/24.10/x86_64/infrafence-router_1.0.1-r1_x86_64.ipk Content-Type)" = application/octet-stream ] &&
    ok "$name: .ipk is application/octet-stream" || ko "$name: .ipk Content-Type"
  [ "$(header "$port" /openwrt/25.12/x86_64/infrafence-router-1.0.1-r1.apk Content-Type)" = application/octet-stream ] &&
    ok "$name: .apk is application/octet-stream (not the Android type)" || ko "$name: .apk Content-Type"
  [ "$(get "$port" /)" = 200 ] && [ "$(get "$port" /keys/usign.pub)" = 200 ] &&
    [ "$(header "$port" /router-install.sh Content-Type)" = "text/plain; charset=utf-8" ] &&
    ok "$name: index page, keys and installer served" || ko "$name: site"
  [ "$(get "$port" /openwrt/)" = 403 ] && ok "$name: no directory listing" || ko "$name: listing"
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$port/openwrt/24.10/x86_64/Packages")
  [ "$code" = 405 ] && ok "$name: POST refused" || ko "$name: POST $code"

  sleep 1
  publisher "$web" "$rel" '
    d=$(mktemp -d)
    openwrt_tree "$d" 1.0.2 x86_64 mipsel_24kc
    tar -C "$d" -czf "$d/ow.tgz" openwrt
    bash /deploy/pkg-publish.sh publish openwrt 1.0.2 < "$d/ow.tgz" >/dev/null'
  [ "$(get "$port" /openwrt/24.10/x86_64/Packages)" = 200 ] && grep -q 'Version: 1.0.2-r1' "$base/body" &&
    ok "$name: 1.0.2 served at once, nginx not restarted" || ko "$name: 1.0.2 not served"
  [ "$(get "$port" /openwrt/24.10/x86_64/infrafence-router_1.0.1-r1_x86_64.ipk)" = 200 ] &&
    ok "$name: previous package still downloadable" || ko "$name: carried package"
  publisher "$web" "$rel" 'bash /deploy/pkg-publish.sh rollback openwrt >/dev/null'
  [ "$(get "$port" /openwrt/24.10/x86_64/Packages)" = 200 ] && grep -q 'Version: 1.0.1-r1' "$base/body" &&
    ok "$name: rollback served at once" || ko "$name: rollback"
  [ "$(docker inspect -f '{{.State.StartedAt}} {{.RestartCount}}' "$cid" | awk '{print $2}')" = 0 ] &&
    ok "$name: same nginx process throughout" || ko "$name: restarted"

  # Nothing of the publisher's state is reachable over HTTP.
  local leaked=0 p
  for p in /.releases/ /.releases/openwrt/ /.openwrt.new /.lock /site/../.releases/; do
    code=$(get "$port" "$p")
    case $code in 403 | 404) ;; *) leaked=1; echo "  $p -> $code" ;; esac
  done
  local id
  id=$(find "$rel/openwrt" -mindepth 1 -maxdepth 1 -type d -name '20*' | head -n1)
  id=${id##*/}
  for p in "/.releases/openwrt/$id/openwrt/24.10/x86_64/Packages" "/$id/openwrt/24.10/x86_64/Packages"; do
    code=$(get "$port" "$p")
    case $code in 403 | 404) ;; *) leaked=1; echo "  $p -> $code" ;; esac
  done
  [ "$leaked" = 0 ] && ok "$name: releases, staging and lock not reachable directly" || ko "$name: publisher state reachable"
}

scenario "outside+mount" "$base/srv/infrafence-pkg" "$base/srv/infrafence-pkg-releases" yes
scenario "inside" "$base/srv/infrafence-pkg" "$base/srv/infrafence-pkg/.releases" no
scenario "outside-only" "$base/srv/infrafence-pkg" "$base/srv/infrafence-pkg-releases" no
echo
echo "passed $pass, failed $fail"
[ "$fail" -eq 0 ]
