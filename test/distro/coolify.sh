# Sourced by inside.sh: the domains of a Coolify server. A fake Docker
# (Podman) API on /run/podman/podman.sock lists coolify-proxy (Traefik) and
# two applications, one with Coolify's Traefik labels and one with its Caddy
# labels. After a restart the heartbeat must report their domains as
# {"domain","source","verify":"dns"} objects (never the HostRegexp one),
# and a trust badge for one of them must be reported dns_only, with no
# verification file anywhere. The socket is removed and the agent restarted
# afterwards. Adds "coolify=..." to EXTRA_RESULT and sets EXTRA_FAIL on a
# failure.

R_COOLIFY=fail
capi=http://127.0.0.1:8080
csock=/run/podman/podman.sock
clog() { log "coolify: $*"; }
chb() { curl -s "$capi/state" | grep -o '"last_heartbeat":{.*' | head -c 60000; }
chbs() { curl -s "$capi/state" | grep -o '"heartbeats":[0-9]*' | cut -d: -f2; }

mkdir -p /run/podman
/distro/mockapi -docker-sock "$csock" >/tmp/mockdocker.log 2>&1 &
cpid=$!
for _ in $(seq 1 20); do [ -S "$csock" ] && break; sleep 0.5; done
systemctl restart infrafence-agent
base=$(chbs)
hb=""
for _ in $(seq 1 150); do
  [ "$(chbs)" -gt "$base" ] 2>/dev/null && { hb=$(chb); grep -q 'coolify-e2e' <<<"$hb" && break; }
  sleep 1
done
reported=yes
for want in \
  '{"domain":"blog.coolify-e2e.example.com","source":"caddy","verify":"dns"}' \
  '{"domain":"coolify-e2e.example.com","source":"traefik","verify":"dns"}' \
  '{"domain":"shop.coolify-e2e.example.com","source":"traefik","verify":"dns"}' \
  '{"domain":"www.coolify-e2e.example.com","source":"traefik","verify":"dns"}'; do
  grep -qF "$want" <<<"$hb" || { reported=no; clog "missing in heartbeat: $want"; }
done
grep -q 'preview' <<<"$hb" && { reported=no; clog "HostRegexp domain reported"; }

curl -s -X POST "$capi/set-sync" -d '{"trust_tokens":[{"domain":"shop.coolify-e2e.example.com","token":"ifv_0123456789abcdef0123456789abcdef"}]}' >/dev/null
dnsonly=no
for _ in $(seq 1 120); do
  curl -s "$capi/state" | grep -o '{"type":"trust_token_failed"[^}]*' | grep -F '"domain":"shop.coolify-e2e.example.com"' | grep -qF '"reason":"dns_only"' && { dnsonly=yes; break; }
  sleep 1
done
nofile=yes
find / -xdev -name infrafence-verification.txt 2>/dev/null | grep -q . && { nofile=no; clog "a verification file was written"; }
clog "reported=$reported dns_only=$dnsonly no_file=$nofile"
if [ "$reported$dnsonly$nofile" = yesyesyes ]; then
  R_COOLIFY=ok
else
  grep -o '"monitored_domains":[^]]*]' <<<"$hb" | sed 's/^/[coolify] /'
  journalctl -u infrafence-agent --no-pager | grep -E '\[proxysites\]|\[trust\]|\[docker\]' | tail -10
fi

curl -s -X POST "$capi/set-sync" -d '{"trust_tokens":null}' >/dev/null
kill "$cpid" 2>/dev/null
wait "$cpid" 2>/dev/null
rm -f "$csock"
systemctl restart infrafence-agent

EXTRA_RESULT="${EXTRA_RESULT:-} coolify=$R_COOLIFY"
[ "$R_COOLIFY" = fail ] && EXTRA_FAIL=1
true
