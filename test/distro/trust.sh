# Sourced by inside.sh: the trust badge verification file. nginx with one
# site (server_name trust.example.test) and one wildcard site; the mock
# dashboard lists both domains in trust_tokens. The file must be served for
# the exact name with the site's owner and mode 0644, the wildcard must be
# refused (no_document_root), and the file and the .well-known created for
# it must go once the domain is no longer listed. nginx is removed again
# afterwards (waf.sh needs port 80 for Apache). Adds "trust=..." to
# EXTRA_RESULT and sets EXTRA_FAIL on a failure.

R_TRUST=fail
tapi=http://127.0.0.1:8080
ttoken=ifv_0123456789abcdef0123456789abcdef
tfile=/var/www/trust/.well-known/infrafence-verification.txt
tlog() { log "trust: $*"; }
# twait TYPE KEY VALUE SECONDS: an event of TYPE whose details.KEY = VALUE.
twait() {
  for _ in $(seq 1 "$4"); do
    curl -s "$tapi/state" | grep -o "{\"type\":\"$1\"[^}]*" | grep -qF "\"$2\":\"$3\"" && return 0
    sleep 1
  done
  return 1
}
tget() { curl -s -o /dev/null -w '%{http_code}' -H 'Host: trust.example.test' http://localhost/.well-known/infrafence-verification.txt; }

if command -v apt-get >/dev/null; then
  { export DEBIAN_FRONTEND=noninteractive; apt-get update -qq; apt-get install -y -qq --no-install-recommends nginx </dev/null; } >/tmp/trust-pkg.log 2>&1
else
  dnf install -y -q nginx >/tmp/trust-pkg.log 2>&1 || yum install -y -q nginx >>/tmp/trust-pkg.log 2>&1
fi
if command -v nginx >/dev/null; then
  mkdir -p /var/www/trust /var/www/wild
  echo ok >/var/www/trust/index.html
  chown -R 1234:1234 /var/www/trust
  cat >/etc/nginx/conf.d/infrafence-trust-test.conf <<'EOF'
server {
    listen 80;
    server_name trust.example.test;
    root /var/www/trust;
}
server {
    listen 80;
    server_name *.wild.example.test;
    root /var/www/wild;
}
EOF
  systemctl restart nginx >/dev/null 2>&1 || systemctl enable --now nginx >/dev/null 2>&1
  curl -s -H 'Host: trust.example.test' http://localhost/ | grep -qx ok || tlog "nginx does not serve the test site"

  curl -s -X POST "$tapi/set-sync" -d "{\"trust_tokens\":[{\"domain\":\"trust.example.test\",\"token\":\"$ttoken\"},{\"domain\":\"x.wild.example.test\",\"token\":\"$ttoken\"}]}" >/dev/null
  placed=no served=no owner=none wild=no removed=no
  if twait trust_token_placed domain trust.example.test 120; then
    placed=yes
    body=$(curl -s -H 'Host: trust.example.test' http://localhost/.well-known/infrafence-verification.txt)
    grep -qxF "$ttoken" <<<"$body" && head -1 <<<"$body" | grep -qx '# infrafence-verification' && served=yes
    owner="$(stat -c '%u:%g %a' "$tfile" 2>/dev/null) / $(stat -c '%u:%g %a' /var/www/trust/.well-known 2>/dev/null)"
  fi
  twait trust_token_failed reason no_document_root 30 && [ ! -e /var/www/wild/.well-known ] && wild=yes
  tlog "placed=$placed served=$served owner=$owner wildcard_refused=$wild"

  curl -s -X POST "$tapi/set-sync" -d '{"trust_tokens":[]}' >/dev/null
  if twait trust_token_removed domain trust.example.test 120 && [ ! -e /var/www/trust/.well-known ] && [ "$(tget)" = 404 ]; then
    removed=yes
  fi
  tlog "removed=$removed"
  if [ "$placed$served$wild$removed" = yesyesyesyes ] && [ "$owner" = "1234:1234 644 / 1234:1234 755" ]; then
    R_TRUST=ok
  else
    curl -s "$tapi/state" | grep -oE '\{"type":"trust_token[^}]*' | sed 's/^/[trust] event: /'
    journalctl -u infrafence-agent --no-pager | grep '\[trust\]' | tail -10
    ls -la /var/www/trust /var/www/trust/.well-known 2>&1 | sed 's/^/[trust] /'
  fi

  curl -s -X POST "$tapi/set-sync" -d '{"trust_tokens":null}' >/dev/null
  rm -f /etc/nginx/conf.d/infrafence-trust-test.conf
  systemctl disable --now nginx >/dev/null 2>&1
  if command -v apt-get >/dev/null; then
    apt-get purge -y -qq nginx nginx-common nginx-core >/dev/null 2>&1
  else
    dnf remove -y -q nginx >/dev/null 2>&1 || yum remove -y -q nginx >/dev/null 2>&1
  fi
  rm -rf /var/www/trust /var/www/wild
else
  R_TRUST=skip
  tail -3 /tmp/trust-pkg.log 2>/dev/null
fi

EXTRA_RESULT="${EXTRA_RESULT:-} trust=$R_TRUST"
[ "$R_TRUST" = fail ] && EXTRA_FAIL=1
true
