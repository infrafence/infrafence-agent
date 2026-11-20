# Sourced by inside.sh after waf.sh (Apache is installed and running there):
# an HTTP flood over one keep-alive connection from another network namespace
# (203.0.113.5) ends with a timed ban and one http_flood event at the mock
# API. The threshold is lowered to 200 requests per minute through
# waf_config, as the dashboard would. Adds "httpflood=..." to EXTRA_RESULT and
# sets EXTRA_FAIL on a failure.

R_HTTPFLOOD=fail
api=http://127.0.0.1:8080
flooder=203.0.113.5
AGENT=${AGENT:-/usr/local/bin/infrafence-agent}
set_sync() { curl -s -X POST -d "$1" "$api/set-sync" >/dev/null; }

# The configuration waf.sh left, restored at the end.
base_config='{"bf_threshold":5,"bf_window":60,"monitor_mode":false}'
[ "${modsec:-no}" = yes ] && base_config='{"bf_threshold":5,"bf_window":60,"monitor_mode":false,"monitor_config":{"webserver_changes":true}}'

if curl -s -o /dev/null http://127.0.0.1/; then
  ip netns exec cl ip addr add "$flooder/24" dev veth1 2>/dev/null
  set_sync "{\"config\":${base_config%\}},\"waf_config\":{\"thresholds\":{\"http_flood\":200}}}}"
  # Restart so the agent reads Apache's access log (installed after it started).
  systemctl restart infrafence-agent
  for _ in $(seq 1 30); do
    journalctl -u infrafence-agent --no-pager -n 200 | grep -qE '\[webwatcher\] watching .*access' && break
    sleep 1
  done
  sleep 3
  # 400 requests on one connection (curl's URL range reuses it): the
  # connection count stays at 1, the request count crosses 200.
  ip netns exec cl curl -s -o /dev/null --interface "$flooder" "http://203.0.113.1/flood?n=[1-400]"
  ev=""
  for _ in $(seq 1 30); do
    ev=$(curl -s "$api/state" | grep -o '{"type":"http_flood"[^}]*' | grep -F '"action":"banned"' | head -1)
    [ -n "$ev" ] && break
    sleep 1
  done
  banned=no
  { ipset list infrafence-bans 2>/dev/null | grep -q "^$flooder" || iptables -S INFRAFENCE 2>/dev/null | grep -q "$flooder"; } && banned=yes
  reported=no
  curl -s "$api/state" | grep -o '"bans":\[[^]]*' | grep -q "\"ip_address\":\"$flooder\"[^}]*\"expires_at\":\"" && reported=yes
  log "http flood: event=${ev:+yes} banned=$banned reported_with_expiry=$reported"
  if [ -n "$ev" ] && [ "$banned" = yes ] && [ "$reported" = yes ] &&
     grep -qF '"ban_seconds":"1800"' <<<"$ev" && grep -qF '"top_paths":"/flood (' <<<"$ev"; then
    R_HTTPFLOOD=ok
  else
    echo "$ev"
    journalctl -u infrafence-agent --no-pager | grep -E 'http_flood|webwatcher' | tail -10
  fi
  # Leave the server as waf.sh did.
  firewall_unban=$("$AGENT" panel unban "$flooder" --actor root 2>&1) || log "unban $flooder: $firewall_unban"
  ip netns exec cl ip addr del "$flooder/24" dev veth1 2>/dev/null
  set_sync "{\"config\":$base_config}"
else
  R_HTTPFLOOD=skip
  log "http flood: no web server answering on port 80"
fi

EXTRA_RESULT="${EXTRA_RESULT:-} httpflood=$R_HTTPFLOOD"
[ "$R_HTTPFLOOD" = fail ] && EXTRA_FAIL=1
true
