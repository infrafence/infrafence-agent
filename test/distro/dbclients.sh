# Sourced by inside.sh after firewall.sh (its c2 namespace: 192.0.2.2 and
# 192.0.2.3 behind 192.0.2.1): regular clients of a database port are never
# cut off. A test build shortens the "day" (INFRAFENCE_TEST_DBCLIENTS_DAY),
# so 192.0.2.2, holding a connection to a database-like service on 5432,
# is seen on 3 "days" in about a minute. Closing 5432 is then refused with
# regular_clients; once 192.0.2.2 is whitelisted it closes, 192.0.2.2 still
# reaches it and 192.0.2.3 does not. A WHM access hosts file
# (/var/cpanel/mysqlaccesshosts) declares 198.51.100.% as MySQL clients:
# closing 3306 is refused from the first minute. The agent reports the
# clients to /api/v1/agent/db-clients. Sets R_DBCLIENTS, R_DBDECLARED;
# appends to EXTRA_RESULT and sets EXTRA_FAIL=1 on a failure.
R_DBCLIENTS=fail R_DBDECLARED=fail
API=http://127.0.0.1:8080
DB_DROPIN=/etc/systemd/system/infrafence-agent.service.d/zz-dbclients-test.conf
had_cpanel_dir=no; [ -d /var/cpanel ] && had_cpanel_dir=yes

fw_event() {
  curl -s "$API/state" | grep -o "\"type\":\"firewall_action_[a-z_]*\",\"severity\":\"[a-z]*\",\"details\":{\"action_id\":\"$1\"[^}]*" | head -1
}
wait_event() {
  for _ in $(seq 1 180); do [ -n "$(fw_event "$1")" ] && return 0; sleep 1; done
  return 1
}
closed() { iptables -S INFRAFENCE-PORTS 2>/dev/null | grep -q -- "--ctorigdstport $1 -j DROP"; }
reaches() { # SRC PORT
  ip netns exec c2 ip route replace 192.0.2.1/32 dev veth3 src "$1"
  ip netns exec c2 timeout 3 bash -c "</dev/tcp/192.0.2.1/$2" 2>/dev/null
  local rc=$?
  ip netns exec c2 ip route del 192.0.2.1/32 dev veth3 src "$1" 2>/dev/null
  return $rc
}

# Database-like services that keep their clients connected.
curl -s "$API/listen?addr=0.0.0.0:5432&hold=1&net=tcp4" >/dev/null
curl -s "$API/listen?addr=192.0.2.1:3306&hold=1&net=tcp4" >/dev/null
mkdir -p /var/cpanel
printf '198.51.100.%%\nlocalhost\n10.0.0.%%\n' >/var/cpanel/mysqlaccesshosts
curl -s -X POST "$API/set-sync" -d '{"firewall_state": {"closed_ports": [], "egress_blocked": []}, "firewall_actions": null, "whitelists": []}' >/dev/null
mkdir -p "$(dirname $DB_DROPIN)"
printf '[Service]\nEnvironment=INFRAFENCE_TEST_DBCLIENTS_DAY=15s INFRAFENCE_TEST_DBCLIENTS_SAMPLE=2s INFRAFENCE_TEST_DBCLIENTS_REPORT=5s\n' >$DB_DROPIN
systemctl daemon-reload
systemctl restart infrafence-agent
sleep 5

# 192.0.2.2 connects and stays, over 4 "days".
ip netns exec c2 bash -c 'exec 3<>/dev/tcp/192.0.2.1/5432 && exec sleep 70' </dev/null >/dev/null 2>&1 &
client=$!
reported=no
for _ in $(seq 1 90); do
  n=$(curl -s "$API/state" | grep -o '"port":5432,"ip":"192.0.2.2","day":"[^"]*","first_seen":"[^"]*"' | sort -u | wc -l)
  [ "$n" -ge 3 ] && { reported=yes; break; }
  sleep 1
done
kill $client 2>/dev/null; wait $client 2>/dev/null
log "db clients reported for 192.0.2.2 on 5432: $reported"
for _ in $(seq 1 10); do ss -tn state established 2>/dev/null | grep -q '192.0.2.1:5432 ' || break; sleep 1; done

ok=$reported
# The WHM plugin's list (panel db-clients): the regular client, not
# whitelisted yet, and the declared range of 3306.
dbpanel() { "$AGENT" panel db-clients --json 2>/dev/null | grep -o "{[^{}]*\"ip\":\"$1\"[^{}]*}"; }
row=$(dbpanel 192.0.2.2)
{ grep -q '"port":5432' <<<"$row" && grep -q '"source":"observed"' <<<"$row" && grep -q '"allowed":false' <<<"$row" &&
  grep -q '"last_seen":"20' <<<"$row"; } || { log "panel db-clients 192.0.2.2: ${row:-missing}"; ok=fail; }
row=$(dbpanel 198.51.100.0/24)
{ grep -q '"port":3306' <<<"$row" && grep -q '"source":"cpanel_access_hosts"' <<<"$row" && grep -q '"host":"198.51.100.%"' <<<"$row"; } ||
  { log "panel db-clients 198.51.100.0/24: ${row:-missing}"; ok=fail; }
curl -s -X POST "$API/set-sync" -d '{"firewall_actions": [{"id": 201, "kind": "close_port", "port": 5432, "proto": "tcp"}, {"id": 204, "kind": "close_port", "port": 3306, "proto": "tcp"}]}' >/dev/null
if wait_event 201 && wait_event 204; then
  grep -q '"type":"firewall_action_failed"' <<<"$(fw_event 201)" && grep -q '"reason":"regular_clients"' <<<"$(fw_event 201)" \
    && grep -q '"clients":"192.0.2.2"' <<<"$(fw_event 201)" || { log "201: $(fw_event 201)"; ok=fail; }
  closed 5432 && { log "5432 closed although 192.0.2.2 is a regular client"; ok=fail; }
  if grep -q '"reason":"regular_clients"' <<<"$(fw_event 204)" && grep -q '"clients":"198.51.100.0/24"' <<<"$(fw_event 204)" && ! closed 3306; then
    curl -s "$API/state" | grep -q '"entry":"198.51.100.0/24"' && R_DBDECLARED=ok || log "declared hosts not reported"
  else
    log "204: $(fw_event 204)"
  fi
else
  log "no result for 201/204"; ok=fail
fi

# Whitelisted: the port closes, the client keeps its access.
curl -s -X POST "$API/set-sync" -d '{"whitelists": [{"id": 9, "ip_address": "192.0.2.2", "ip_range": null}],
  "firewall_actions": [{"id": 202, "kind": "close_port", "port": 5432, "proto": "tcp"}]}' >/dev/null
if wait_event 202; then
  grep -q '"type":"firewall_action_done"' <<<"$(fw_event 202)" || { log "202: $(fw_event 202)"; ok=fail; }
  closed 5432 || { log "5432 not closed after whitelisting"; ok=fail; }
  reaches 192.0.2.2 5432 || { log "the whitelisted client lost 5432"; ok=fail; }
  reaches 192.0.2.3 5432 && { log "192.0.2.3 still reaches 5432"; ok=fail; }
  grep -q '"allowed":true' <<<"$(dbpanel 192.0.2.2)" || { log "panel db-clients after whitelisting: $(dbpanel 192.0.2.2)"; ok=fail; }
else
  log "no result for 202"; ok=fail
fi
[ "$ok" = yes ] && R_DBCLIENTS=ok

# Clean up: reopen, no whitelist, normal days, no access hosts file.
curl -s -X POST "$API/set-sync" -d '{"firewall_state": {"closed_ports": [{"port": 5432, "proto": "tcp"}], "egress_blocked": []},
  "firewall_actions": [{"id": 203, "kind": "open_port", "port": 5432, "proto": "tcp"}]}' >/dev/null
wait_event 203 || log "no result for 203"
curl -s -X POST "$API/set-sync" -d '{"firewall_state": {"closed_ports": [], "egress_blocked": []}, "firewall_actions": null, "whitelists": []}' >/dev/null
curl -s "$API/unlisten?addr=0.0.0.0:5432" >/dev/null
curl -s "$API/unlisten?addr=192.0.2.1:3306" >/dev/null
rm -f "$DB_DROPIN" /var/cpanel/mysqlaccesshosts
[ $had_cpanel_dir = no ] && rmdir /var/cpanel 2>/dev/null
systemctl daemon-reload
systemctl restart infrafence-agent
sleep 5
if [ -e /var/lib/infrafence/db-clients.json ]; then
  stat -c '%a' /var/lib/infrafence/db-clients.json | grep -qx 600 || { log "db-clients.json mode $(stat -c '%a' /var/lib/infrafence/db-clients.json)"; R_DBCLIENTS=fail; }
else
  log "db-clients.json not saved"; R_DBCLIENTS=fail
fi

EXTRA_RESULT="${EXTRA_RESULT:-} dbclients=${R_DBCLIENTS} dbdeclared=${R_DBDECLARED}"
[ "$R_DBCLIENTS$R_DBDECLARED" = okok ] || EXTRA_FAIL=1
