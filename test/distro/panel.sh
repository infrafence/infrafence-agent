# Sourced by inside.sh: the commands the WHM and Plesk plugins run
# ("infrafence-agent panel <command> --json", internal/panel). Checks that
# nothing of it runs on a host without cPanel/WHM or Plesk, then turns it on
# with "panel": true in the config and checks the
# socket (root only, 0600 in a 0700 directory), every read command, that an
# unban from the panel is reported with the panel user and is not reapplied
# by the next sync or after a restart, allow/disallow, input validation,
# the map and the score (one request per interval), and the answers without
# a running agent. Sets R_PANEL; appends to EXTRA_RESULT
# and sets EXTRA_FAIL=1 on a failure.
R_PANEL=fail
API=http://127.0.0.1:8080
AGENT=/usr/local/bin/infrafence-agent
CONFIG='"config":{"bf_threshold":5,"bf_window":60,"monitor_mode":false}'
pfail=""
pf() { pfail="$pfail $1"; log "panel: $1${2:+: $2}"; }
pcmd() { "$AGENT" panel "$@" --json 2>/dev/null; }
banned() { ipset list infrafence-bans 2>/dev/null | grep -q "^$1" || iptables -S INFRAFENCE 2>/dev/null | grep -q "$1/32"; }
syncs() { curl -s "$API/state" | grep -o '"syncs":[0-9]*' | cut -d: -f2; }
# wait_sync: bump the mock's config version and wait for the agent's sync.
wait_sync() {
  local before; before=$(syncs)
  curl -s -X POST "$API/set-sync" -d "$1" >/dev/null
  for _ in $(seq 1 120); do [ "$(syncs)" -gt "$before" ] && { sleep 2; return 0; }; sleep 1; done
  return 1
}

# ── off by default: no cPanel/WHM or Plesk in these containers ──
sock=/run/infrafence/panel.sock
[ -e "$sock" ] && pf default_off "socket present without a hosting panel"
out=$(pcmd bans); grep -q '"error":"agent_not_running"' <<<"$out" || pf default_off_reply "$out"
# "panel": true in the config turns it on.
sed -i '$ s/^}$/  ,"panel": true\n}/' /etc/infrafence/config.json
systemctl restart infrafence-agent
for _ in $(seq 1 30); do [ -S "$sock" ] && break; sleep 1; done
sleep 3

# ── socket ──
[ -S "$sock" ] || pf socket "missing"
[ "$(stat -c '%a %U' "$sock" 2>/dev/null)" = "600 root" ] || pf socket_mode "$(stat -c '%a %U' "$sock" 2>&1)"
[ "$(stat -c '%a' /run/infrafence 2>/dev/null)" = 700 ] || pf socket_dir "$(stat -c '%a' /run/infrafence 2>&1)"
if command -v su >/dev/null; then
  out=$(su nobody -s /bin/sh -c "$AGENT panel status --json" 2>/dev/null); rc=$?
  { [ $rc -ne 0 ] && grep -q '"error":"not_root"' <<<"$out"; } || pf non_root "rc=$rc $out"
fi

# ── read commands ──
out=$(pcmd status); rc=$?
{ [ $rc = 0 ] && grep -q '"ok":true' <<<"$out" && grep -q '"agent_running":true' <<<"$out" &&
  grep -q '"dashboard_url":"http://127.0.0.1:8080/servers/1"' <<<"$out"; } || pf status "rc=$rc $out"
for c in allowlist findings events coexistence sites; do
  out=$(pcmd "$c"); rc=$?
  { [ $rc = 0 ] && grep -q '"ok":true' <<<"$out"; } || pf "$c" "rc=$rc $(head -c 300 <<<"$out")"
done
grep -q '"mode":"' <<<"$(pcmd coexistence)" || pf coexistence_mode

# ── map and score: from the dashboard, at most one request per 5 (map) or
# 15 (score) minutes, answered or not ──
calls() { curl -s "$API/state" | grep -o "\"$1\":[0-9]*" | cut -d: -f2; }
curl -s "$API/info-down?on=1" >/dev/null
out=$(pcmd map --hours 168); rc=$?
{ [ $rc = 1 ] && grep -q '"error":"not_connected"' <<<"$out" && grep -q '"agent_running":true' <<<"$out"; } || pf map_not_connected "rc=$rc $out"
curl -s "$API/info-down?on=0" >/dev/null
grep -q '"error":"not_connected"' <<<"$(pcmd map --hours 168)" || pf map_retry "asked again within 5 minutes"
[ "$(calls 'map:168')" = 1 ] || pf map_calls_168 "$(calls 'map:168')"
for _ in 1 2 3; do out=$(pcmd map); done
{ grep -q '"ok":true' <<<"$out" && grep -q '"stale":false' <<<"$out" && grep -q '"hours":24' <<<"$out" &&
  grep -q '"code":"CN"' <<<"$out" && grep -q '"attacks":123' <<<"$out"; } || pf map "$out"
[ "$(calls 'map:24')" = 1 ] || pf map_calls_24 "$(calls 'map:24')"
grep -q '"error":"bad_request"' <<<"$(pcmd map --hours 48)" || pf map_hours
for _ in 1 2; do out=$(pcmd score); done
{ grep -q '"ok":true' <<<"$out" && grep -q '"score":72' <<<"$out" && grep -q '"grade":"C"' <<<"$out" &&
  grep -q '"key":"hardening"' <<<"$out"; } || pf score "$out"
[ "$(calls score)" = 1 ] || pf score_calls "$(calls score)"

# ── validation: never reaches the agent ──
out=$(pcmd unban '203.0.113.0/24' --actor root); rc=$?
{ [ $rc = 1 ] && grep -q '"error":"invalid_ip"' <<<"$out"; } || pf invalid_ip "rc=$rc $out"
grep -q '"error":"invalid_actor"' <<<"$(pcmd unban 203.0.113.2)" || pf no_actor
grep -q '"error":"invalid_actor"' <<<"$(pcmd unban 203.0.113.2 --actor 'x;id')" || pf bad_actor
grep -q '"error":"invalid_path"' <<<"$(pcmd scan ../etc --actor root)" || pf invalid_path

# ── unban: the dashboard keeps sending the ban, it stays lifted ──
BANS='"bans":[{"id":11,"ip_address":"203.0.113.2","expires_at":null}]'
wait_sync "{$CONFIG, $BANS}" || pf sync "no sync"
banned 203.0.113.2 || pf ban_setup "203.0.113.2 not banned before the unban"
grep -q '"ip":"203.0.113.2"' <<<"$(pcmd bans --limit 10)" || pf bans "203.0.113.2 not listed"
out=$(pcmd unban 203.0.113.2 --actor root); rc=$?
{ [ $rc = 0 ] && grep -q '"reported":true' <<<"$out"; } || pf unban "rc=$rc $out"
sleep 2
banned 203.0.113.2 && pf unban_fw "still in the firewall"
curl -s "$API/state" | grep -o '"type":"panel_unban"[^}]*}' | grep -q '"actor":"root"' || pf unban_event "no panel_unban event with the actor"
wait_sync "{$CONFIG, $BANS, \"whitelists\": []}" || pf sync "no sync after unban"
banned 203.0.113.2 && pf reapplied "lifted ban reapplied by the sync"
grep -q '"ip":"203.0.113.2"' <<<"$(pcmd bans)" && pf bans_lifted "lifted ban still listed"
grep -q '"error":"not_banned"' <<<"$(pcmd unban 203.0.113.2 --actor root)" || pf unban_twice
[ "$(stat -c '%a' /var/lib/infrafence/panel-state.json 2>/dev/null)" = 600 ] || pf state_file "$(ls -l /var/lib/infrafence/ 2>&1)"

# ── allow / disallow ──
out=$(pcmd allow 192.0.2.77 --note 'office VPN' --actor root)
grep -q '"ok":true' <<<"$out" || pf allow "$out"
# One entry, whatever the key order.
entry=$(pcmd allowlist | grep -o '{[^{}]*"address":"192.0.2.77"[^{}]*}')
{ grep -q '"source":"panel"' <<<"$entry" && grep -q '"note":"office VPN"' <<<"$entry" && grep -q '"actor":"root"' <<<"$entry"; } || pf allowlist "$(pcmd allowlist)"
curl -s "$API/state" | grep -o '"type":"panel_allow"[^}]*}' | grep -q '"ip":"192.0.2.77"' || pf allow_event
grep -q '"ok":true' <<<"$(pcmd disallow 192.0.2.77 --actor root)" || pf disallow
grep -q '"error":"not_in_allowlist"' <<<"$(pcmd disallow 192.0.2.77 --actor root)" || pf disallow_twice

# ── without the agent; then a restart keeps the lift ──
systemctl stop infrafence-agent
[ -e "$sock" ] && pf socket_left "socket not removed on stop"
out=$(pcmd status); rc=$?
{ [ $rc = 0 ] && grep -q '"agent_running":false' <<<"$out" && grep -q '"agent_id":1' <<<"$out"; } || pf offline_status "rc=$rc $out"
out=$(pcmd bans); rc=$?
{ [ $rc = 1 ] && grep -q '"error":"agent_not_running"' <<<"$out" && grep -q '"agent_running":false' <<<"$out"; } || pf offline_bans "rc=$rc $out"
grep -q '"ok":true' <<<"$(pcmd coexistence)" || pf offline_coexistence
grep -q '"error":"agent_not_running"' <<<"$(pcmd map)" || pf offline_map
systemctl start infrafence-agent
for _ in $(seq 1 30); do [ -S "$sock" ] && break; sleep 1; done
[ -S "$sock" ] || pf restart "no socket after restart"
sleep 5
banned 203.0.113.2 && pf restart_reapplied "lifted ban reapplied after restart"

# Back to the default sync for the following checks.
curl -s -X POST "$API/set-sync" -d '{"bans": null, "whitelists": null}' >/dev/null

[ -z "$pfail" ] && R_PANEL=ok
EXTRA_RESULT="${EXTRA_RESULT:-} panel=${R_PANEL}"
[ "$R_PANEL" = ok ] || EXTRA_FAIL=1
