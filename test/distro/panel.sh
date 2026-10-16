# Sourced by inside.sh: the commands the WHM and Plesk plugins run
# ("infrafence-agent panel <command> --json", internal/panel). Checks the
# socket (root only, 0600 in a 0700 directory), every read command, that an
# unban from the panel is reported with the panel user and is not reapplied
# by the next sync or after a restart, allow/disallow, input validation and
# the answers without a running agent. Sets R_PANEL; appends to EXTRA_RESULT
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

# ── socket ──
sock=/run/infrafence/panel.sock
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
