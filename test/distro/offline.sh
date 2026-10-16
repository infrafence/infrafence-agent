# Sourced by inside.sh: the dashboard refuses the agent (403
# {"error":"suspended"}) and the agent restarts with its chain and sets
# emptied. The last known protection must come back from the state file: the
# allow list (198.51.100.2 is never banned, not even geo-blocked), the
# country block (XX = 198.51.100.0/25, from a test GeoIP database: blocks
# 198.51.100.3), the dashboard's bans (one expiring soon, one permanent). The
# expiring ban must expire on this server while the dashboard still refuses
# the agent, a ban made meanwhile (198.51.100.200) must be reported once the
# dashboard answers again, and the refused agent must not keep asking.
# Sets R_RESTORE, R_GEO, R_ALLOW, R_EXPIRE, R_OUTBOX, R_QUIET; appends to
# EXTRA_RESULT and sets EXTRA_FAIL=1 on a failure.
R_RESTORE=fail R_GEO=fail R_ALLOW=fail R_EXPIRE=fail R_OUTBOX=fail R_QUIET=fail
API=http://127.0.0.1:8080
WL=198.51.100.2 GEO=198.51.100.3 ATK=198.51.100.200
EXP_BAN=203.0.113.77 PERM_BAN=203.0.113.78
STATE=/var/lib/infrafence/protection-state.json

ip netns add c3
ip link add veth4 type veth peer name veth5
ip link set veth5 netns c3
ip addr add 198.51.100.1/24 dev veth4 && ip link set veth4 up
for a in $WL $GEO $ATK; do ip netns exec c3 ip addr add "$a/24" dev veth5; done
ip netns exec c3 ip link set veth5 up
ip netns exec c3 ip link set lo up

ipset_mode() { ipset list -n 2>/dev/null | grep -qx infrafence-bans; }
banned() {
  if ipset_mode; then ipset list infrafence-bans 2>/dev/null | grep -qx "$1"
  else iptables -S INFRAFENCE 2>/dev/null | grep -q -- "-s $1/32 -j DROP"; fi
}
# ssh_from ADDR USER: an SSH login from one of c3's addresses (fails: no
# such user, no key).
ssh_from() {
  ip netns exec c3 timeout 8 ssh -b "$1" -o BatchMode=yes -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 -o PreferredAuthentications=password,publickey \
    "$2@198.51.100.1" true 2>&1
}
# reaches ADDR: sshd answered (a refused login), not a dropped connection.
reaches() { ssh_from "$1" probe | grep -qiE 'permission denied|closed by|reset by'; }
brute() { for i in $(seq 1 8); do ssh_from "$1" "nosuch$i" >/dev/null; done; }
mock_bans() { curl -s "$API/state" | grep -o '"bans":\[[^]]*\]'; }
denied() { curl -s "$API/state" | grep -o '"denied":[0-9]*' | cut -d: -f2; }

# ── the dashboard's state: allow list, country XX, two bans ──
mkdir -p /etc/infrafence
/distro/mkmmdb -out /etc/infrafence/GeoLite2-Country.mmdb -cidr 198.51.100.0/25 -country XX
systemctl restart infrafence-agent # loads the GeoIP database
sleep 10
exp=$(date -u -d '+180 seconds' +%Y-%m-%dT%H:%M:%SZ)
exp_at=$(date -u -d "$exp" +%s)
curl -s -X POST "$API/set-sync" -d "{
  \"config\": {\"bf_threshold\": 5, \"bf_window\": 60, \"monitor_mode\": false, \"blocked_countries\": [\"XX\"]},
  \"whitelists\": [{\"id\": 1, \"ip_address\": \"$WL\", \"ip_range\": null}],
  \"bans\": [{\"id\": 901, \"ip_address\": \"$EXP_BAN\", \"expires_at\": \"$exp\"},
             {\"id\": 902, \"ip_address\": \"$PERM_BAN\", \"expires_at\": null}]}" >/dev/null
ready=no
for _ in $(seq 1 100); do
  if banned $EXP_BAN && banned $PERM_BAN && grep -q '"XX"' $STATE 2>/dev/null && grep -q "\"$WL\"" $STATE 2>/dev/null &&
     { ! ipset_mode || ipset list -n | grep -qx infrafence-geo-xx; }; then ready=yes; break; fi
  sleep 1
done
log "dashboard state applied and saved: $ready ($(ipset_mode && echo ipset || echo iptables))"
[ $ready = yes ] || { journalctl -u infrafence-agent --no-pager | grep -iE 'sync|geo|protection' | tail -10; ls -l $STATE; }
stat -c '%a' $STATE 2>/dev/null | grep -qx 600 || { log "state file mode $(stat -c '%a' $STATE 2>/dev/null)"; ready=no; }

if [ $ready = yes ]; then
  # ── refused, and a restart that loses what is in the kernel ──
  curl -s "$API/deny?mode=suspended" >/dev/null
  systemctl stop infrafence-agent
  iptables -F INFRAFENCE
  if ipset_mode; then
    ipset flush infrafence-bans
    ipset destroy infrafence-geo-xx 2>/dev/null
    ipset destroy infrafence-allow 2>/dev/null
  fi
  d0=$(denied)
  t0=$(date +%s)
  systemctl start infrafence-agent

  ok=no
  for _ in $(seq 1 60); do
    if banned $EXP_BAN && banned $PERM_BAN && { ! ipset_mode || ipset list -n | grep -qx infrafence-geo-xx; }; then ok=yes; break; fi
    sleep 1
  done
  [ $ok = yes ] && R_RESTORE=ok || { log "after the restart: bans $(banned $EXP_BAN && echo $EXP_BAN) $(banned $PERM_BAN && echo $PERM_BAN)"; journalctl -u infrafence-agent --no-pager | grep -iE 'protection|restor' | tail -6; }
  if ipset_mode; then
    if ! reaches $GEO && reaches $WL; then R_GEO=ok; else log "geo: $GEO reaches=$(reaches $GEO && echo yes) $WL reaches=$(reaches $WL && echo yes)"; fi
  else
    R_GEO=skip # country blocks need ipset
  fi

  # ── brute force from the allowed address and from another one ──
  brute $WL
  brute $ATK
  for _ in $(seq 1 30); do banned $ATK && break; sleep 1; done
  if banned $ATK && ! banned $WL && reaches $WL; then R_ALLOW=ok; else log "allow: $ATK banned=$(banned $ATK && echo yes) $WL banned=$(banned $WL && echo yes)"; fi
  mock_bans | grep -q "$ATK" && { log "$ATK reported although the dashboard refuses the agent"; R_ALLOW=fail; }

  # ── the expiring ban expires here, the permanent one stays ──
  while [ "$(date +%s)" -lt $((exp_at + 45)) ] && banned $EXP_BAN; do sleep 2; done
  if ! banned $EXP_BAN && banned $PERM_BAN; then R_EXPIRE=ok; else log "expiry: $EXP_BAN still banned=$(banned $EXP_BAN && echo yes) $PERM_BAN=$(banned $PERM_BAN && echo yes)"; fi

  # ── one SUSPENDED line, and only a handful of requests in minutes ──
  n=$(journalctl -u infrafence-agent --no-pager --since "@$t0" | grep -c 'SUSPENDED')
  asked=$(( $(denied) - d0 ))
  log "refused requests in $(( $(date +%s) - t0 ))s: $asked, SUSPENDED logged $n time(s)"
  [ "$n" = 1 ] && [ "$asked" -le 8 ] && R_QUIET=ok

  # ── the dashboard answers again (a restart skips the 30-minute wait): the
  # ban made meanwhile is reported and stays although the sync, fetched
  # first, does not list it ──
  curl -s "$API/deny?mode=off" >/dev/null
  systemctl restart infrafence-agent
  for _ in $(seq 1 60); do mock_bans | grep -q "$ATK" && break; sleep 1; done
  sleep 5
  if mock_bans | grep -q "$ATK" && banned $ATK; then R_OUTBOX=ok; else log "outbox: reported=$(mock_bans | grep -q "$ATK" && echo yes) banned=$(banned $ATK && echo yes)"; fi
fi

# ── back to the plain state ──
curl -s "$API/deny?mode=off" >/dev/null
curl -s -X POST "$API/set-sync" -d '{"config": {"bf_threshold": 5, "bf_window": 60, "monitor_mode": false}, "whitelists": [], "bans": []}' >/dev/null
EXTRA_RESULT="${EXTRA_RESULT:-} restore=${R_RESTORE} geo=${R_GEO} allow=${R_ALLOW} expire=${R_EXPIRE} outbox=${R_OUTBOX} quiet=${R_QUIET}"
[ "$R_RESTORE$R_ALLOW$R_EXPIRE$R_OUTBOX$R_QUIET" = okokokokok ] && [ "$R_GEO" != fail ] || EXTRA_FAIL=1
ip netns pids c3 2>/dev/null | xargs -r kill 2>/dev/null
