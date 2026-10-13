# Sourced by inside.sh: ports closed and egress blocked from the dashboard
# (firewall_actions / firewall_state). A second client namespace "c2"
# (192.0.2.2; the first one is banned by now) checks the effect from
# outside; the egress cases block its second address, 192.0.2.3, so the
# host's answers to 192.0.2.2 are not affected. Egress is only blocked to an
# address the agent flagged itself: 192.0.2.3 goes into the dashboard threat
# feed (detection only) and the host holds a connection to it until the
# egress monitor reports it. Sets R_PORTS, R_EGRESS, R_PERSIST, R_IPV6,
# R_SSHSOCK, R_HB; appends to EXTRA_RESULT and sets EXTRA_FAIL=1 on a failure.
R_PORTS=fail R_EGRESS=fail R_PERSIST=fail R_IPV6=fail R_SSHSOCK=skip R_HB=fail
API=http://127.0.0.1:8080
CONFIG='"config":{"bf_threshold":5,"bf_window":60,"monitor_mode":false}'

ip netns add c2
ip link add veth2 type veth peer name veth3
ip link set veth3 netns c2
ip addr add 192.0.2.1/24 dev veth2 && ip link set veth2 up
ip netns exec c2 ip addr add 192.0.2.2/24 dev veth3
ip netns exec c2 ip addr add 192.0.2.3/24 dev veth3
ip netns exec c2 ip link set veth3 up
ip netns exec c2 ip link set lo up

# A service on 6379 on the host, and one in c2 for the egress cases.
curl -s "$API/listen?addr=0.0.0.0:6379" >/dev/null
ip netns exec c2 /distro/mockapi -addr 192.0.2.3:9000 -binary /distro/agent >/tmp/c2.log 2>&1 &
sleep 1
c2_reaches_6379() { ip netns exec c2 timeout 3 bash -c '</dev/tcp/192.0.2.1/6379' 2>/dev/null; }
host_reaches_c2() { timeout 3 bash -c '</dev/tcp/192.0.2.3/9000' 2>/dev/null; }

# fw_event ID prints the result event of request ID (up to its verify
# detail, whose JSON string is not needed here), empty until it arrives.
fw_event() {
  curl -s "$API/state" | grep -o "\"type\":\"firewall_action_[a-z_]*\",\"severity\":\"[a-z]*\",\"details\":{\"action_id\":\"$1\"[^}]*" | head -1
}
wait_events() {
  for _ in $(seq 1 100); do
    local missing=0
    for id in "$@"; do [ -n "$(fw_event "$id")" ] || missing=1; done
    [ $missing = 0 ] && return 0
    sleep 1
  done
  return 1
}
expect() { # ID TYPE [REASON]
  local e; e=$(fw_event "$1")
  if ! grep -q "\"type\":\"$2\"" <<<"$e" || { [ -n "${3:-}" ] && ! grep -q "\"reason\":\"$3\"" <<<"$e"; }; then
    log "action $1: want $2 ${3:-}, got: ${e:-nothing}"; return 1
  fi
}
egress_has() {
  if ipset list -n 2>/dev/null | grep -q infrafence-egress; then
    ipset list infrafence-egress | grep -q "^$1"
  else
    iptables -S INFRAFENCE-EGRESS | grep -q "$1/32"
  fi
}
v4_closed() { iptables -S INFRAFENCE-PORTS 2>/dev/null | grep -q -- "--ctorigdstport $1 -j DROP"; }
v6_closed() { ip6tables -S INFRAFENCE-PORTS 2>/dev/null | grep -q -- "--ctorigdstport $1 -j DROP"; }

base=ok
c2_reaches_6379 || { log "baseline: c2 cannot reach 6379"; base=fail; }
host_reaches_c2 || { log "baseline: host cannot reach c2"; base=fail; }

# ── an SSH port only systemd knows about: ssh.socket / sshd.socket listening
# on 2222 (left inactive, so the running sshd is not touched) ──
sock=""
for u in ssh.socket sshd.socket; do
  if systemctl cat "$u" >/dev/null 2>&1 && ! systemctl is-active --quiet "$u"; then sock=$u; break; fi
done
if [ -n "$sock" ]; then
  mkdir -p "/etc/systemd/system/$sock.d"
  printf '[Socket]\nListenStream=\nListenStream=2222\n' >"/etc/systemd/system/$sock.d/infrafence-test.conf"
  systemctl daemon-reload
  systemctl show "$sock" -p Listen | sed 's/^/[firewall] /'
  # The agent reads the SSH ports once a minute: start it afresh.
  systemctl restart infrafence-agent
  sleep 12
fi

# ── close 6379; 22, 8000 and (socket) 2222 refused; egress to an address
# the agent never flagged, and to a private one, refused ──
actions='{"id": 101, "kind": "close_port", "port": 6379, "proto": "tcp"},
    {"id": 102, "kind": "close_port", "port": 22, "proto": "tcp"},
    {"id": 103, "kind": "block_egress", "ip": "192.0.2.3"},
    {"id": 104, "kind": "block_egress", "ip": "10.9.9.9"},
    {"id": 107, "kind": "close_port", "port": 8000, "proto": "tcp"}'
ids="101 102 103 104 107"
if [ -n "$sock" ]; then
  actions="$actions, {\"id\": 108, \"kind\": \"close_port\", \"port\": 2222, \"proto\": \"tcp\"}"
  ids="$ids 108"
fi
curl -s -X POST "$API/set-sync" -d "{\"firewall_state\": {\"closed_ports\": [], \"egress_blocked\": []}, \"firewall_actions\": [$actions]}" >/dev/null
p=$base e=$base
# shellcheck disable=SC2086
if wait_events $ids; then
  expect 101 firewall_action_done || p=fail
  fw_event 101 | grep -q 'ssh_ok\\":true' || { log "101: no verify detail with ssh_ok"; p=fail; }
  expect 102 firewall_action_failed ssh_port || p=fail
  expect 107 firewall_action_failed not_closable || p=fail
  v4_closed 6379 || { log "no 6379 rule"; iptables -S INFRAFENCE-PORTS; p=fail; }
  c2_reaches_6379 && { log "c2 still reaches 6379"; p=fail; }
  timeout 3 bash -c '</dev/tcp/127.0.0.1/6379' 2>/dev/null || { log "localhost lost 6379"; p=fail; }
  ip netns exec c2 timeout 3 bash -c '</dev/tcp/192.0.2.1/22' 2>/dev/null || { log "ssh closed"; p=fail; }
  expect 103 firewall_action_failed not_flagged || e=fail
  expect 104 firewall_action_failed private_target || e=fail
  egress_has 192.0.2.3 && { log "unflagged 192.0.2.3 blocked"; e=fail; }
  if [ -n "$sock" ]; then
    expect 108 firewall_action_failed ssh_port && R_SSHSOCK=ok || R_SSHSOCK=fail
  fi
  # IPv6: the same chain in ip6tables, or the result says IPv4 only.
  if command -v ip6tables >/dev/null && ip6tables -S INPUT >/dev/null 2>&1; then
    if v6_closed 6379 && ip6tables -S INPUT | grep -q -- '-j INFRAFENCE-PORTS'; then
      fw_event 101 | grep -q 'IPv4 only' && log "101 claims IPv4 only although ip6tables has the rule" || R_IPV6=ok
    else
      log "no IPv6 mirror"; ip6tables -S INFRAFENCE-PORTS 2>&1 | head -5
    fi
  else
    R_IPV6=skip
  fi
else
  log "no result events for $ids"; p=fail; e=fail; journalctl -u infrafence-agent --no-pager | grep -i firewall | tail -10
fi

# ── the agent flags 192.0.2.3 (threat feed + a connection to it), then
# blocking egress to it is allowed ──
# The state now has what the agent reported done (6379 closed).
curl -s -X POST "$API/set-sync" -d "{$CONFIG, \"threat_feed\": [{\"ip\": \"192.0.2.3\", \"cidr\": null, \"source\": \"distro-test\"}],
  \"firewall_state\": {\"closed_ports\": [{\"port\": 6379, \"proto\": \"tcp\"}], \"egress_blocked\": []}, \"firewall_actions\": null}" >/dev/null
(exec 3<>/dev/tcp/192.0.2.3/9000; sleep 150) 2>/dev/null &
holder=$!
flagged=no
for _ in $(seq 1 150); do
  curl -s "$API/state" | grep -o '{"type":"egress_threat_match"[^}]*' | grep -q '192.0.2.3' && { flagged=yes; break; }
  sleep 1
done
kill $holder 2>/dev/null; wait $holder 2>/dev/null
log "egress_threat_match for 192.0.2.3: $flagged"
if [ $flagged = yes ]; then
  curl -s -X POST "$API/set-sync" -d '{"firewall_actions": [{"id": 109, "kind": "block_egress", "ip": "192.0.2.3"}]}' >/dev/null
  if wait_events 109; then
    expect 109 firewall_action_done || e=fail
    egress_has 192.0.2.3 || { log "192.0.2.3 not in the egress set"; e=fail; }
    host_reaches_c2 && { log "host still reaches c2"; e=fail; }
  else
    log "no result event for 109"; e=fail
  fi
else
  e=fail
fi
[ $p = ok ] && R_PORTS=half; [ $e = ok ] && R_EGRESS=half
curl -s -X POST "$API/set-sync" -d '{"firewall_state": {"closed_ports": [{"port": 6379, "proto": "tcp"}], "egress_blocked": ["192.0.2.3"]}, "firewall_actions": null}' >/dev/null

# ── persistence: the dashboard goes down, the chains are flushed, the agent
# restarts: the saved state closes 6379 and blocks 192.0.2.3 again ──
if [ $R_PORTS = half ] && [ $R_EGRESS = half ]; then
  ls -l /var/lib/infrafence/firewall-state.json | sed 's/^/[firewall] /'
  curl -s "$API/offline?on=1" >/dev/null
  systemctl stop infrafence-agent
  iptables -F INFRAFENCE-PORTS; ip6tables -F INFRAFENCE-PORTS 2>/dev/null
  ipset flush infrafence-egress 2>/dev/null || iptables -F INFRAFENCE-EGRESS
  systemctl start infrafence-agent
  ok=no
  for _ in $(seq 1 60); do
    if v4_closed 6379 && egress_has 192.0.2.3; then ok=yes; break; fi
    sleep 1
  done
  if [ $ok = yes ] && ! c2_reaches_6379 && ! host_reaches_c2 && { [ $R_IPV6 != ok ] || v6_closed 6379; }; then
    R_PERSIST=ok
  else
    log "after restart without the dashboard: v4=$(v4_closed 6379 && echo closed) v6=$(v6_closed 6379 && echo closed) egress=$(egress_has 192.0.2.3 && echo blocked)"
    journalctl -u infrafence-agent --no-pager | grep -iE 'firewall|restored' | tail -8
  fi
  stat -c '%a' /var/lib/infrafence/firewall-state.json | grep -qx 600 || { log "state file mode $(stat -c '%a' /var/lib/infrafence/firewall-state.json)"; R_PERSIST=fail; }
  curl -s "$API/offline?on=0" >/dev/null
fi

# ── undo both; the state now has what the agent reported done ──
curl -s -X POST "$API/set-sync" -d '{
  "threat_feed": null,
  "firewall_state": {"closed_ports": [{"port": 6379, "proto": "tcp"}], "egress_blocked": ["192.0.2.3"]},
  "firewall_actions": [
    {"id": 105, "kind": "open_port", "port": 6379, "proto": "tcp"},
    {"id": 106, "kind": "unblock_egress", "ip": "192.0.2.3"}
  ]}' >/dev/null
if wait_events 105 106; then
  expect 105 firewall_action_done && c2_reaches_6379 && ! v6_closed 6379 && [ $R_PORTS = half ] && R_PORTS=ok
  expect 106 firewall_action_done && host_reaches_c2 && [ $R_EGRESS = half ] && R_EGRESS=ok
else
  log "no result events for 105-106"
fi
curl -s -X POST "$API/set-sync" -d '{"firewall_state": {"closed_ports": [], "egress_blocked": []}, "firewall_actions": null}' >/dev/null
[ $R_PORTS = ok ] || log "ports: $R_PORTS"
[ $R_EGRESS = ok ] || log "egress: $R_EGRESS"
if [ -n "$sock" ]; then
  rm -rf "/etc/systemd/system/$sock.d/infrafence-test.conf"
  systemctl daemon-reload
fi

# ── heartbeat reports the SSH and web ports ──
curl -s "$API/state" | grep -q '"ssh_ports":\[22' && R_HB=ok || { log "heartbeat without ssh_ports"; curl -s "$API/state" | grep -o '"last_heartbeat":.\{0,200\}'; }

EXTRA_RESULT="${EXTRA_RESULT:-} ports=${R_PORTS} egress=${R_EGRESS} persist=${R_PERSIST} ipv6=${R_IPV6} sshsocket=${R_SSHSOCK} heartbeat_ports=${R_HB}"
[ "$R_PORTS$R_EGRESS$R_PERSIST$R_HB" = okokokok ] && [ "$R_IPV6" != fail ] && [ "$R_SSHSOCK" != fail ] || EXTRA_FAIL=1
ip netns pids c2 2>/dev/null | xargs -r kill 2>/dev/null
