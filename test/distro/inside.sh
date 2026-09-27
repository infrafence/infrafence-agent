#!/usr/bin/env bash
# Runs inside one distro container (systemd as PID 1): installs the agent
# with the real install.sh against the mock dashboard, attacks SSH from
# another network namespace and checks detection, ban, blocking and a clean
# uninstall. Prints one RESULT line; exit status 0 only if everything passed.
set -uo pipefail

R_INSTALL=fail R_SERVICE=fail R_SCAN=fail R_DETECT=fail R_BAN=fail R_BLOCK=fail R_UNINSTALL=fail
SOURCE=none
log() { echo "[inside] $*"; }
result() {
  echo "RESULT distro=${DISTRO} install=${R_INSTALL} service=${R_SERVICE} portscan=${R_SCAN} detect=${R_DETECT} source=${SOURCE} ban=${R_BAN} blocked=${R_BLOCK} uninstall=${R_UNINSTALL}"
}
trap result EXIT

# ── network: the "attacker" lives in its own namespace, 203.0.113.2 ──
ip netns add cl
ip link add veth0 type veth peer name veth1
ip link set veth1 netns cl
ip addr add 203.0.113.1/24 dev veth0 && ip link set veth0 up
ip netns exec cl ip addr add 203.0.113.2/24 dev veth1
ip netns exec cl ip link set veth1 up
ip netns exec cl ip link set lo up

# ── sshd ──
ssh-keygen -A >/dev/null 2>&1
systemctl enable --now ssh >/dev/null 2>&1 || systemctl enable --now sshd >/dev/null 2>&1
sleep 1
if ! ip netns exec cl timeout 3 bash -c '</dev/tcp/203.0.113.1/22' 2>/dev/null; then
  log "sshd not reachable before install"; exit 1
fi

# ── mock dashboard ──
/distro/mockapi -binary /distro/agent >/tmp/mockapi.log 2>&1 &
sleep 1

# ── install with the real installer ──
if INFRAFENCE_SERVER_URL=http://127.0.0.1:8080 RELEASE_BASE=http://127.0.0.1:8080/releases \
   INFRAFENCE_AGENT_NAME=distro-test bash /distro/install.sh --token distro-test >/tmp/install.log 2>&1; then
  R_INSTALL=ok
else
  log "install.sh failed:"; tail -20 /tmp/install.log
fi

for _ in $(seq 1 15); do
  systemctl is-active --quiet infrafence-agent && { R_SERVICE=ok; break; }
  sleep 1
done
[ "$R_SERVICE" = ok ] || { log "service not active"; journalctl -u infrafence-agent --no-pager -n 30; }

# Let the agent start its watchers and first sync.
sleep 12
journalctl -u infrafence-agent --no-pager | grep -iE "watch|auth|journal" | head -5 | sed 's/^/[agent] /'

# ── port scan: 30 closed ports in a few seconds (reported, not banned) ──
for p in $(seq 1000 1029); do
  ip netns exec cl timeout 1 bash -c "</dev/tcp/203.0.113.1/$p" 2>/dev/null
done
for _ in $(seq 1 15); do
  if curl -s http://127.0.0.1:8080/state | grep -q '"type":"port_scan"'; then R_SCAN=ok; break; fi
  sleep 1
done
[ "$R_SCAN" = ok ] || { log "no port_scan event"; journalctl -u infrafence-agent --no-pager | grep -i portscan | tail -5; }

# ── attack: 8 logins as a user that doesn't exist ──
for i in $(seq 1 8); do
  ip netns exec cl timeout 5 ssh -o BatchMode=yes -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 -o PreferredAuthentications=password,publickey \
    "nosuchuser$i@203.0.113.1" true >/dev/null 2>&1
done

for _ in $(seq 1 30); do
  # A ban report for the attacker (the port scan event carries its address
  # too, so matching the address anywhere would pass too early).
  bans=$(curl -s http://127.0.0.1:8080/state | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin).get("bans") or []))' 2>/dev/null ||
         curl -s http://127.0.0.1:8080/state | sed -n 's/.*"bans":\(\[[^]]*\]\).*/\1/p')
  if grep -q '203.0.113.2' <<<"$bans"; then R_DETECT=ok; break; fi
  sleep 1
done
if [ "$R_DETECT" = ok ]; then
  journalctl -u infrafence-agent --no-pager | grep -q "journal" && SOURCE=journald || SOURCE=logfile
  [ -f /var/log/auth.log ] || [ -f /var/log/secure ] || SOURCE=journald
else
  log "no ban reported; agent log:"; journalctl -u infrafence-agent --no-pager -n 40
  log "diagnostics:"
  systemctl is-active rsyslog systemd-journald 2>&1 | sed 's/^/[diag] active: /'
  for f in /var/log/auth.log /var/log/secure; do
    [ -f "$f" ] && { echo "[diag] tail $f:"; tail -5 "$f"; }
  done
  echo "[diag] journal auth:"; journalctl --no-pager -n 10 SYSLOG_FACILITY=4 SYSLOG_FACILITY=10 2>&1 | tail -10
  echo "[diag] journal sshd unit:"; journalctl --no-pager -n 10 -u sshd -u ssh 2>&1 | tail -10
  ls -la /dev/log /run/systemd/journal/ 2>&1 | sed 's/^/[diag] /'
  logger -p authpriv.info "infrafence-diag-logger-test"; sleep 2
  echo "[diag] logger test in journal: $(journalctl --no-pager -n 50 2>/dev/null | grep -c infrafence-diag-logger-test)"
  grep -iE '^(SyslogFacility|LogLevel)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* 2>/dev/null | sed 's/^/[diag] /'
  journalctl -u rsyslog --no-pager -n 10 2>&1 | sed 's/^/[diag] rsyslog: /'
fi

if ipset list infrafence-bans 2>/dev/null | grep -q '^203.0.113.2' || iptables -S INFRAFENCE 2>/dev/null | grep -q '203.0.113.2'; then
  R_BAN=ok
fi
if [ "$R_BAN" = ok ] && ! ip netns exec cl timeout 3 bash -c '</dev/tcp/203.0.113.1/22' 2>/dev/null; then
  R_BLOCK=ok
fi

# ── preflight (read only) for the record ──
/usr/local/bin/infrafence-agent preflight 2>/dev/null | head -25 | sed 's/^/[preflight] /'

# ── uninstall: nothing may be left behind ──
bash /distro/install.sh --uninstall >/tmp/uninstall.log 2>&1
left=""
iptables -S 2>/dev/null | grep -q INFRAFENCE && left="$left iptables"
ipset list -n 2>/dev/null | grep -q infrafence && left="$left ipset"
systemctl list-unit-files 2>/dev/null | grep -q infrafence-agent && left="$left service"
[ -e /usr/local/bin/infrafence-agent ] && left="$left binary"
if [ -z "$left" ]; then R_UNINSTALL=ok; else log "left behind:$left"; fi
# And sshd still answers the attacker's address now that the ban is gone.
ip netns exec cl timeout 3 bash -c '</dev/tcp/203.0.113.1/22' 2>/dev/null || { R_UNINSTALL=fail; log "ssh still blocked after uninstall"; }

[ "$R_INSTALL$R_SERVICE$R_SCAN$R_DETECT$R_BAN$R_BLOCK$R_UNINSTALL" = okokokokokokok ]
