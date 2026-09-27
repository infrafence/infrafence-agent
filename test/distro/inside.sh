#!/usr/bin/env bash
# Runs inside one distro container (systemd as PID 1): installs the agent
# with the real install.sh against the mock dashboard, attacks SSH from
# another network namespace and checks detection, ban, blocking and a clean
# uninstall. Prints one RESULT line; exit status 0 only if everything passed.
set -uo pipefail

R_INSTALL=fail R_SERVICE=fail R_DETECT=fail R_BAN=fail R_BLOCK=fail R_UNINSTALL=fail
SOURCE=none
log() { echo "[inside] $*"; }
result() {
  echo "RESULT distro=${DISTRO} install=${R_INSTALL} service=${R_SERVICE} detect=${R_DETECT} source=${SOURCE} ban=${R_BAN} blocked=${R_BLOCK} uninstall=${R_UNINSTALL}"
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

# ── attack: 8 logins as a user that doesn't exist ──
for i in $(seq 1 8); do
  ip netns exec cl timeout 5 ssh -o BatchMode=yes -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 -o PreferredAuthentications=password,publickey \
    "nosuchuser$i@203.0.113.1" true >/dev/null 2>&1
done

for _ in $(seq 1 30); do
  st=$(curl -s http://127.0.0.1:8080/state)
  if grep -q '203.0.113.2' <<<"$st"; then R_DETECT=ok; break; fi
  sleep 1
done
if [ "$R_DETECT" = ok ]; then
  journalctl -u infrafence-agent --no-pager | grep -q "journal" && SOURCE=journald || SOURCE=logfile
  [ -f /var/log/auth.log ] || [ -f /var/log/secure ] || SOURCE=journald
else
  log "no ban reported; agent log:"; journalctl -u infrafence-agent --no-pager -n 40
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

[ "$R_INSTALL$R_SERVICE$R_DETECT$R_BAN$R_BLOCK$R_UNINSTALL" = okokokokokok ]
