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
  echo "RESULT distro=${DISTRO} install=${R_INSTALL} service=${R_SERVICE} portscan=${R_SCAN} detect=${R_DETECT} source=${SOURCE} ban=${R_BAN} blocked=${R_BLOCK} uninstall=${R_UNINSTALL}${EXTRA_RESULT:-}"
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

# ── dry run: no token needed, nothing changed, and the release download from
# GitHub works (on RHEL-family hosts the dry run once replaced curl's CAs
# with ISRG Root X1 alone, and github.com failed) ──
R_DRYRUN=fail
anchors=$(ls /etc/pki/ca-trust/source/anchors 2>/dev/null)
if bash /distro/install.sh --dry-run >/tmp/dryrun.log 2>&1 \
   && grep -q "Dry run — nothing was installed or changed" /tmp/dryrun.log \
   && grep -q "needs --token" /tmp/dryrun.log \
   && [ ! -e /usr/local/bin/infrafence-agent ] && [ ! -e /etc/infrafence ] \
   && [ "$(ls /etc/pki/ca-trust/source/anchors 2>/dev/null)" = "$anchors" ] \
   && ! ls /tmp/infrafence-ca-* /tmp/infrafence-isrg-* >/dev/null 2>&1; then
  R_DRYRUN=ok
else
  log "dry run failed:"; tail -20 /tmp/dryrun.log; ls -d /tmp/infrafence-* 2>/dev/null
fi
# The Let's Encrypt root is embedded in install.sh (never downloaded): its
# fingerprint is pinned, and a copy that doesn't match is not trusted.
isrg_fp=96:BC:EC:06:26:49:76:F3:74:60:77:9A:CF:28:C5:A7:CF:E8:A3:C0:AA:E1:1A:8F:FC:EE:05:C0:BD:DF:08:C6
if command -v openssl >/dev/null; then
  got=$(awk '/<<.ISRGEOF/{f=1;next} /^ISRGEOF$/{f=0} f' /distro/install.sh | openssl x509 -noout -fingerprint -sha256 | cut -d= -f2)
  [ "$got" = "$isrg_fp" ] || { R_DRYRUN=fail; log "embedded ISRG root: fingerprint $got"; }
  [ "$(grep -v '^ *#' /distro/install.sh | grep -c 'letsencrypt.org/certs')" = 0 ] \
    || { R_DRYRUN=fail; log "install.sh still downloads the root"; }
  if command -v update-ca-trust >/dev/null; then
    # One character of the certificate changed: refused, and the dry run
    # goes on without it (RHEL's curl keeps its own CAs).
    awk '/<<.ISRGEOF/{f=1;print;next} /^ISRGEOF$/{f=0} f&&!done&&/^MII/{sub(/^MII../,"MIIAA");done=1} {print}' \
      /distro/install.sh >/tmp/install-badroot.sh
    if ! bash /tmp/install-badroot.sh --dry-run >/tmp/dryrun-badroot.log 2>&1 \
       || ! grep -q "does not match its fingerprint" /tmp/dryrun-badroot.log \
       || grep -q "Let's Encrypt root CA bundle" /tmp/dryrun-badroot.log \
       || ls /tmp/infrafence-ca-* >/dev/null 2>&1; then
      R_DRYRUN=fail; log "dry run with a bad root:"; tail -20 /tmp/dryrun-badroot.log
    fi
    rm -f /tmp/install-badroot.sh
  fi
fi
# A failed download stops with the troubleshooting link and tries no mirror.
RELEASE_BASE=http://127.0.0.1:9/releases bash /distro/install.sh --dry-run >/tmp/dryrun-fail.log 2>&1
rc=$?
if [ $rc -ne 1 ] || ! grep -q "infrafence.com/docs/troubleshooting" /tmp/dryrun-fail.log \
   || grep -q "infrafence.com/downloads" /tmp/dryrun-fail.log; then
  R_DRYRUN=fail; log "failed download: rc=$rc"; tail -20 /tmp/dryrun-fail.log
fi
# The checksum is required: missing or wrong, nothing is kept; only
# --skip-checksum (unsafe) goes on without it.
tmps=$(find /tmp -mindepth 1 -maxdepth 1 | wc -l)
for mode in missing bad; do
  curl -s "http://127.0.0.1:8080/checksum?mode=$mode" >/dev/null
  RELEASE_BASE=http://127.0.0.1:8080/releases bash /distro/install.sh --dry-run >/tmp/dryrun-sum.log 2>&1
  rc=$?
  want="Could not download the checksum"; [ $mode = bad ] && want="Checksum mismatch"
  if [ $rc -ne 1 ] || ! grep -q "$want" /tmp/dryrun-sum.log || ! grep -q "docs/troubleshooting" /tmp/dryrun-sum.log \
     || [ "$(find /tmp -mindepth 1 -maxdepth 1 | wc -l)" -ne $((tmps + 1)) ]; then
    R_DRYRUN=fail; log "checksum $mode: rc=$rc"; tail -10 /tmp/dryrun-sum.log; ls -la /tmp
  fi
  rm -f /tmp/dryrun-sum.log
done
if ! RELEASE_BASE=http://127.0.0.1:8080/releases bash /distro/install.sh --dry-run --skip-checksum >/tmp/dryrun-skip.log 2>&1 \
   || ! grep -q "NOT verified" /tmp/dryrun-skip.log; then
  R_DRYRUN=fail; log "--skip-checksum:"; tail -10 /tmp/dryrun-skip.log
fi
curl -s "http://127.0.0.1:8080/checksum?mode=ok" >/dev/null
EXTRA_RESULT="${EXTRA_RESULT:-} dryrun=${R_DRYRUN}"
[ "$R_DRYRUN" = ok ] || EXTRA_FAIL=1

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

# ── hosting panel commands (test/distro/panel.sh) ──
. /distro/panel.sh

# ── closed ports and egress blocks (test/distro/firewall.sh) ──
. /distro/firewall.sh

# ── trust badge verification file in an nginx site (test/distro/trust.sh) ──
. /distro/trust.sh

# ── virtual patch and quarantine restore (test/distro/waf.sh) ──
. /distro/waf.sh

# ── SSH checks read the effective configuration (test/distro/sshconfig.sh) ──
. /distro/sshconfig.sh

# ── PHP configuration: detection, verified fix and revert (test/distro/php.sh) ──
. /distro/php.sh

# ── dashboard refusing the agent, restart, local expiry (test/distro/offline.sh) ──
. /distro/offline.sh

# ── refused past the limit: protection switched off, then back (test/distro/disable.sh) ──
. /distro/disable.sh

# ── CSF on the same host: csf -r, repaired within seconds (test/distro/csf.sh) ──
. /distro/csf.sh

# ── uninstall: nothing may be left behind ──
bash /distro/install.sh --uninstall >/tmp/uninstall.log 2>&1
left=""
iptables -S 2>/dev/null | grep -q INFRAFENCE && left="$left iptables"
ip6tables -S 2>/dev/null | grep -q INFRAFENCE && left="$left ip6tables"
[ -e /var/lib/infrafence/firewall-state.json ] && left="$left firewall-state"
[ -e /var/lib/infrafence/panel-state.json ] && left="$left panel-state"
[ -e /var/lib/infrafence/protection-state.json ] && left="$left protection-state"
[ -e /var/lib/infrafence/trust-state.json ] && left="$left trust-state"
[ -e /run/infrafence/panel.sock ] && left="$left panel-socket"
ipset list -n 2>/dev/null | grep -q infrafence && left="$left ipset"
systemctl list-unit-files 2>/dev/null | grep -q infrafence-agent && left="$left service"
[ -e /usr/local/bin/infrafence-agent ] && left="$left binary"
ls /etc/php/*/*/conf.d/zz-infrafence-hardening.ini /etc/php.d/zz-infrafence-hardening.ini >/dev/null 2>&1 && left="$left php-dropin"
if [ -z "$left" ]; then R_UNINSTALL=ok; else log "left behind:$left"; fi
# And sshd still answers the attacker's address now that the ban is gone.
ip netns exec cl timeout 3 bash -c '</dev/tcp/203.0.113.1/22' 2>/dev/null || { R_UNINSTALL=fail; log "ssh still blocked after uninstall"; }

[ "$R_INSTALL$R_SERVICE$R_SCAN$R_DETECT$R_BAN$R_BLOCK$R_UNINSTALL" = okokokokokokok ] && [ -z "${EXTRA_FAIL:-}" ]
