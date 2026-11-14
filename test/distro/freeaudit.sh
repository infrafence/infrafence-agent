#!/usr/bin/env bash
# The free server audit on a server without InfraFence (runs inside one
# distro container, before inside.sh): an SSH attack from another network
# namespace, a database port open to everyone and a web access log with
# attacks, then
#   - `infrafence-agent audit --no-upload --json`: a valid schema 1 report
#     (test/distro/auditcheck), the attack and the open port in it, no host
#     name or server address, in at most 60 seconds;
#   - nothing changed: every file outside /proc, /sys, /dev, /run (size,
#     mtime, mode, owner), the firewall rules, the systemd units and the
#     processes, before and after;
#   - audit.sh as `curl | sh` runs it, with the shell that is /bin/sh here
#     (dash on Debian and Ubuntu) and dash where installed: download,
#     checksum and signature from the mock dashboard (a copy of audit.sh with
#     the mock's throwaway release key), --no-upload, then an upload to the
#     mock's /api/v1/audit/report and the link it prints;
#   - the real audit.sh refuses the mock's binary (not signed with the
#     InfraFence release key) and runs nothing; without root it says why.
# Fixtures are removed at the end, so inside.sh starts from a clean host.
# Prints one AUDITRESULT line.
set -uo pipefail
export LC_ALL=C

R_JSON=fail R_READONLY=fail R_TIME=fail R_SCRIPT=fail R_UPLOAD=fail R_BADSIG=fail R_NONROOT=fail
SECS=-1
log() { echo "[freeaudit] $*"; }
result() {
  echo "AUDITRESULT audit=$( [ "$R_JSON$R_READONLY$R_TIME$R_SCRIPT$R_UPLOAD$R_BADSIG$R_NONROOT" = okokokokokokok ] && echo ok || echo fail) json=${R_JSON} readonly=${R_READONLY} time=${R_TIME}(${SECS}s) script=${R_SCRIPT} upload=${R_UPLOAD} badsig=${R_BADSIG} nonroot=${R_NONROOT}"
}
cleanup() {
  [ -n "${MOCK_PID:-}" ] && kill "$MOCK_PID" 2>/dev/null
  ip netns del au 2>/dev/null
  ip link del vau0 2>/dev/null
  rm -f /tmp/au-access.log
  rm -rf /tmp/au-noossl /tmp/au-planted /tmp/au-planted-ran
  if [ -n "${OSSL_TEMP:-}" ]; then
    { [ "$OSSL_TEMP" != unknown ] && dnf history undo -y -q "$OSSL_TEMP" >/dev/null 2>&1; } \
      || rpm -e openssl >/dev/null 2>&1 || log "could not remove the openssl installed for the test"
    command -v openssl >/dev/null && log "openssl still installed after the test"
  fi
}
trap 'cleanup; result' EXIT

PORT=8099
MOCK=http://127.0.0.1:$PORT

# ── fixtures (before the first snapshot) ──
ip netns add au
ip link add vau0 type veth peer name vau1
ip link set vau1 netns au
ip addr add 192.0.2.1/24 dev vau0 && ip link set vau0 up
ip netns exec au ip addr add 192.0.2.2/24 dev vau1
ip netns exec au ip link set vau1 up
ip netns exec au ip link set lo up
ssh-keygen -A >/dev/null 2>&1
systemctl enable --now ssh >/dev/null 2>&1 || systemctl enable --now sshd >/dev/null 2>&1
sleep 1
for i in $(seq 1 6); do
  ip netns exec au timeout 5 ssh -o BatchMode=yes -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 -o PreferredAuthentications=password,publickey \
    "auditprobe$i@192.0.2.1" true >/dev/null 2>&1
done
/distro/mockapi -addr 127.0.0.1:$PORT -binary /distro/agent -sig-pub /tmp/au-key.pub >/tmp/au-mock.log 2>&1 &
MOCK_PID=$!
for _ in $(seq 1 20); do curl -fsS "$MOCK/audit-state" >/dev/null 2>&1 && break; sleep 0.5; done
# A database port open to everyone (the mock listens, IPv4 any address).
curl -fsS "$MOCK/listen?addr=0.0.0.0:3306&net=tcp4" >/dev/null || log "could not open 3306"
now=$(date -u +%d/%b/%Y:%H:%M:%S)
{
  echo "198.51.100.77 - - [$now +0000] \"GET /.env HTTP/1.1\" 404 153 \"-\" \"Mozilla/5.0\""
  echo "198.51.100.77 - - [$now +0000] \"GET /wp-config.php.bak HTTP/1.1\" 404 153 \"-\" \"Mozilla/5.0\""
  echo "198.51.100.78 - - [$now +0000] \"GET / HTTP/1.1\" 200 10 \"-\" \"sqlmap/1.7\""
  echo "198.51.100.79 - - [$now +0000] \"GET /about HTTP/1.1\" 200 10 \"-\" \"Mozilla/5.0\""
} >/tmp/au-access.log
sleep 2

# ── snapshots ──
snap_files() {
  find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /var/log/journal \
      -o -path '/tmp/au-*' -o -path /tmp/freeaudit-snap \) -prune -o -printf '%p|%y|%s|%T@|%m|%U\n' 2>/dev/null \
    | grep -vE '^(/tmp|/var/tmp)\|' | sort
}
snap_state() {
  { command -v iptables-save >/dev/null && iptables-save 2>/dev/null | grep -v '^#'
    command -v nft >/dev/null && nft list ruleset 2>/dev/null
    systemctl list-units --all --no-legend --plain 2>/dev/null | awk '{print $1, $3, $4}' | grep -v '^session-'
    systemctl list-unit-files --no-legend 2>/dev/null | awk '{print $1, $2}'
  } | sort
}
# Processes started before the audit: none may be left behind by it.
snap_procs() { ps -eo pid=,comm= | awk '{print $1, $2}' | sort; }

# The container's boot must be over first: a start job still running (on
# Ubuntu 20.04 a getty waits 90 s for a console device) would change the
# units between the two snapshots.
if command -v systemctl >/dev/null; then
  timeout 150 systemctl is-system-running --wait >/dev/null 2>&1 || true
fi
# EL8's rpm keeps a Berkeley DB environment (/var/lib/rpm/__db.NNN) that
# its first reader creates. A fresh image (GitHub's runners) has none, an
# image built locally may: removed here (a cache rpm regenerates; nothing
# uses rpm in this container now), every run checks the audit creating them.
if ls /var/lib/rpm/__db.* >/dev/null 2>&1 && ! pgrep -x 'rpm|dnf|yum|dnf-automatic' >/dev/null; then
  rm -f /var/lib/rpm/__db.*
fi
if [ -d /var/lib/rpm ]; then
  log "rpm Berkeley DB environment files before the audit: $(find /var/lib/rpm -maxdepth 1 -name '__db.*' | wc -l)"
fi
mkdir -p /tmp/freeaudit-snap
S=/tmp/freeaudit-snap
snap_files >$S/files.before; snap_state >$S/state.before; snap_procs >$S/procs.before

# ── the audit itself ──
start=$(date +%s)
WEB_LOG_PATH=/tmp/au-access.log timeout 120 /distro/agent audit --no-upload --json >/tmp/au-report.json 2>/tmp/au-report.err
rc=$?
SECS=$(( $(date +%s) - start ))
[ "$rc" = 0 ] && [ "$SECS" -le 60 ] && R_TIME=ok
[ "$rc" = 0 ] || { log "audit exit $rc"; tail -5 /tmp/au-report.err; }

# The text form too (what a person reads), nothing sent.
WEB_LOG_PATH=/tmp/au-access.log timeout 120 /distro/agent audit --no-upload >/tmp/au-report.txt 2>&1 \
  && grep -q "Nothing was sent (--no-upload)." /tmp/au-report.txt \
  && grep -q "Findings, worst first" /tmp/au-report.txt || { R_TIME=fail; log "text report:"; tail -20 /tmp/au-report.txt; }

sleep 1
snap_files >$S/files.after; snap_state >$S/state.after; snap_procs >$S/procs.after

host=$(cat /proc/sys/kernel/hostname)
addrs=$(ip -o addr show | awk '{print $4}' | cut -d/ -f1 | grep -vE '^(127\.0\.0\.1|::1)$' | tr '\n' ',')
if /distro/auditcheck -report /tmp/au-report.json -forbid "$host,$addrs" -min-ssh 6 -top-ip 192.0.2.2 -db-port 3306; then
  R_JSON=ok
else
  log "report:"; head -c 4000 /tmp/au-report.json; echo
fi
# Web attacks from the fixture log: 3 suspicious requests from 2 addresses.
grep -q '"web_suspicious_requests": 3' /tmp/au-report.json && grep -q '"web_unique_ips": 2' /tmp/au-report.json \
  || { R_JSON=fail; log "web attacks not counted"; grep -E '"web_' /tmp/au-report.json; }

R_READONLY=ok
# comm (coreutils): diff is not installed on every image. "<" before only,
# ">" after only.
changes() { comm -3 "$1" "$2" | sed -e 's/^\t/> /' -e 't' -e 's/^/< /'; }
# Tolerated, and only these:
#   - a directory whose size alone changed (overlayfs reports a new size when
#     a directory is copied up to the container's layer; mtime unchanged);
#   - on RPM distributions, rpm's SQLite shared-memory index
#     (rpmdb.sqlite-shm in /var/lib/rpm or /usr/lib/sysimage/rpm) and, on
#     EL8, the Berkeley DB environment files /var/lib/rpm/__db.NNN, created
#     by the first reader of a fresh image or modified (same type, mode and
#     owner; never one removed), with the mtime of /var/lib/rpm itself:
#     every reader of the rpm database does this, the database is unchanged and the mtime of dnf's
#     cache directories (dnf -C takes a lock file there and removes it);
#   - lines appended to the system log by other programs (printed below;
#     containers share the kernel, so rsyslog also logs the veth events of
#     the containers starting next to this one) and rsyslog's journal
#     cursor (/var/lib/rsyslog/imjournal.state).
tolerated() {
  # Input: path|type|size|mtime|mode|uid|side, side "<" (before only) or
  # ">" (after only); a path in both snapshots comes as a before/after pair.
  awk -F'|' '
    { key=$1 "|" $2; rest=$4 "|" $5 "|" $6; own=$5 "|" $6; size=$3
      if (seen[key] == "") { seen[key]=$0; r[key]=rest; o[key]=own; s[key]=size; side[key]=$7; next }
      # second occurrence of the same path: both lines are its before/after
      sameMeta = (r[key] == rest); sameOwn = (o[key] == own)
      if ($2 == "d" && sameMeta) { delete seen[key]; next }          # size only
      if ($1 ~ /^\/(var\/lib|usr\/lib\/sysimage)\/rpm\/rpmdb\.sqlite-shm$/) { delete seen[key]; next }
      if ($1 ~ /^\/var\/lib\/rpm\/__db\.[0-9]+$/ && $2 == "f" && sameOwn) { delete seen[key]; next }
      if ($1 == "/var/lib/rpm" && $2 == "d" && sameOwn) { delete seen[key]; next }
      if ($2 == "d" && $1 ~ /^\/var\/cache\/(dnf|yum)(\/|$)/) { delete seen[key]; next }
      if ($1 ~ /^\/var\/log\/(messages|syslog|kern\.log)$/) { logs[$1]=1; delete seen[key]; next }
      if ($1 ~ /^\/var\/lib\/rsyslog(\/imjournal\.state)?$/) { delete seen[key]; next }
      print seen[key]; print $0; delete seen[key] }
    END {
      for (k in seen) {
        split(seen[k], f, "|")
        # created by rpm (EL8 Berkeley DB environment), never one removed
        if (side[k] == ">" && f[2] == "f" && f[1] ~ /^\/var\/lib\/rpm\/__db\.[0-9]+$/) continue
        print seen[k]
      }
      for (l in logs) print "LOG " l }'
}
changes $S/files.before $S/files.after | sed -E 's/^([<>]) (.*)$/\2|\1/' | sort | tolerated >$S/files.diff
for l in $(sed -n 's/^LOG //p' $S/files.diff); do
  before=$(awk -F'|' -v p="$l" '$1==p {print $3}' $S/files.before)
  log "appended to $l during the audit:"; tail -c +"$((before + 1))" "$l" | sed 's/^/    /' | head -20
done
sed -i '/^LOG /d' $S/files.diff
if [ -s $S/files.diff ]; then
  R_READONLY=fail; log "files changed:"; head -40 $S/files.diff
fi
changes $S/state.before $S/state.after >$S/state.diff
if [ -s $S/state.diff ]; then
  R_READONLY=fail; log "firewall/units changed:"; head -40 $S/state.diff
fi
# New processes left running (the snapshot's own ps, awk and sort excluded,
# and systemd's helpers: udev workers handle the device events of the
# containers starting next to this one, which share the kernel).
left=$(comm -13 $S/procs.before $S/procs.after | grep -vE ' (ps|awk|sort|sleep|systemd-.*|\(sd-.*|\(udev-worker\))$')
if [ -n "$left" ]; then
  R_READONLY=fail; log "processes left behind:"; echo "$left"
fi
ls -d /tmp/infrafence-audit* /var/tmp/infrafence-audit* 2>/dev/null && { R_READONLY=fail; log "temp dir left behind"; }

# Root's PATH with a planted directory first: the audit runs commands from
# the system directories only, so none of these may run.
mkdir -p /tmp/au-planted
for c in systemctl sshd ss nginx apache2ctl httpd iptables iptables-save nft ufw firewall-cmd journalctl \
         apt-get dnf yum rpm php php-fpm ip docker conntrack uname id hostname cat ls; do
  printf '#!/bin/sh\ntouch /tmp/au-planted-ran\nexit 1\n' >/tmp/au-planted/$c; chmod 755 /tmp/au-planted/$c
done
PATH=/tmp/au-planted:$PATH WEB_LOG_PATH=/tmp/au-access.log timeout 120 /distro/agent audit --no-upload --json >/dev/null 2>/tmp/au-planted.err
rc=$?
if [ $rc -ne 0 ] || [ -e /tmp/au-planted-ran ]; then
  R_READONLY=fail; log "a program planted in PATH ran (exit $rc)"; tail -5 /tmp/au-planted.err
fi
rm -rf /tmp/au-planted /tmp/au-planted-ran /tmp/au-planted.err

# ── audit.sh, as curl | sh runs it ──
key=$(cat /tmp/au-key.pub)
awk -v key="$key" '
  /^-----BEGIN PUBLIC KEY-----$/ && !done { print key; skip=1; next }
  skip && /^-----END PUBLIC KEY-----$/ { skip=0; done=1; next }
  !skip { print }' /distro/audit.sh >/tmp/au-test-audit.sh
VERIFIED="Checksum and release signature verified."

# Without openssl (or base64) audit.sh stops before downloading anything.
# Where openssl is installed, it is hidden from PATH for this one run.
nopath=$PATH
if command -v openssl >/dev/null; then
  rm -rf /tmp/au-noossl; mkdir /tmp/au-noossl
  for d in /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin; do
    for f in "$d"/*; do
      [ -e "$f" ] || continue
      b=${f##*/}
      [ "$b" = openssl ] || [ -e "/tmp/au-noossl/$b" ] || ln -s "$f" "/tmp/au-noossl/$b"
    done
  done
  nopath=/tmp/au-noossl
fi
hits0=$(curl -fsS $MOCK/release-hits | grep -o '"hits":[0-9]*')
out=$(timeout 60 env PATH="$nopath" RELEASE_BASE=$MOCK/releases sh -s </tmp/au-test-audit.sh 2>&1)
rc=$?
hits1=$(curl -fsS $MOCK/release-hits | grep -o '"hits":[0-9]*')
rm -rf /tmp/au-noossl
R_SCRIPT=ok
if [ $rc -eq 0 ] || ! echo "$out" | grep -q "openssl is needed to verify the agent's release signature" \
   || ! echo "$out" | grep -q "Nothing was downloaded and nothing on this server was changed." \
   || ! echo "$out" | grep -q "dnf install -y openssl" || [ "$hits0" != "$hits1" ] \
   || ls -d /tmp/infrafence-audit* /var/tmp/infrafence-audit* /dev/shm/infrafence-audit* >/dev/null 2>&1; then
  R_SCRIPT=fail; log "without openssl (exit $rc, release requests $hits0 -> $hits1):"; echo "$out" | tail -12
fi

# The rest needs openssl: minimal images (Rocky/Alma 8, Fedora, Amazon
# Linux) get it for these tests and lose it again in cleanup, so inside.sh
# sees the image as it was.
if ! command -v openssl >/dev/null; then
  if dnf install -y -q openssl >/dev/null 2>&1 || yum install -y -q openssl >/dev/null 2>&1; then
    # The whole transaction is undone at the end: on EL8 it also adds
    # openssl-pkcs11 (which needs openssl) and upgrades openssl-libs.
    OSSL_TEMP=$(dnf history list 2>/dev/null | awk '$1 ~ /^[0-9]+$/ {print $1; exit}')
    OSSL_TEMP=${OSSL_TEMP:-unknown}
    log "openssl installed for the audit.sh tests (transaction $OSSL_TEMP, undone at the end)"
  else
    log "openssl could not be installed: audit.sh tests fail"
  fi
fi
shells="sh"
command -v dash >/dev/null && shells="$shells dash"
for shell in $shells; do
  out=$(RELEASE_BASE=$MOCK/releases WEB_LOG_PATH=/tmp/au-access.log timeout 120 "$shell" -s -- --no-upload </tmp/au-test-audit.sh 2>&1)
  rc=$?
  if [ $rc -ne 0 ] || ! echo "$out" | grep -q "$VERIFIED" \
     || ! echo "$out" | grep -q "Note: using a non-default release base (RELEASE_BASE): $MOCK/releases" \
     || echo "$out" | grep -q "non-default upload URL" \
     || ! echo "$out" | grep -q "Nothing was sent (--no-upload)." \
     || ! echo "$out" | grep -q '"schema": 1' \
     || ls -d /tmp/infrafence-audit* /var/tmp/infrafence-audit* /dev/shm/infrafence-audit* >/dev/null 2>&1; then
    R_SCRIPT=fail; log "audit.sh with $shell (exit $rc):"; echo "$out" | tail -20
  fi
done
[ "$(curl -fsS $MOCK/audit-state | grep -o '"reports":[0-9]*')" = '"reports":0' ] || { R_SCRIPT=fail; log "--no-upload sent a report"; }

# Upload to the mock dashboard.
out=$(RELEASE_BASE=$MOCK/releases INFRAFENCE_AUDIT_URL=$MOCK/api/v1/audit/report timeout 120 sh -s </tmp/au-test-audit.sh 2>&1)
rc=$?
state=$(curl -fsS $MOCK/audit-state)
if [ $rc -eq 0 ] && echo "$out" | grep -q "Your report: $MOCK/tools/server-audit/r#Tk7p3QxV9mZr2LcY8bNw4HsJ6aDf1GeK5uQo" \
   && echo "$out" | grep -q "Everything that is sent to $MOCK/api/v1/audit/report" \
   && echo "$out" | grep -q "Note: using a non-default upload URL (INFRAFENCE_AUDIT_URL): $MOCK/api/v1/audit/report" \
   && ! echo "$out" | grep -q "Uploading in 5 s" \
   && echo "$state" | grep -q '"reports":1' && echo "$state" | grep -q '"invalid":0'; then
  # What the mock received is a valid report too.
  curl -fsS $MOCK/audit-last >/tmp/au-uploaded.json
  /distro/auditcheck -report /tmp/au-uploaded.json -forbid "$host,$addrs" && R_UPLOAD=ok
fi
[ "$R_UPLOAD" = ok ] || { log "upload (exit $rc):"; echo "$out" | tail -15; echo "$state" | head -c 600; echo; }

# A checksum that doesn't match: refused, nothing run (with or without openssl).
curl -fsS "$MOCK/checksum?mode=bad" >/dev/null
out=$(RELEASE_BASE=$MOCK/releases timeout 120 sh -s -- --no-upload </tmp/au-test-audit.sh 2>&1)
rc=$?
curl -fsS "$MOCK/checksum?mode=ok" >/dev/null
R_BADSIG=ok
if [ $rc -eq 0 ] || ! echo "$out" | grep -q "checksum mismatch" || echo "$out" | grep -q '"schema"' \
   || ls -d /tmp/infrafence-audit* >/dev/null 2>&1; then
  R_BADSIG=fail; log "bad checksum accepted (exit $rc):"; echo "$out" | tail -10
fi
# The real audit.sh: the mock's binary is not signed by InfraFence.
if command -v openssl >/dev/null; then
  out=$(RELEASE_BASE=$MOCK/releases timeout 120 sh -s -- --no-upload </distro/audit.sh 2>&1)
  rc=$?
  if [ $rc -eq 0 ] || ! echo "$out" | grep -q "release signature is not valid" || echo "$out" | grep -q '"schema"' \
     || ls -d /tmp/infrafence-audit* >/dev/null 2>&1; then
    R_BADSIG=fail; log "bad signature accepted (exit $rc):"; echo "$out" | tail -10
  fi
fi

# Without root: it says why it needs root, and does nothing.
if command -v setpriv >/dev/null; then
  out=$(setpriv --reuid=65534 --regid=65534 --clear-groups sh -s </distro/audit.sh 2>&1)
  rc=$?
  if [ $rc -eq 1 ] && echo "$out" | grep -q "The audit needs root: it reads the authentication logs"; then
    R_NONROOT=ok
  else
    log "non-root (exit $rc):"; echo "$out" | tail -5
  fi
else
  R_NONROOT=ok; log "setpriv not available: non-root case skipped"
fi

# The text summary, for the record.
sed -n '1,40p' /tmp/au-report.txt | sed 's/^/[summary] /'
rm -rf /tmp/freeaudit-snap /tmp/au-key.pub /tmp/au-test-audit.sh /tmp/au-uploaded.json
