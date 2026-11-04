# Sourced by inside.sh: the SSH logins of the last 30 days are known from
# the first minute after install. Before the agent is installed, the
# administrator (namespace "adm", 198.18.7.7) logs in with a key, as on a
# server in production for years; on hosts with an auth log file a rotated,
# gzipped log also holds a login of 198.18.7.8 from 10 days ago. After the
# install the agent must have read both (reported as imported), and a brute
# force from 198.18.7.7 must not be banned: the guard line is in the agent's
# log and the attack is reported as not banned. inside.sh's own attacker
# (203.0.113.2, no login) is banned as before.
#
# SSH service users: before the install a deploy account (ci-deploy,
# namespace "ci") also logs in 11 times, each from another /24 (198.19.N.9),
# as a CI runner does. The agent must log it as a service user, and a brute
# force from one of those addresses must be banned, while the
# administrator's address stays protected.
#
# loginhist_before runs before the install, loginhist_check after the main
# attack. Sets R_LOGINHIST; appends to EXTRA_RESULT and sets EXTRA_FAIL=1 on
# a failure.
R_LOGINHIST=fail
R_LHSERVICE=fail
LH_ADMIN=198.18.7.7
LH_CI_USER=ci-deploy
LH_CI_NETS=11
LH_CI_ATTACKER=198.19.5.9
LH_OLD=198.18.7.8
LH_OLD_EXPECTED=no

loginhist_before() {
  ip netns add adm
  ip link add veth20 type veth peer name veth21
  ip link set veth21 netns adm
  ip addr add 198.18.7.1/24 dev veth20 && ip link set veth20 up
  ip netns exec adm ip addr add $LH_ADMIN/24 dev veth21
  ip netns exec adm ip link set veth21 up
  ip netns exec adm ip link set lo up

  rm -f /tmp/admkey /tmp/admkey.pub
  ssh-keygen -q -t ed25519 -N '' -f /tmp/admkey
  # As in firewall.sh: logins are refused until systemd-user-sessions has
  # run, and without PAM a "!" password field refuses even a key.
  systemctl start systemd-user-sessions >/dev/null 2>&1 || true
  rm -f /run/nologin
  LH_SHADOW=""
  if getent shadow root | cut -d: -f2 | grep -q '^!'; then
    LH_SHADOW=/tmp/shadow.lh-test
    cp -p /etc/shadow "$LH_SHADOW" && usermod -p '*' root
  fi
  # On an Ubuntu host (the CI runners) AppArmor's unix-chkpwd profile is in
  # the host kernel and confines the container's unix_chkpwd too: it denies
  # the capabilities (dac_read_search, dac_override) that reading the RPM
  # family's /etc/shadow (mode 000) needs, pam_unix's account check fails
  # ("could not obtain user info (root)") and sshd closes the connection
  # ("Access denied for user root by PAM account configuration").
  # Readable by its owner for the login, mode restored afterwards.
  LH_SHMODE=$(stat -c %a /etc/shadow)
  [ "$LH_SHMODE" = 0 ] && chmod 400 /etc/shadow
  mkdir -p /root/.ssh && chmod 700 /root/.ssh
  cp -p /root/.ssh/authorized_keys /tmp/authorized_keys.lh 2>/dev/null || : >/tmp/authorized_keys.lh
  cat /tmp/admkey.pub >>/root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys
  if ip netns exec adm timeout 60 ssh -b $LH_ADMIN -i /tmp/admkey -o BatchMode=yes -o StrictHostKeyChecking=no \
       -o GSSAPIAuthentication=no -o PreferredAuthentications=publickey -o ConnectTimeout=10 \
       -o UserKnownHostsFile=/dev/null root@198.18.7.1 true </dev/null >/dev/null 2>/tmp/admssh.log; then
    log "loginhist: $LH_ADMIN logged in before the install"
  else
    log "loginhist: the administrator's login failed:"; tail -5 /tmp/admssh.log
    journalctl --no-pager -n 5 -u sshd -u ssh
  fi
  lh_ci_logins
  cp -p /tmp/authorized_keys.lh /root/.ssh/authorized_keys
  [ -n "$LH_SHADOW" ] && cp -p "$LH_SHADOW" /etc/shadow && rm -f "$LH_SHADOW"
  [ "$LH_SHMODE" = 0 ] && chmod 000 /etc/shadow

  # A login 10 days ago in a rotated, gzipped log (hosts with a log file).
  local f
  for f in /var/log/auth.log /var/log/secure; do
    [ -f "$f" ] || continue
    printf '%s %s sshd[4242]: Accepted publickey for deploy from %s port 50022 ssh2: ED25519 SHA256:lhtest\n' \
      "$(date -d '10 days ago' '+%b %e %H:%M:%S')" "$(cat /proc/sys/kernel/hostname)" "$LH_OLD" | gzip >"$f.9.gz"
    touch -d '9 days ago' "$f.9.gz"
    LH_OLD_EXPECTED=yes
    break
  done
}

# lh_ci_logins: the deploy account logs in from LH_CI_NETS networks
# (namespace "ci": 198.19.N.9, the server 198.19.N.1). The account is removed
# afterwards; its logins stay in the logs and login records.
lh_ci_logins() {
  local n okn=0
  ip netns add ci
  ip link add veth22 type veth peer name veth23
  ip link set veth23 netns ci
  ip link set veth22 up
  ip netns exec ci ip link set veth23 up
  ip netns exec ci ip link set lo up
  for n in $(seq 1 $LH_CI_NETS); do
    ip addr add 198.19.$n.1/24 dev veth22
    ip netns exec ci ip addr add 198.19.$n.9/24 dev veth23
  done
  useradd -m -s /bin/sh "$LH_CI_USER" >/dev/null 2>&1 && usermod -p '*' "$LH_CI_USER" >/dev/null 2>&1
  local home; home=$(getent passwd "$LH_CI_USER" | cut -d: -f6)
  if [ -z "$home" ]; then log "loginhist: $LH_CI_USER could not be created"; return; fi
  mkdir -p "$home/.ssh" && cp /tmp/admkey.pub "$home/.ssh/authorized_keys"
  chown -R "$LH_CI_USER:" "$home/.ssh" && chmod 700 "$home/.ssh" && chmod 600 "$home/.ssh/authorized_keys"
  for n in $(seq 1 $LH_CI_NETS); do
    ip netns exec ci timeout 30 ssh -b 198.19.$n.9 -i /tmp/admkey -o BatchMode=yes -o StrictHostKeyChecking=no \
      -o GSSAPIAuthentication=no -o PreferredAuthentications=publickey -o ConnectTimeout=10 \
      -o UserKnownHostsFile=/dev/null "$LH_CI_USER@198.19.$n.1" true </dev/null >/dev/null 2>/tmp/cissh.log && okn=$((okn + 1))
  done
  log "loginhist: $LH_CI_USER logged in from $okn of $LH_CI_NETS networks before the install"
  [ $okn = $LH_CI_NETS ] || tail -3 /tmp/cissh.log
  userdel -r "$LH_CI_USER" >/dev/null 2>&1
}

# lh_report_has IP prints the reported entry of IP (empty: none); the mock
# keeps the agent's compact JSON as sent.
lh_report_has() {
  curl -s http://127.0.0.1:8080/state | grep -o "{\"ip\":\"$1\",[^}]*}" | head -1
}

loginhist_check() {
  local ok=yes rep old=skip
  journalctl -u infrafence-agent --no-pager | grep -F '[ssh-logins]' | head -3 | sed 's/^/[loginhist] /'
  for _ in $(seq 1 30); do
    rep=$(lh_report_has $LH_ADMIN)
    [ -n "$rep" ] && break
    sleep 1
  done
  if ! grep -q '"imported":true' <<<"$rep" || ! grep -q '"root"' <<<"$rep"; then
    ok=no; log "loginhist: $LH_ADMIN not reported as imported: ${rep:-none}"
  fi
  if [ $LH_OLD_EXPECTED = yes ]; then
    rep=$(lh_report_has $LH_OLD)
    if grep -q '"imported":true' <<<"$rep" && grep -q '"deploy"' <<<"$rep"; then old=ok; else old=fail; ok=no; log "loginhist: $LH_OLD (rotated log) not reported: ${rep:-none}"; fi
  fi

  # The administrator mistypes: 8 failed logins.
  for i in $(seq 1 8); do
    ip netns exec adm timeout 5 ssh -b $LH_ADMIN -o BatchMode=yes -o StrictHostKeyChecking=no -o GSSAPIAuthentication=no \
      -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 -o PreferredAuthentications=password,publickey \
      "nosuchuser$i@198.18.7.1" true >/dev/null 2>&1
  done
  local guard=""
  for _ in $(seq 1 30); do
    guard=$(journalctl -u infrafence-agent --no-pager | grep -F "[guard] not banning $LH_ADMIN: SSH login on" | head -1)
    [ -n "$guard" ] && break
    sleep 1
  done
  sleep 3
  if [ -z "$guard" ]; then ok=no; log "loginhist: no guard line"; journalctl -u infrafence-agent --no-pager | grep -F "$LH_ADMIN" | tail -5; else log "loginhist: ${guard#*: }"; fi
  local state; state=$(curl -s http://127.0.0.1:8080/state)
  if grep -q "\"ip_address\":\"$LH_ADMIN\"" <<<"$state"; then
    ok=no; log "loginhist: $LH_ADMIN reported as banned"
  fi
  if ipset list infrafence-bans 2>/dev/null | grep -q "^$LH_ADMIN" || iptables -S INFRAFENCE 2>/dev/null | grep -q "$LH_ADMIN"; then
    ok=no; log "loginhist: $LH_ADMIN banned in the firewall"
  fi
  if ! grep -q '"action":"not_banned"' <<<"$state" || ! grep -q '"not_banned":"ssh_login"' <<<"$state"; then
    ok=no; log "loginhist: no brute_force event with action not_banned"
  fi
  ip netns exec adm timeout 3 bash -c '</dev/tcp/198.18.7.1/22' 2>/dev/null || { ok=no; log "loginhist: SSH unreachable from $LH_ADMIN"; }
  [ $ok = yes ] && R_LOGINHIST=ok
  lh_service_check
  EXTRA_RESULT="${EXTRA_RESULT:-} loginhist=${R_LOGINHIST} loginhist_rotated=${old} loginhist_service=${R_LHSERVICE}"
  [ "$R_LOGINHIST" = ok ] && [ "$R_LHSERVICE" = ok ] || EXTRA_FAIL=1
  ip netns pids adm 2>/dev/null | xargs -r kill 2>/dev/null
  ip netns pids ci 2>/dev/null | xargs -r kill 2>/dev/null
}

# lh_service_check: the deploy account is a service user (logged after the
# scan), and a brute force from one of its addresses is banned.
lh_service_check() {
  local sok=yes line banned=no
  line=$(journalctl -u infrafence-agent --no-pager | grep -F "[ssh-logins] service users (their logins protect no address): $LH_CI_USER ($LH_CI_NETS networks)" | head -1)
  if [ -n "$line" ]; then log "loginhist: ${line#*\[ssh-logins\] }"; else
    sok=no; log "loginhist: $LH_CI_USER not logged as a service user"
    journalctl -u infrafence-agent --no-pager | grep -F '[ssh-logins]' | tail -3
  fi
  for i in $(seq 1 8); do
    ip netns exec ci timeout 5 ssh -b $LH_CI_ATTACKER -o BatchMode=yes -o StrictHostKeyChecking=no -o GSSAPIAuthentication=no \
      -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 -o PreferredAuthentications=password,publickey \
      "nosuchuser$i@198.19.5.1" true >/dev/null 2>&1
  done
  for _ in $(seq 1 30); do
    if ipset list infrafence-bans 2>/dev/null | grep -q "^$LH_CI_ATTACKER" || iptables -S INFRAFENCE 2>/dev/null | grep -q "$LH_CI_ATTACKER"; then
      banned=yes; break
    fi
    sleep 1
  done
  if [ $banned = no ]; then
    sok=no; log "loginhist: $LH_CI_ATTACKER (only $LH_CI_USER logged in from it) not banned"
    journalctl -u infrafence-agent --no-pager | grep -F "$LH_CI_ATTACKER" | tail -5
  fi
  # The administrator's address is still protected.
  if ipset list infrafence-bans 2>/dev/null | grep -q "^$LH_ADMIN" || iptables -S INFRAFENCE 2>/dev/null | grep -q "$LH_ADMIN"; then
    sok=no; log "loginhist: $LH_ADMIN banned after the service user's attack"
  fi
  [ $sok = yes ] && R_LHSERVICE=ok
}
