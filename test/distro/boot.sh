#!/usr/bin/env bash
# A ruleset saved while the agent runs restores at a real boot. Run by
# run.sh after inside.sh, in two phases around a restart of the container
# (a new network namespace: no rules, no ipsets, and systemd boots again,
# so the restore services run in their real order):
#   save   iptables-persistent (apt) or iptables-services (dnf), plus on
#          apt HestiaCP's own save and boot unit exactly as v-update-firewall
#          writes them; the agent installed with install.sh; the unit
#          disabled, then removed and masked, by the administrator and left
#          so by the agent's restarts, put back by "boot-sets --install",
#          then removed with its marker (a server set up before it existed)
#          and installed again by the agent's start; a customer
#          rule (IPv4 and IPv6); the ruleset saved while the agent runs. In
#          a fresh network namespace (no sets, as at boot) the saved file
#          is refused ("Set infrafence-... doesn't exist"), and loads once
#          "infrafence-agent boot-sets" has run there.
#   check  after the boot: infrafence-ipsets.service ran, every restore
#          service loaded its file, the customer's rules are back. Then
#          the uninstall warns about each saved file that still holds the
#          agent's chains, removes the unit, and the file saved again with
#          the command it names restores without any set.
# Prints "BOOTRESULT boot=ok|fail|skip[:reason]".
set -uo pipefail
phase=${1:-}
R_BOOT=fail
fails=""
bf() { fails="$fails $1"; echo "[boot] $1${2:+: $2}"; }
trap 'if [ -n "$fails" ]; then R_BOOT=fail; fi; echo "BOOTRESULT boot=$R_BOOT${fails:+ boot_fail=$(echo $fails | tr " " ,)}"' EXIT

V4RULE="-s 198.51.100.77/32 -p tcp -m tcp --dport 2222 -m comment --comment customer-rule -j DROP"
V6RULE="-s 2001:db8::77/128 -p tcp -m tcp --dport 2222 -m comment --comment customer-rule -j DROP"

# has OUTPUT PATTERN (the output captured first: "cmd | grep -q" fails
# under pipefail when grep exits before cmd has written everything).
has() { grep -q -- "$2" <<<"$1"; }

mockapi() {
  curl -s -o /dev/null http://127.0.0.1:8080/state && return 0
  (setsid /distro/mockapi -binary /distro/agent >/tmp/mockapi-boot.log 2>&1 &)
  sleep 1
}

# Files restored at boot on this host, one per line.
saved_files() {
  if command -v netfilter-persistent >/dev/null; then
    echo /etc/iptables/rules.v4
    echo /etc/iptables.rules
  else
    echo /etc/sysconfig/iptables
  fi
}

# restores_without_sets FILE: loads in a network namespace with no sets.
restores_without_sets() {
  ip netns add bootns 2>/dev/null
  ip netns exec bootns iptables-restore <"$1" >/tmp/boot-restore.log 2>&1
  local rc=$?
  ip netns del bootns
  return $rc
}

save_now() {
  if command -v netfilter-persistent >/dev/null; then
    netfilter-persistent save >/tmp/boot-save.log 2>&1 || { bf save "netfilter-persistent save"; cat /tmp/boot-save.log; }
    # HestiaCP's v-update-firewall, Debian branch.
    /sbin/iptables-save | sed -e 's/[[0-9]\+:[0-9]\+]/[0:0]/g' -e '/^-A fail2ban-[A-Z]\+ -s .\+$/d' >/etc/iptables.rules
  else
    # What "service iptables save" runs (no "service" in the images).
    { /usr/libexec/iptables/iptables.init save && /usr/libexec/iptables/ip6tables.init save; } >/tmp/boot-save.log 2>&1 \
      || { bf save "iptables.init save"; cat /tmp/boot-save.log; }
  fi
}

if [ "$phase" = save ]; then
  mockapi
  if command -v apt-get >/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    printf 'iptables-persistent iptables-persistent/autosave_v4 boolean false\niptables-persistent iptables-persistent/autosave_v6 boolean false\n' | debconf-set-selections
    if ! apt-get install -y -qq iptables-persistent >/tmp/boot-pkg.log 2>&1; then
      R_BOOT=skip:no-iptables-persistent; tail -5 /tmp/boot-pkg.log; exit 0
    fi
    # HestiaCP's boot unit, as v-update-firewall writes it (its
    # ExecStartPre loads HestiaCP's own ipset lists: not here).
    cat >/etc/systemd/system/hestia-iptables.service <<'EOF'
[Unit]
Description=Loading Hestia firewall rules
DefaultDependencies=no
Wants=network-pre.target local-fs.target
Before=network-pre.target
After=local-fs.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/sbin/iptables-restore --wait=10 /etc/iptables.rules

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload && systemctl -q enable hestia-iptables
  else
    # restorecon is called by "service iptables save" (policycoreutils is
    # in every real install, not in the container images).
    if ! dnf install -y -q iptables-services policycoreutils >/tmp/boot-pkg.log 2>&1; then
      R_BOOT=skip:no-iptables-services; tail -5 /tmp/boot-pkg.log; exit 0
    fi
    systemctl -q enable iptables ip6tables
  fi

  if ! INFRAFENCE_SERVER_URL=http://127.0.0.1:8080 RELEASE_BASE=http://127.0.0.1:8080/releases \
     INFRAFENCE_AGENT_NAME=distro-boot bash /distro/install.sh --token distro-test >/tmp/boot-install.log 2>&1; then
    bf install; tail -20 /tmp/boot-install.log; exit 1
  fi
  [ "$(systemctl is-enabled infrafence-ipsets.service 2>&1)" = enabled ] || bf unit-enabled "$(systemctl is-enabled infrafence-ipsets.service 2>&1)"
  for _ in $(seq 1 30); do
    has "$(iptables -S INFRAFENCE 2>/dev/null)" '--match-set infrafence-bans' && break
    sleep 1
  done
  has "$(iptables -S INFRAFENCE 2>/dev/null)" '--match-set infrafence-' || { bf agent-chain; journalctl -u infrafence-agent --no-pager -n 20; }
  # The administrator's choice is kept: disabled, or removed and masked,
  # the unit stays so across agent restarts; "boot-sets --install" puts it
  # back. Then the update path: a server set up before the unit existed
  # (no unit, no marker) gets it when the agent starts.
  U=/etc/systemd/system/infrafence-ipsets.service
  agent_log() { # PATTERN: the agent logged it within 30 s
    local _
    for _ in $(seq 1 30); do
      has "$(journalctl -u infrafence-agent --no-pager -o cat 2>/dev/null)" "$1" && return 0
      sleep 1
    done
    return 1
  }
  # (installed by install.sh: marker written)
  systemctl disable -q infrafence-ipsets.service
  systemctl restart infrafence-agent
  agent_log "disabled by the administrator" && [ "$(systemctl is-enabled infrafence-ipsets.service 2>&1)" = disabled ] \
    || bf admin-disabled "$(systemctl is-enabled infrafence-ipsets.service 2>&1)"
  rm -f $U && systemctl mask -q infrafence-ipsets.service
  systemctl restart infrafence-agent
  agent_log "is a symlink (masked?)" && [ "$(readlink $U)" = /dev/null ] || bf admin-masked "$(ls -l $U 2>&1)"
  systemctl unmask -q infrafence-ipsets.service
  /usr/local/bin/infrafence-agent boot-sets --install | sed 's/^/[boot] /'
  [ "$(systemctl is-enabled infrafence-ipsets.service 2>&1)" = enabled ] || bf explicit-install
  # Last, so the reboot below runs the unit the agent itself installed.
  systemctl disable -q infrafence-ipsets.service; rm -f $U /var/lib/infrafence/boot-sets-installed; systemctl daemon-reload
  systemctl restart infrafence-agent
  agent_log "installed $U" && [ "$(systemctl is-enabled infrafence-ipsets.service 2>&1)" = enabled ] \
    || bf update-path "$(systemctl is-enabled infrafence-ipsets.service 2>&1)"
  for _ in $(seq 1 30); do
    has "$(iptables -S INFRAFENCE 2>/dev/null)" '--match-set infrafence-bans' && break
    sleep 1
  done

  # The customer's own rules.
  eval "iptables -A INPUT $V4RULE" || bf customer-rule
  # IPv6 where ip6tables works in this container (not on Ubuntu 20.04's
  # legacy backend in CI: inside.sh reports ipv6=skip there too).
  if ip6tables -S INPUT >/dev/null 2>&1; then
    eval "ip6tables -A INPUT $V6RULE" && touch /root/boot-v6 || bf customer-rule6
  else
    echo "[boot] ip6tables not usable here: IPv6 customer rule skipped"
  fi

  save_now
  for f in $(saved_files); do
    grep -q -- '--match-set infrafence-' "$f" || bf "saved-without-sets:$f"
    # As at boot: no sets yet. The whole file is refused...
    if restores_without_sets "$f"; then
      bf "restored-without-sets:$f"
    elif ! grep -q "Set infrafence-.* doesn't exist" /tmp/boot-restore.log; then
      bf "refused-for-another-reason:$f" "$(head -2 /tmp/boot-restore.log)"
    else
      echo "[boot] $f without the agent's sets: $(head -1 /tmp/boot-restore.log)"
    fi
    # ...and loads once boot-sets has run.
    ip netns add bootns
    ip netns exec bootns /usr/local/bin/infrafence-agent boot-sets | sed 's/^/[boot-sets] /'
    ip netns exec bootns iptables-restore <"$f" >/tmp/boot-restore.log 2>&1 || bf "boot-sets-restore:$f" "$(head -2 /tmp/boot-restore.log)"
    has "$(ip netns exec bootns iptables -S INPUT)" customer-rule || bf "boot-sets-customer-rule:$f"
    ip netns del bootns
  done
  [ -z "$fails" ] && R_BOOT=ok
  exit 0
fi

if [ "$phase" = check ]; then
  unit_ok() { [ "$(systemctl show -p Result --value "$1")$(systemctl show -p ExecMainStatus --value "$1")" = success0 ]; }
  unit_ok infrafence-ipsets.service && systemctl is-active -q infrafence-ipsets.service \
    || { bf ipsets-unit; systemctl status infrafence-ipsets --no-pager | tail -5; }
  journalctl -b -u infrafence-ipsets --no-pager -o cat | grep -v '^$' | sed 's/^/[boot] infrafence-ipsets: /'
  if command -v netfilter-persistent >/dev/null; then
    # netfilter-persistent reports success even when a file failed to load.
    journalctl -b -u netfilter-persistent --no-pager -o cat | grep -E "NOT loaded|doesn't exist" && bf netfilter-persistent
    unit_ok hestia-iptables.service || { bf hestia-iptables; journalctl -b -u hestia-iptables --no-pager -n 5; }
  else
    for u in iptables ip6tables; do
      systemctl is-active -q $u || { bf "$u.service"; journalctl -b -u $u --no-pager -n 5; }
    done
  fi
  # Every restore service on the host is ordered after it (not only by
  # luck). (On Debian iptables.service and ip6tables.service are aliases
  # of netfilter-persistent.service.)
  for u in netfilter-persistent.service iptables.service ip6tables.service hestia-iptables.service; do
    [ "$(systemctl show -p LoadState --value $u)" = loaded ] || continue
    has "$(systemctl show -p After --value $u)" infrafence-ipsets.service || bf "order:$u"
  done
  has "$(iptables -S INPUT)" customer-rule || bf customer-rule-after-boot
  if [ -e /root/boot-v6 ]; then
    has "$(ip6tables -S INPUT)" customer-rule || bf customer-rule6-after-boot
  fi
  iptables -S INFRAFENCE >/dev/null 2>&1 || bf agent-chain-after-boot

  # Uninstall: the unit goes, and each saved file that still holds the
  # agent's chains is named with the command that saves it again.
  mockapi
  bash /distro/install.sh --uninstall >/tmp/boot-uninstall.log 2>&1
  for f in $(saved_files); do
    grep -q "WARNING: the saved ruleset $f still contains InfraFence's chains" /tmp/boot-uninstall.log \
      || { bf "uninstall-warning:$f"; tail -20 /tmp/boot-uninstall.log; }
  done
  [ -e /etc/systemd/system/infrafence-ipsets.service ] && bf unit-left
  has "$(systemctl list-unit-files 2>/dev/null)" infrafence && bf units-left
  has "$(ipset list -n 2>/dev/null)" infrafence && bf sets-left
  save_now
  for f in $(saved_files); do
    grep -q INFRAFENCE "$f" && bf "resaved-still-has-agent:$f"
    grep -q customer-rule "$f" || bf "resaved-lost-customer-rule:$f"
    restores_without_sets "$f" || bf "resaved-restore:$f" "$(head -2 /tmp/boot-restore.log)"
  done
  [ -z "$fails" ] && R_BOOT=ok
  exit 0
fi

echo "usage: boot.sh save|check"
exit 1
