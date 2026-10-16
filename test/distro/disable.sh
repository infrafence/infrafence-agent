# Sourced by inside.sh after offline.sh: the dashboard refuses the agent
# long enough (INFRAFENCE_TEST_REFUSAL_LIMIT=90s instead of 24 hours, honoured
# by test builds only) and the agent switches its protection off: none of
# InfraFence's chains, jumps or ipsets left, another tool's chain, jump and
# set untouched, SSH reachable (also from the address banned earlier), the
# login notice in /etc/motd.d (where the distro uses it), panel status says
# "disabled". Then the dashboard accepts the agent again: protection back,
# notice gone. Sets R_OFF, R_OTHERS, R_SSHOFF, R_MOTD, R_BACK; appends to
# EXTRA_RESULT and sets EXTRA_FAIL=1 on a failure.
R_OFF=fail R_OTHERS=fail R_SSHOFF=fail R_MOTD=fail R_BACK=fail
API=http://127.0.0.1:8080
DROPIN=/etc/systemd/system/infrafence-agent.service.d/test-refusal.conf
MOTD=/etc/motd.d/infrafence

ours_left() {
  { iptables -S 2>/dev/null; ip6tables -S 2>/dev/null; } | grep -q INFRAFENCE && return 0
  ipset list -n 2>/dev/null | grep -q '^infrafence-' && return 0
  return 1
}
others_intact() {
  iptables -S OTHERTOOL 2>/dev/null | grep -q -- '-s 192.0.2.99/32 -j DROP' &&
    iptables -S INPUT | grep -q -- '-j OTHERTOOL' &&
    { ! command -v ipset >/dev/null || ipset list -n 2>/dev/null | grep -qx othertool; }
}
motd_used() { [ -d /etc/motd.d ] || grep -rqs pam_motd /etc/pam.d; }

# ── another tool's rules: a chain, its jump at the end of INPUT, a set ──
iptables -N OTHERTOOL 2>/dev/null
iptables -A OTHERTOOL -s 192.0.2.99 -j DROP
iptables -A INPUT -j OTHERTOOL
command -v ipset >/dev/null && ipset create othertool hash:ip -exist && ipset add othertool 192.0.2.98 -exist
had_motd_dir=no; [ -d /etc/motd.d ] && had_motd_dir=yes
motd_used && expect_motd=yes || expect_motd=no

# ── refused for longer than the (test) limit ──
mkdir -p "$(dirname $DROPIN)"
printf '[Service]\nEnvironment=INFRAFENCE_TEST_REFUSAL_LIMIT=90s\n' >$DROPIN
systemctl daemon-reload
curl -s "$API/deny?mode=suspended" >/dev/null
systemctl restart infrafence-agent
t0=$(date +%s)
for _ in $(seq 1 300); do ours_left || break; sleep 1; done
log "switched off after $(( $(date +%s) - t0 ))s: $(ours_left && echo no || echo yes)"
if ! ours_left; then R_OFF=ok; else
  { iptables -S; ipset list -n; } 2>/dev/null | grep -i infrafence | head -5
  journalctl -u infrafence-agent --no-pager | grep -iE 'protection|refus' | tail -8
fi
others_intact && R_OTHERS=ok || { log "another tool's rules changed"; iptables -S | grep -i other; }
# SSH from the host and from the address banned at the start of the test.
if timeout 3 bash -c '</dev/tcp/127.0.0.1/22' 2>/dev/null && ip netns exec cl timeout 3 bash -c '</dev/tcp/203.0.113.1/22' 2>/dev/null; then
  R_SSHOFF=ok
else
  log "SSH not reachable after the switch-off"
fi
journalctl -u infrafence-agent --no-pager | grep -q 'SSH still answers' || { log "no SSH check logged"; R_SSHOFF=fail; }
if [ $expect_motd = yes ]; then
  grep -q 'https://infrafence.com/billing' $MOTD 2>/dev/null && R_MOTD=ok || log "no login notice in $MOTD"
else
  [ ! -e $MOTD ] && R_MOTD=ok || log "notice written on a host without motd.d"
fi
journalctl -u infrafence-agent --no-pager | grep -q 'WARNING: InfraFence no longer protects this server' || { log "notice not logged"; R_MOTD=fail; }
st=$(/usr/local/bin/infrafence-agent panel status --json 2>/dev/null)
grep -q '"protection":"disabled"' <<<"$st" && grep -q '"disabled_at":"20' <<<"$st" || { log "panel status: $st"; R_OFF=fail; }

# ── accepted again (a restart skips the 30-minute idle wait) ──
curl -s "$API/deny?mode=off" >/dev/null
systemctl restart infrafence-agent
for _ in $(seq 1 60); do
  iptables -S INPUT 2>/dev/null | grep -q -- '-j INFRAFENCE' && [ ! -e $MOTD ] && break
  sleep 1
done
if iptables -S INFRAFENCE >/dev/null 2>&1 && iptables -S INPUT | grep -q -- '-j INFRAFENCE' && [ ! -e $MOTD ] && others_intact; then
  R_BACK=ok
  [ $had_motd_dir = no ] && [ -d /etc/motd.d ] && { log "/etc/motd.d created by the agent left behind"; R_BACK=fail; }
else
  log "after acceptance: chain=$(iptables -S INFRAFENCE >/dev/null 2>&1 && echo yes) motd=$( [ -e $MOTD ] && echo left)"
  journalctl -u infrafence-agent --no-pager | grep -iE 'protection' | tail -5
fi
journalctl -u infrafence-agent --no-pager | grep -q 'protection is back on' || { log "no 'back on' log"; R_BACK=fail; }

# ── back to the plain state ──
rm -f $DROPIN && systemctl daemon-reload && systemctl restart infrafence-agent
iptables -D INPUT -j OTHERTOOL 2>/dev/null; iptables -F OTHERTOOL 2>/dev/null; iptables -X OTHERTOOL 2>/dev/null
command -v ipset >/dev/null && ipset destroy othertool 2>/dev/null
EXTRA_RESULT="${EXTRA_RESULT:-} off=${R_OFF} others=${R_OTHERS} ssh_off=${R_SSHOFF} motd=${R_MOTD} back=${R_BACK}"
[ "$R_OFF$R_OTHERS$R_SSHOFF$R_MOTD$R_BACK" = okokokokok ] || EXTRA_FAIL=1
