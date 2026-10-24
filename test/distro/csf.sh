# Sourced by inside.sh before the uninstall: CSF (ConfigServer Security &
# Firewall) on the same host. ConfigServer's own download closed in August
# 2025; CSF is installed from the maintained GPLv3 fork
# github.com/Aetherinox/csf-firewall, a pinned release checked by SHA-256.
# CSF runs with TESTING off, AUTO_UPDATES off, SSH in TCP_IN and lfd
# stopped (it would block the test's clients on its own). The dashboard
# bans 198.18.0.2 (namespace c5); 198.18.1.2 (namespace c6) is a client
# that is never banned. Then, twice (LF_IPSET 0, the default, and 1, where
# "csf -r" also destroys every ipset on the host): "csf -r" flushes the
# firewall, and the agent must bring back its chains, jumps and sets and
# the ban within RESTORE_MAX seconds (the guard looks for its INPUT jump
# every 5 s), while SSH answers the client throughout and CSF's own rules
# stay exactly as CSF wrote them. "panel coexistence" must report CSF with mode
# coexist. OpenSSH 9.8+ (Fedora 41/42, Debian 13) refuses a source after
# repeated connections that never authenticate (PerSourcePenalties): the
# client's banner probes are exactly that, so the client is exempted for
# the test, and the exemption removed afterwards. CSF's installer switches
# iptables to iptables-nft when it is installed ("update-alternatives
# --set" in its os.pl); the switch is logged. Sets R_CSF (ok|fail|skip: CSF
# cannot be installed or started in this image, with the reason); appends
# to EXTRA_RESULT and sets EXTRA_FAIL=1 on a failure.
R_CSF=fail
API=http://127.0.0.1:8080
AGENT=/usr/local/bin/infrafence-agent
CSF_VERSION=15.10
CSF_URL=https://github.com/Aetherinox/csf-firewall/releases/download/$CSF_VERSION/csf-firewall-v$CSF_VERSION.tgz
CSF_SHA256=788317da71d31a338da4cff3bdae9471137efc3978436692fe9d005eb70f54b3
BAN=198.18.0.2 CLIENT=198.18.1.2
RESTORE_MAX=15
csf_fail="" csf_skip="" csf_times=""
cf() { csf_fail="$csf_fail $1"; log "csf: $1${2:+: $2}"; }

ip netns add c5
ip link add veth6 type veth peer name veth7
ip link set veth7 netns c5
ip addr add 198.18.0.1/24 dev veth6 && ip link set veth6 up
ip netns exec c5 ip addr add $BAN/24 dev veth7
ip netns exec c5 ip link set veth7 up
ip netns add c6
ip link add veth8 type veth peer name veth9
ip link set veth9 netns c6
ip addr add 198.18.1.1/24 dev veth8 && ip link set veth8 up
ip netns exec c6 ip addr add $CLIENT/24 dev veth9
ip netns exec c6 ip link set veth9 up

# ssh_answers NS HOST [TIMEOUT]: sshd's banner arrives (not a dropped connection).
# (Output captured first: with pipefail a timeout would fail the pipe.)
ssh_answers() {
  local out
  out=$(ip netns exec "$1" timeout "${3:-2}" bash -c "exec 3<>/dev/tcp/$2/22 && head -c 4 <&3" 2>/dev/null || true)
  [ "$out" = SSH- ]
}
# ssh_ok NS HOST: sshd answers within three tries (one slow answer on a busy
# container is not a block; a block fails every try).
ssh_ok() {
  local i
  for i in 1 2 3; do ssh_answers "$1" "$2" 3 && return 0; log "csf: $1 got no sshd banner (try $i)"; done
  return 1
}
banned_here() {
  if ipset list -n 2>/dev/null | grep -qx infrafence-bans; then ipset list infrafence-bans 2>/dev/null | grep -qx "$1"
  else iptables -S INFRAFENCE 2>/dev/null | grep -q -- "-s $1/32 -j DROP"; fi
}
# ours_back: the agent's chains, the INPUT and OUTPUT jumps, its ban set
# (when it uses ipset) with the ban in it, and the ban enforced.
ours_back() {
  local c
  for c in INFRAFENCE INFRAFENCE-RULES INFRAFENCE-PORTS INFRAFENCE-EGRESS; do
    iptables -S "$c" >/dev/null 2>&1 || return 1
  done
  iptables -S INPUT 2>/dev/null | grep -q -- '-j INFRAFENCE$' || return 1
  iptables -S INPUT 2>/dev/null | grep -q -- '-j INFRAFENCE-RULES$' || return 1
  iptables -S OUTPUT 2>/dev/null | grep -q -- '-j INFRAFENCE-EGRESS$' || return 1
  banned_here $BAN
}
# csf_rules: everything in the firewall that is not the agent's, without
# counters: CSF's chains, rules and ipsets.
csf_rules() {
  iptables-save -t filter 2>/dev/null | grep -v '^#' | grep -vi infrafence | sed 's/ \[[0-9]*:[0-9]*\]$//'
  ipset save 2>/dev/null | grep -v infrafence | sort
}
csf_set() { sed -i "s/^$1 = \".*\"/$1 = \"$2\"/" /etc/csf/csf.conf; }

# sshd's per-source penalties would refuse the client's probes on their own.
SSHD_EXEMPT=/etc/ssh/sshd_config.d/00-infrafence-csf-test.conf
reload_sshd() { systemctl reload sshd >/dev/null 2>&1 || systemctl reload ssh >/dev/null 2>&1 || true; }
if [ -d /etc/ssh/sshd_config.d ] && sshd -T -o "PerSourcePenaltyExemptList=$CLIENT" >/dev/null 2>&1; then
  echo "PerSourcePenaltyExemptList $CLIENT" >"$SSHD_EXEMPT"
  reload_sshd
  log "csf: sshd per-source penalties: $CLIENT exempted for the test"
fi
backend() { iptables -V 2>/dev/null | grep -o '(.*)' || echo none; }
backend_before=$(backend)

# ── install CSF ──
if [ -z "$csf_skip" ]; then
  # (Three tries: a mirror that drops a connection is not the image's fault.)
  csf_skip=deps
  for _ in 1 2 3; do
    if command -v apt-get >/dev/null; then
      apt-get update -qq >/tmp/csf-deps.log 2>&1
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
        perl libwww-perl liblwp-protocol-https-perl iptables ipset tar >>/tmp/csf-deps.log 2>&1 && { csf_skip=""; break; }
    else
      dnf install -y -q perl perl-libwww-perl perl-LWP-Protocol-https iptables-nft ipset tar >/tmp/csf-deps.log 2>&1 && { csf_skip=""; break; }
    fi
    sleep 10
  done
  [ "$csf_skip" = deps ] && tail -5 /tmp/csf-deps.log
fi
if [ -z "$csf_skip" ]; then
  rm -rf /tmp/csf-src && mkdir -p /tmp/csf-src
  # csf edits /etc/crontab (TESTING) and fails without one; minimal images have none.
  [ -e /etc/crontab ] || touch /etc/crontab
  if ! curl -fsSL -m 120 --retry 3 --retry-all-errors --retry-delay 5 -o /tmp/csf-src/csf.tgz "$CSF_URL"; then
    csf_skip=download
  elif ! echo "$CSF_SHA256  /tmp/csf-src/csf.tgz" | sha256sum -c --quiet; then
    cf checksum "$(sha256sum /tmp/csf-src/csf.tgz)"; csf_skip=bad-checksum
  elif ! tar -xzf /tmp/csf-src/csf.tgz -C /tmp/csf-src || ! (cd /tmp/csf-src/csf && sh install.sh) >/tmp/csf-install.log 2>&1 ||
       [ ! -x /usr/sbin/csf ]; then
    csf_skip=installer; tail -10 /tmp/csf-install.log
  fi
  [ "$(backend)" = "$backend_before" ] || log "csf: CSF's install switched iptables from $backend_before to $(backend)"
fi
if [ -z "$csf_skip" ]; then
  csf_set TESTING 0
  csf_set AUTO_UPDATES 0
  csf_set LF_IPSET 0
  csf_set RESTRICT_SYSLOG 3
  grep -q '^TCP_IN = "\(.*,\)\?22\(,.*\)\?"' /etc/csf/csf.conf || cf ssh_port "22 not in TCP_IN"
  systemctl disable --now lfd >/dev/null 2>&1
  if ! csf -r >/tmp/csf-start.log 2>&1 || ! iptables -S LOCALINPUT >/dev/null 2>&1; then
    csf_skip=start; tail -10 /tmp/csf-start.log
  fi
fi

if [ -n "$csf_fail" ]; then
  log "csf: not tested ($csf_skip)"
elif [ -n "$csf_skip" ]; then
  R_CSF=skip
  log "csf: skipped, CSF cannot be used in this image ($csf_skip)"
else
  log "csf: CSF $(cat /etc/csf/version.txt 2>/dev/null), $(iptables -V)"

  # ── the agent restores itself after CSF's first start; then the ban ──
  t0=$(date +%s)
  for _ in $(seq 1 75); do iptables -S INPUT 2>/dev/null | grep -q -- '-j INFRAFENCE$' && break; sleep 1; done
  log "csf: agent chains back $(( $(date +%s) - t0 ))s after CSF's first start"
  curl -s -X POST "$API/set-sync" -d "{\"config\": {\"bf_threshold\": 5, \"bf_window\": 60, \"monitor_mode\": false}, \"bans\": [{\"id\": 31, \"ip_address\": \"$BAN\", \"expires_at\": null}]}" >/dev/null
  for _ in $(seq 1 90); do ours_back && break; sleep 1; done
  ours_back || cf ban "$BAN not banned: $(iptables -S INPUT 2>&1 | head -5 | tr '\n' ' ')"
  ssh_answers c5 198.18.0.1 && cf ban_enforced "$BAN still reaches sshd"
  ssh_ok c6 198.18.1.1 || cf ssh "the client cannot reach sshd with CSF and the agent"

  for ipsetmode in 0 1; do
    if [ $ipsetmode = 1 ]; then
      command -v ipset >/dev/null || { log "csf: no ipset, LF_IPSET=1 pass skipped"; break; }
      csf_set LF_IPSET 1
      csf -r >/tmp/csf-start.log 2>&1 || cf "start_ipset" "$(tail -3 /tmp/csf-start.log)"
      for _ in $(seq 1 75); do ours_back && break; sleep 1; done
      ipset list -n | grep -q '^chain_' || cf csf_ipsets "CSF made no ipsets with LF_IPSET=1"
    fi

    # ── csf -r: measured from its return to everything of the agent's back ──
    csf -r >/tmp/csf-restart.log 2>&1 || cf "restart_$ipsetmode" "$(tail -3 /tmp/csf-restart.log)"
    t1=$(date +%s.%N)
    theirs=$(csf_rules)
    gone=no; ours_back || gone=yes
    back="" sshlost=0 checks=0
    while :; do
      now=$(date +%s.%N)
      if ours_back; then
        back=$(awk -v a="$t1" -v b="$now" 'BEGIN { printf "%.1f", b - a }'); break
      fi
      checks=$((checks + 1))
      ssh_ok c6 198.18.1.1 || sshlost=$((sshlost + 1))
      awk -v a="$t1" -v b="$now" 'BEGIN { exit !(b - a > 75) }' && break
      sleep 0.5
    done
    log "csf: LF_IPSET=$ipsetmode: agent's rules removed by csf -r: $gone; back after ${back:-never}s"
    if [ -n "$back" ] && awk -v b="$back" -v m=$RESTORE_MAX 'BEGIN { exit !(b > m) }'; then
      cf "slow_$ipsetmode" "back after ${back}s, more than ${RESTORE_MAX}s"
    elif [ -z "$back" ]; then
      cf "restore_$ipsetmode" "not back 75s after csf -r"
      iptables -S INPUT | head -8; journalctl -u infrafence-agent --no-pager | grep -i firewall | tail -5
    fi
    csf_times="$csf_times${csf_times:+,}${back:-never}"
    ssh_answers c5 198.18.0.1 && cf "ban_$ipsetmode" "$BAN reaches sshd after the restore"
    [ $sshlost = 0 ] || cf "ssh_$ipsetmode" "client lost sshd $sshlost of $checks times while the agent restored"
    ssh_ok c6 198.18.1.1 || cf "ssh_after_$ipsetmode" "client cannot reach sshd"
    timeout 3 bash -c '</dev/tcp/127.0.0.1/22' 2>/dev/null || cf "ssh_local_$ipsetmode"

    # ── CSF's rules: all there, and exactly as csf -r left them ──
    for c in LOCALINPUT LOCALOUTPUT DENYIN DENYOUT ALLOWIN ALLOWOUT INVALID LOGDROPIN LOGDROPOUT; do
      iptables -S "$c" >/dev/null 2>&1 || cf "chain_$ipsetmode" "CSF chain $c missing"
    done
    if [ "$theirs" != "$(csf_rules)" ]; then
      cf "untouched_$ipsetmode" "CSF's rules changed after the agent's repair"
      diff <(echo "$theirs") <(csf_rules) | head -10
    fi
  done
  curl -s "$API/state" | grep -q '"type":"firewall_rules_restored"' || cf event "no firewall_rules_restored event"

  # ── panel coexistence ──
  out=$("$AGENT" panel coexistence --json 2>/dev/null)
  grep -q '"mode":"coexist"' <<<"$out" || cf coexistence_mode "$out"
  grep -o '{[^{}]*"id":"csf"[^{}]*}' <<<"$out" | grep -q '"active":true' || cf coexistence_csf "$out"

  [ -z "$csf_fail" ] && R_CSF=ok
fi

# ── back to the plain state: CSF removed, its rules with it, ban lifted ──
curl -s -X POST "$API/set-sync" -d '{"bans": []}' >/dev/null
if [ -x /etc/csf/uninstall.sh ] || [ -f /etc/csf/uninstall.sh ]; then
  sh /etc/csf/uninstall.sh >/tmp/csf-uninstall.log 2>&1
fi
for c in INPUT OUTPUT FORWARD; do iptables -P $c ACCEPT 2>/dev/null; done
# (The agent's chains go too; its restart below puts them back.)
iptables -S 2>/dev/null | grep -q LOCALINPUT && { iptables -F; iptables -X; log "csf: rules left after its uninstall, flushed"; }
systemctl restart infrafence-agent
if [ -e "$SSHD_EXEMPT" ]; then rm -f "$SSHD_EXEMPT"; reload_sshd; fi
ip netns pids c5 2>/dev/null | xargs -r kill 2>/dev/null
ip netns pids c6 2>/dev/null | xargs -r kill 2>/dev/null
EXTRA_RESULT="${EXTRA_RESULT:-} csf=${R_CSF}${csf_skip:+ csf_skip=$csf_skip}${csf_times:+ csf_restore_s=$csf_times}"
[ "$R_CSF" = fail ] && EXTRA_FAIL=1
