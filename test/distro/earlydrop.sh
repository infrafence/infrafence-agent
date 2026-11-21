# Sourced by inside.sh once 203.0.113.2 (namespace "cl") is banned: the
# raw-table early drop (internal/firewall/raw.go) and Imunify360's rule
# recreation (cmd/infrafence-agent/fwguard.go). The ban is in
# INFRAFENCE-RAW. An Imunify360-like chain that ACCEPTs SSH is put first in
# INPUT three times, as Imunify360 does every minute: the banned client
# still gets nothing (the raw table drops it first), the guard moves the
# INFRAFENCE jump back, logs the first restore as expected and not the
# others, and reports no warning or conflict. Learning (monitor mode)
# removes the raw chain, protection brings it back. Sets R_RAW; appends to
# EXTRA_RESULT and sets EXTRA_FAIL=1 on a failure.
R_RAW=fail
RAW_API=http://127.0.0.1:8080
raw_fail=""
rf() { raw_fail="$raw_fail $1"; log "earlydrop: $1${2:+: $2}"; }
raw_has() {
  local hook chain
  hook=$(iptables -t raw -S PREROUTING 2>/dev/null)
  chain=$(iptables -t raw -S INFRAFENCE-RAW 2>/dev/null)
  grep -q -- '-j INFRAFENCE-RAW' <<<"$hook" && grep -q -- '--match-set infrafence-bans src -j DROP' <<<"$chain"
}
raw_none() { ! grep -qi infrafence <<<"$(iptables -t raw -S 2>/dev/null)"; }
raw_drops() { iptables -t raw -L INFRAFENCE-RAW -v -n -x 2>/dev/null | awk '/DROP/ {print $1; exit}'; }
ours_first() { iptables -S INPUT | grep -- ' -j ' | head -1 | grep -q -- '-j INFRAFENCE$'; }
sev_count() { grep -o "\"type\":\"$1\",\"severity\":\"$2\"" <<<"$(curl -s "$RAW_API/state")" | wc -l; }
# raw_sync MONITOR: the dashboard's monitor_mode, and the ban as a
# dashboard ban (a local one is let go 10 minutes after it is reported).
raw_sync() {
  curl -s -X POST "$RAW_API/set-sync" -d "{\"config\":{\"bf_threshold\":5,\"bf_window\":60,\"monitor_mode\":$1},\"bans\":[{\"id\":41,\"ip_address\":\"203.0.113.2\",\"expires_at\":null}]}" >/dev/null
}

if ! command -v ipset >/dev/null || ! ipset list -n 2>/dev/null | grep -q '^infrafence-bans$'; then
  R_RAW=skip
  log "earlydrop: no ipset, skipped (bans are rules in the filter chain only)"
else
  raw_sync false
  for _ in $(seq 1 30); do raw_has && break; sleep 1; done
  raw_has || rf present "$(iptables -t raw -S 2>&1 | head -5 | tr '\n' ' ')"

  # ── Imunify360, as preflight sees it, recreating its rules ──
  mkdir -p /etc/sysconfig/imunify360
  iptables -N INPUT_imunify360 2>/dev/null
  iptables -F INPUT_imunify360 && iptables -A INPUT_imunify360 -p tcp --dport 22 -j ACCEPT
  iptables -N OUTPUT_imunify360 2>/dev/null
  imunify_recreate() {
    while iptables -D INPUT -j INPUT_imunify360 2>/dev/null; do :; done
    while iptables -D OUTPUT -j OUTPUT_imunify360 2>/dev/null; do :; done
    iptables -I INPUT 1 -j INPUT_imunify360
    iptables -I OUTPUT 1 -j OUTPUT_imunify360
  }
  since=$(date '+%Y-%m-%d %H:%M:%S')
  warn0=$(sev_count firewall_rules_restored warning)
  conf0=$(sev_count firewall_conflict warning)
  info0=$(sev_count firewall_rules_restored info)
  drops0=$(raw_drops)
  for round in 1 2 3; do
    imunify_recreate
    # The ACCEPT is first now: the raw table holds the ban.
    if ! ours_first; then
      windows=$((${windows:-0} + 1))
      ip netns exec cl timeout 3 bash -c '</dev/tcp/203.0.113.1/22' 2>/dev/null && rf "window_$round" "the banned client reached sshd"
    fi
    for _ in $(seq 1 30); do ours_first && break; sleep 1; done
    ours_first || rf "restore_$round" "$(iptables -S INPUT | head -3 | tr '\n' ' ')"
    sleep 35 # more than 30 s apart: not back-to-back
  done
  [ "${windows:-0}" -gt 0 ] || rf window "the guard was always faster than the check"
  drops1=$(raw_drops)
  [ "${drops1:-0}" -gt "${drops0:-0}" ] || rf counter "raw DROP packets $drops0 -> $drops1"
  jl=$(journalctl -u infrafence-agent --no-pager --since "$since" 2>/dev/null)
  [ "$(grep -c 'after Imunify360 recreated its rules (expected' <<<"$jl")" = 1 ] || rf first "$(grep 'guard' <<<"$jl" | tail -4)"
  [ "$(grep -c 'guard: restored' <<<"$jl")" = 1 ] || rf quiet "$(grep 'guard: restored' <<<"$jl" | tail -4)"
  grep -q 'bans hold meanwhile in the raw table' <<<"$jl" || rf held "$(grep 'guard' <<<"$jl" | head -2)"
  [ "$(sev_count firewall_rules_restored warning)" = "$warn0" ] || rf warning "a warning event for an expected rebuild"
  [ "$(sev_count firewall_conflict warning)" = "$conf0" ] || rf conflict "firewall_conflict for an expected rebuild"
  [ "$(sev_count firewall_rules_restored info)" -gt "$info0" ] || rf info "no info event for the first expected restore"
  while iptables -D INPUT -j INPUT_imunify360 2>/dev/null; do :; done
  while iptables -D OUTPUT -j OUTPUT_imunify360 2>/dev/null; do :; done
  iptables -F INPUT_imunify360; iptables -X INPUT_imunify360; iptables -X OUTPUT_imunify360
  rm -rf /etc/sysconfig/imunify360

  # ── Learning adds nothing in the raw table; protection puts it back ──
  raw_sync true
  for _ in $(seq 1 150); do raw_none && break; sleep 1; done
  raw_none || rf learning "$(iptables -t raw -S | grep -i infrafence | head -3 | tr '\n' ' ')"
  raw_sync false
  for _ in $(seq 1 150); do raw_has && break; sleep 1; done
  raw_has || rf protect "raw chain not back after Learning"
  ip netns exec cl timeout 3 bash -c '</dev/tcp/203.0.113.1/22' 2>/dev/null && rf banned_after "the banned client reached sshd"
  curl -s -X POST "$RAW_API/set-sync" -d '{"bans": null}' >/dev/null
  [ -z "$raw_fail" ] && R_RAW=ok
fi
EXTRA_RESULT="${EXTRA_RESULT:-} earlydrop=${R_RAW}${raw_fail:+ earlydrop_fail=$(echo $raw_fail | tr ' ' ',')}"
[ "$R_RAW" = fail ] && EXTRA_FAIL=1
