#!/bin/sh
# pf integration test of the appliance agent on plain FreeBSD (CI: a
# disposable vmactions/freebsd-vm VM; never run it on a real firewall: it
# loads its own pf ruleset).
#
# The ruleset declares the three tables as OPNsense does for the plugin's
# External aliases and blocks from them; everything else passes. The test
# registers the agent against the mock dashboard and checks: dashboard bans
# reach the table, a ruleset reload keeps it, an empty table ("reboot") is
# refilled from the agent's state, a brute force in the auth log is banned,
# Learning empties the tables, a ruleset without the tables makes the agent
# detect-only, and "appliance flush" empties them.
#
#   AGENT_BIN=./infrafence-agent MOCKAPI=./mockapi sh test/opnsense/pf-freebsd.sh
# Needs curl (pkg install curl).
set -eu
: "${AGENT_BIN:?}" "${MOCKAPI:?}"
[ "$(uname -s)" = FreeBSD ] || { echo "FreeBSD only" >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }
# It replaces the pf ruleset and wipes the agent's state: only in a
# disposable VM, which says so with PF_TEST_FORCE=1.
if [ -z "${PF_TEST_FORCE:-}" ]; then
	echo "refusing: this test replaces the pf ruleset (PF_TEST_FORCE=1 in a disposable VM only)" >&2
	exit 2
fi
# A clean agent state: bans from an earlier run would not be reported again.
rm -rf /var/db/infrafence /var/run/infrafence /usr/local/etc/infrafence
API=http://127.0.0.1:18080
W=$(mktemp -d -t ifpf)
pass=0 fail=0
ok() { pass=$((pass + 1)); echo "PASS: $*"; }
ko() { fail=$((fail + 1)); echo "FAIL: $*"; }
until_ok() { # until_ok "description" SECONDS command...
	d=$1 t=$2; shift 2
	i=0
	while [ $i -lt "$t" ]; do
		if "$@" > /dev/null 2>&1; then ok "$d"; return 0; fi
		sleep 2; i=$((i + 2))
	done
	ko "$d (not within ${t}s)"
	return 0
}
in_table() { pfctl -t "$1" -T show 2>/dev/null | grep -qx "   $2"; }
not_in_table() { ! in_table "$@"; }
only_negations() { ! pfctl -t infrafence_bans -T show | grep -v '!' | grep -q .; }
post() { curl -fsS -X POST --data-binary "$2" "$API$1" > /dev/null; } # curl: pkg install curl
state() { fetch -q -o - "$API/state"; }
hup() { kill -HUP "$(cat /var/run/infrafence/agent.pid)"; }

cleanup() {
	[ -f /var/run/infrafence/agent.pid ] && kill "$(cat /var/run/infrafence/agent.pid)" 2>/dev/null || true
	[ -n "${API_PID:-}" ] && kill "$API_PID" 2>/dev/null || true
	pfctl -d > /dev/null 2>&1 || true
}
trap cleanup EXIT

kldload -n pf
cat > "$W/pf.conf" <<'EOF'
table <infrafence_bans> persist
table <infrafence_threat> persist
table <infrafence_geo> persist
pass all
block in quick from <infrafence_bans>
block in quick from <infrafence_threat>
block in quick from <infrafence_geo>
EOF
printf 'pass all\n' > "$W/pf-without-tables.conf"
pfctl -e > /dev/null 2>&1 || true
pfctl -f "$W/pf.conf"

"$MOCKAPI" -addr 127.0.0.1:18080 -binary "$AGENT_BIN" -geoip /nonexistent > "$W/mockapi.log" 2>&1 &
API_PID=$!
sleep 1

install -m 0755 "$AGENT_BIN" /usr/local/sbin/infrafence-agent
export INFRAFENCE_CONFIG=/usr/local/etc/infrafence/config.json
echo "ci-install-token-0123456789" | infrafence-agent register --token-stdin --mode protect "$API" ci-freebsd
if [ "$(stat -f %Lp $INFRAFENCE_CONFIG)" = 600 ]; then ok "config is 0600"; else ko "config mode"; fi
if pgrep -f ci-install-token > /dev/null; then ko "token visible in ps"; else ok "token not in the process list"; fi
mkdir -p /var/log/audit
: > /var/log/audit/latest.log
daemon -o "$W/agent.log" /usr/local/sbin/infrafence-agent start
until_ok "agent running" 30 test -s /var/run/infrafence/agent.pid
until_ok "heartbeat with kind opnsense" 90 sh -c "fetch -q -o - $API/state | grep -q '\"kind\":\"opnsense\"'"

post /set-sync '{"bans":[{"id":1,"ip_address":"80.94.95.1","expires_at":null},{"id":2,"ip_address":"10.1.2.3","expires_at":null}],"whitelists":[{"id":1,"ip_address":"37.19.221.10"}]}'
hup
until_ok "dashboard ban in the table" 60 in_table infrafence_bans 80.94.95.1
if not_in_table infrafence_bans 10.1.2.3; then ok "private address never banned"; else ko "private address banned"; fi
if pfctl -t infrafence_bans -T show | grep -q '!37.19.221.10'; then ok "allow list negated"; else ko "allow list"; fi

pfctl -f "$W/pf.conf"
if in_table infrafence_bans 80.94.95.1; then ok "ruleset reload keeps the table"; else ko "ruleset reload emptied the table"; fi

for t in infrafence_bans infrafence_threat infrafence_geo; do pfctl -t $t -T flush > /dev/null 2>&1; done
until_ok "emptied table refilled by the guard (reboot case)" 90 in_table infrafence_bans 80.94.95.1

for i in 1 2 3 4 5 6; do
	echo "<38>1 $(date -u +%Y-%m-%dT%H:%M:%SZ) ci sshd 4242 - [meta sequenceId=\"$i\"] Failed password for root from 45.155.205.233 port 5$i ssh2" >> /var/log/audit/latest.log
done
until_ok "brute force from the auth log banned" 60 in_table infrafence_bans 45.155.205.233
until_ok "ban reported to the dashboard" 30 sh -c "fetch -q -o - $API/state | grep -q 45.155.205.233"

post /set-sync '{"config":{"bf_threshold":5,"bf_window":60,"monitor_mode":true}}'
hup
until_ok "Learning: no blocking entry" 60 only_negations
post /set-sync '{"config":{"bf_threshold":5,"bf_window":60,"monitor_mode":false}}'
hup
until_ok "Full protection: bans back" 60 in_table infrafence_bans 80.94.95.1

pfctl -f "$W/pf-without-tables.conf"
until_ok "detect-only without the tables" 90 sh -c "infrafence-agent appliance status | grep -q '\"protection\": \"detect_only\"'"
if pfctl -vsT | grep infrafence | grep -q '^....r'; then ko "a rule still references the tables"; else ok "tables left unreferenced (agent wrote no rule)"; fi
pfctl -f "$W/pf.conf"
until_ok "protection back once the tables are" 90 sh -c "infrafence-agent appliance status | grep -q '\"protection\": \"active\"' && pfctl -t infrafence_bans -T show | grep -qx '   80.94.95.1'"

rss=$(ps -o rss= -p "$(cat /var/run/infrafence/agent.pid)" | tr -d ' ')
echo "agent RSS ${rss} KiB"
if [ "$rss" -lt 61440 ]; then ok "RSS under 60 MB"; else ko "RSS ${rss} KiB"; fi

kill "$(cat /var/run/infrafence/agent.pid)"
sleep 2
infrafence-agent appliance flush
n=0
for t in infrafence_bans infrafence_threat infrafence_geo; do n=$((n + $(pfctl -t $t -T show | wc -l))); done
if [ "$n" -eq 0 ]; then ok "flush empties the tables"; else ko "flush left $n entries"; fi

echo "--- agent log (tail)"
tail -n 40 "$W/agent.log" || true
echo "result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
