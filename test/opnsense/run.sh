#!/usr/bin/env bash
# End-to-end test of the OPNsense product on a real OPNsense VM (QEMU).
#
# Boots the official nano image (amd64), builds both packages inside it
# (pkg create), publishes them in a locally signed pkg repository, installs
# os-infrafence from that repository, registers against the mock dashboard
# (test/distro/mockapi) and checks: bans from the dashboard reach the pf
# table, brute force and port scans from the OPNsense logs are detected and
# banned, Learning mode empties the tables, the tables survive a filter
# reload and a reboot, and uninstalling removes everything.
#
# Needs: Linux with qemu-system-x86_64 (KVM if /dev/kvm, else TCG: slow),
# python3, bzip2, curl. The firewall never reaches the Internet for the
# test: the mock dashboard runs on the host (10.0.2.2 from the VM).
#
#   OPN_IMG=/path/OPNsense-26.7-nano-amd64.img.bz2 \
#   AGENT_BIN=/path/infrafence-agent-freebsd-amd64 \
#   MOCKAPI=/path/mockapi-linux \
#   test/opnsense/run.sh [WORKDIR]
#
# On macOS: test/opnsense/docker-run.sh wraps this in a container.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
: "${OPN_IMG:?set OPN_IMG to the OPNsense nano image (.img or .img.bz2)}"
: "${AGENT_BIN:?set AGENT_BIN to the FreeBSD amd64 agent binary}"
: "${MOCKAPI:?set MOCKAPI to a mockapi binary for this host}"
WORK=${1:-$(mktemp -d)}
mkdir -p "$WORK/www" "$WORK/artifacts"
SOCK=$WORK/console.sock
API=http://127.0.0.1:18080
VERSION=${AGENT_VERSION:-1.0.44}
pass=0 fail=0

log() { printf '\n=== %s\n' "$*"; }
ok() { pass=$((pass + 1)); printf 'PASS: %s\n' "$*"; }
ko() { fail=$((fail + 1)); printf 'FAIL: %s\n' "$*"; }
vm() { python3 "$here/console.py" "$SOCK" run "$1" "${2:-300}"; }
check() { # check "description" command...
	local d=$1; shift
	if "$@"; then ok "$d"; else ko "$d"; fi
}
# until_vm "description" SECONDS "shell test run in the VM"
until_vm() {
	local d=$1 t=$2 c=$3 end=$((SECONDS + $2))
	while [ $SECONDS -lt $end ]; do
		if vm "$c" 60 > /dev/null 2>&1; then ok "$d"; return 0; fi
		sleep 5
	done
	ko "$d (not within ${t}s)"
	return 1
}
until_host() {
	local d=$1 t=$2 c=$3 end=$((SECONDS + $2))
	while [ $SECONDS -lt $end ]; do
		if bash -c "$c" > /dev/null 2>&1; then ok "$d"; return 0; fi
		sleep 5
	done
	ko "$d (not within ${t}s)"
	return 1
}
state() { curl -fsS "$API/state"; }
setsync() { curl -fsS -X POST -d "$1" "$API/set-sync" > /dev/null; }
hup() { vm "kill -HUP \$(cat /var/run/infrafence/agent.pid) || true" > /dev/null; }

cleanup() {
	if [ -n "${HOLD:-}" ]; then
		# Keep the VM for debugging: console.py "$SOCK" run CMD; touch release to end.
		echo "HOLD: VM kept running; touch $WORK/release to stop it"
		while [ ! -e "$WORK/release" ]; do sleep 5; done
	fi
	[ -n "${QEMU_PID:-}" ] && kill "$QEMU_PID" 2> /dev/null || true
	[ -n "${API_PID:-}" ] && kill "$API_PID" 2> /dev/null || true
	[ -n "${WWW_PID:-}" ] && kill "$WWW_PID" 2> /dev/null || true
}
trap cleanup EXIT

log "disk image"
if [ ! -f "$WORK/disk.img" ]; then
	case $OPN_IMG in
	*.bz2) bzip2 -dc "$OPN_IMG" > "$WORK/disk.img" ;;
	*) cp "$OPN_IMG" "$WORK/disk.img" ;;
	esac
fi

log "mock dashboard and file server on the host"
"$MOCKAPI" -addr 0.0.0.0:18080 -binary "$AGENT_BIN" -geoip /nonexistent > "$WORK/artifacts/mockapi.log" 2>&1 &
API_PID=$!
cp "$AGENT_BIN" "$WORK/www/infrafence-agent"
tar -C "$repo/packaging" -cf "$WORK/www/packaging.tar" opnsense
(cd "$WORK/www" && exec python3 -m http.server 18081 --bind 0.0.0.0) > "$WORK/artifacts/www.log" 2>&1 &
WWW_PID=$!
sleep 1

log "boot OPNsense"
accel=tcg
[ -w /dev/kvm ] && accel=kvm
rm -f "$SOCK"
qemu-system-x86_64 -machine q35,accel=$accel -cpu max -smp 2 -m "${OPN_MEM:-2048}" -nographic \
	-drive file="$WORK/disk.img",if=virtio,format=raw \
	-netdev user,id=lan,net=192.168.1.0/24,host=192.168.1.2,dhcpstart=192.168.1.100,hostfwd=tcp:127.0.0.1:18443-192.168.1.1:443 \
	-device virtio-net-pci,netdev=lan \
	-netdev user,id=wan \
	-device virtio-net-pci,netdev=wan \
	-serial unix:"$SOCK",server=on,wait=off -monitor none -display none \
	> "$WORK/artifacts/qemu.log" 2>&1 &
QEMU_PID=$!
for _ in $(seq 60); do [ -S "$SOCK" ] && break; sleep 1; done
start=$SECONDS
python3 "$here/console.py" "$SOCK" boot
echo "booted in $((SECONDS - start)) s ($accel)"
vm "opnsense-version; freebsd-version -k; uname -m" | tee "$WORK/artifacts/version.txt"
until_vm "WAN has an address" 180 "ifconfig vtnet1 | grep -q 'inet 10.0.2.'"
until_vm "the host is reachable" 120 "fetch -q -o /dev/null http://10.0.2.2:18081/infrafence-agent"

log "build the packages in the VM and publish a signed local repository"
vm "mkdir -p /root/if && cd /root/if && fetch -q http://10.0.2.2:18081/infrafence-agent http://10.0.2.2:18081/packaging.tar && tar -xf packaging.tar && chmod 755 infrafence-agent && ./infrafence-agent version" | tee "$WORK/artifacts/agent-version.txt"
check "packages built" vm "cd /root/if && sh opnsense/build-pkgs.sh -b ./infrafence-agent -v $VERSION -a amd64 -o /root/if/pkgs" 600
vm "ls -l /root/if/pkgs; pkg info -F /root/if/pkgs/os-infrafence-0.1.pkg | head -30; pkg info -l -F /root/if/pkgs/os-infrafence-0.1.pkg" > "$WORK/artifacts/pkg-info.txt" || true
check "signed repository built" vm "cd /root/if && openssl genrsa -out repo.key 2048 2>/dev/null && openssl rsa -in repo.key -pubout -out repo.pub 2>/dev/null && sh opnsense/make-repo.sh -k repo.key -r /root/if/repo -a amd64 pkgs/*.pkg"
vm "ls -lR /root/if/repo | head -40" > "$WORK/artifacts/repo-layout.txt" || true
vm "install -d /usr/local/etc/pkg/repos /usr/local/etc/pkg/keys && cp /root/if/repo.pub /usr/local/etc/pkg/keys/infrafence.pub && printf 'InfraFence: {\n  url: \"file:///root/if/repo/\${ABI}/latest\",\n  signature_type: \"pubkey\",\n  pubkey: \"/usr/local/etc/pkg/keys/infrafence.pub\",\n  enabled: yes\n}\n' > /usr/local/etc/pkg/repos/InfraFence.conf"
check "repository signature verifies (pkg update)" vm "pkg update -f -r InfraFence" 300

log "install os-infrafence from the repository"
check "pkg install os-infrafence" vm "pkg install -y -r InfraFence os-infrafence" 600
vm "pkg info os-infrafence infrafence-agent" > "$WORK/artifacts/pkg-installed.txt" || true
check "aliases created in config.xml" vm "grep -c '<name>infrafence_' /conf/config.xml | grep -qx 3"
check "pf tables declared after install" vm "for t in infrafence_bans infrafence_threat infrafence_geo; do pfctl -sT | grep -qx \$t || exit 1; done"
check "plugin listed by the firmware page" vm "test -f /usr/local/opnsense/version/infrafence"
check "configd knows the actions" vm "configctl infrafence status | grep -q registered"
check "menu and ACL present" vm "test -f /usr/local/opnsense/mvc/app/models/OPNsense/InfraFence/Menu/Menu.xml"

log "configure and register (the GUI controller's path: token spool file + configd)"
vm "cd /usr/local/opnsense/mvc && php -r 'require_once \"script/load_phalcon.php\"; \$m = new \\OPNsense\\InfraFence\\General(); \$m->enabled = \"1\"; \$m->server_url = \"http://10.0.2.2:18080\"; \$m->mode = \"protect\"; \$m->interfaces = \"wan\"; \$m->serializeToConfig(); \\OPNsense\\Core\\Config::getInstance()->save();'"
# The mock dashboard is plain http: allowed only with the lab flag file.
vm "install -d -m 0750 /var/db/infrafence && touch /var/db/infrafence/allow-http && umask 077 && echo 'lab-install-token-0123456789' > /var/db/infrafence/register.token"
check "register via configd" vm "configctl infrafence register | tee /dev/stderr | grep -q '\"status\":\"ok\"'" 120
check "token spool removed" vm "test ! -e /var/db/infrafence/register.token"
check "token not in config.xml" vm "! grep -q lab-install-token /conf/config.xml /conf/backup/*.xml"
check "agent config is 0600" vm "stat -f %Lp /usr/local/etc/infrafence/config.json | grep -qx 600"
vm "configctl template reload OPNsense/InfraFence; cat /etc/rc.conf.d/infrafence; configctl filter reload; configctl infrafence start" || true
until_vm "agent running" 60 "kill -0 \$(cat /var/run/infrafence/agent.pid)"
check "block rules loaded (automatic rules)" vm "grep -c 'InfraFence: block' /tmp/rules.debug | grep -qv '^0$'"
vm "grep -n 'infrafence' /tmp/rules.debug" > "$WORK/artifacts/rules-debug.txt" || true
until_host "heartbeat reaches the dashboard" 180 "curl -fsS $API/state | python3 -c 'import json,sys; s=json.load(sys.stdin); h=json.loads(json.dumps(s.get(\"last_heartbeat\") or {})); sys.exit(0 if h.get(\"kind\")==\"opnsense\" and h.get(\"appliance\",{}).get(\"protection\")==\"active\" else 1)'"
state | python3 -c 'import json,sys; s=json.load(sys.stdin); print(json.dumps(s.get("last_register"), indent=1)); print(json.dumps(s.get("last_heartbeat"), indent=1))' > "$WORK/artifacts/register-heartbeat.json" || true
check "register sent kind/mode/platform" bash -c "grep -q '\"kind\": \"opnsense\"' $WORK/artifacts/register-heartbeat.json && grep -q '\"mode\": \"protect\"' $WORK/artifacts/register-heartbeat.json"

log "dashboard bans reach the pf table"
setsync '{"bans":[{"id":1,"ip_address":"80.94.95.1","expires_at":null},{"id":2,"ip_address":"192.168.1.50","expires_at":null}],"whitelists":[{"id":1,"ip_address":"37.19.221.10"}]}'
hup
until_vm "network ban in infrafence_bans" 120 "pfctl -t infrafence_bans -T show | grep -qx '   80.94.95.1'"
check "LAN address from the dashboard never enters the table" vm "! pfctl -t infrafence_bans -T show | grep -q '^   192.168.1.50'"
check "allow-listed address negated" vm "pfctl -t infrafence_bans -T show | grep -q '!37.19.221.10'"

log "brute force from the logs (sshd and GUI via syslog-ng)"
vm "for i in 1 2 3 4 5 6; do logger -p auth.info -t sshd \"Failed password for root from 45.155.205.233 port 4242\$i ssh2\"; done"
until_vm "SSH brute force banned" 120 "pfctl -t infrafence_bans -T show | grep -qx '   45.155.205.233'"
vm "grep 45.155.205.233 /var/log/audit/latest.log | tail -2" >> "$WORK/artifacts/real-log-lines.txt" || true
vm "c=/tmp/ifcj; for i in 1 2 3 4 5 6; do rm -f \$c; p=\$(curl -sk -c \$c https://127.0.0.1/); n=\$(echo \"\$p\" | sed -n 's/.*<input type=\"hidden\" name=\"\\([^\"]*\\)\" value=\"\\([^\"]*\\)\".*/\\1/p' | head -1); v=\$(echo \"\$p\" | sed -n 's/.*<input type=\"hidden\" name=\"[^\"]*\" value=\"\\([^\"]*\\)\".*/\\1/p' | head -1); curl -sk -b \$c -c \$c --data-urlencode \"\$n=\$v\" --data-urlencode usernamefld=root --data-urlencode passwordfld=wrong-\$i --data-urlencode login=1 https://127.0.0.1/ > /dev/null; done; true" 300
vm "grep -i 'authenticat' /var/log/audit/latest.log | tail -4" >> "$WORK/artifacts/real-log-lines.txt" || true
until_host "GUI login failures reported (loopback: not banned)" 120 "curl -fsS $API/state | grep -q 'opnsense-gui'"

log "port scan from the filter log"
vm "for p in \$(seq 30000 30019); do logger -p local0.info -t filterlog \"96,,,02f4bab031b57d1e30553ce08e0ec131,vtnet1,match,block,in,4,0x0,,242,54321,0,none,6,tcp,40,193.32.162.77,10.0.2.15,51234,\$p,0,S,1449382391,,1024,,\"; done"
until_host "port_scan event" 120 "curl -fsS $API/state | grep -q port_scan"
vm "tail -3 /var/log/filter/latest.log" >> "$WORK/artifacts/real-log-lines.txt" || true

log "Suricata alert (eve.json reader)"
vm "mkdir -p /var/log/suricata && echo '{\"timestamp\":\"2026-11-15T09:40:01.123456+0100\",\"in_iface\":\"vtnet1\",\"event_type\":\"alert\",\"src_ip\":\"45.155.205.240\",\"src_port\":51515,\"dest_ip\":\"10.0.2.15\",\"dest_port\":443,\"proto\":\"TCP\",\"alert\":{\"action\":\"allowed\",\"signature_id\":2024897,\"rev\":3,\"signature\":\"ET SCAN test\",\"category\":\"Attempted Information Leak\",\"severity\":2}}' >> /var/log/suricata/eve.json"
until_host "ids_alert event" 90 "curl -fsS $API/state | grep -q ids_alert"

log "Learning mode from the GUI's mode switch (POST /api/v1/agent/mode)"
check "mode switch accepted" vm "configctl infrafence mode monitor root | grep -q '\"ok\"'"
until_vm "Learning: tables hold no blocking entry" 120 "! pfctl -t infrafence_bans -T show | grep -v '!' | grep -q ."
check "dashboard recorded the actor" bash -c "curl -fsS $API/state | grep -q 'opnsense-gui'"
vm "configctl infrafence mode protect root" > /dev/null || true
until_vm "Full protection: bans back" 120 "pfctl -t infrafence_bans -T show | grep -qx '   80.94.95.1'"

log "filter reload keeps the tables"
vm "configctl filter reload; sleep 3"
check "bans survive a filter reload" vm "pfctl -t infrafence_bans -T show | grep -qx '   80.94.95.1' && pfctl -t infrafence_bans -T show | grep -qx '   45.155.205.233'"

log "resources"
vm "ps -o rss=,vsz=,command= -p \$(cat /var/run/infrafence/agent.pid)" | tee "$WORK/artifacts/agent-rss.txt" || true
check "agent RSS under 60 MB" bash -c "awk '{exit !(\$1 < 61440)}' $WORK/artifacts/agent-rss.txt"
vm "configctl infrafence status" > "$WORK/artifacts/status.json" || true
vm "cat /var/db/infrafence/pf-state.json; echo; /usr/local/opnsense/scripts/OPNsense/InfraFence/log.sh" > "$WORK/artifacts/agent-log.txt" || true

log "reboot"
vm "shutdown -r now" 30 || true
sleep 20
python3 "$here/console.py" "$SOCK" login
until_vm "agent running after reboot" 300 "kill -0 \$(cat /var/run/infrafence/agent.pid)"
until_vm "bans restored after reboot" 180 "pfctl -t infrafence_bans -T show | grep -qx '   80.94.95.1' && pfctl -t infrafence_bans -T show | grep -qx '   45.155.205.233'"

log "uninstall"
check "pkg delete" vm "pkg delete -y os-infrafence infrafence-agent" 600
check "agent stopped" vm "! pgrep -f 'sbin/infrafence-agent start'"
check "aliases removed" vm "! grep -q '<name>infrafence_' /conf/config.xml"
check "rules removed" vm "! grep -q InfraFence /tmp/rules.debug"
check "InfraFence tables removed" vm "! pfctl -sT | grep -q infrafence"
check "rc.conf.d entry removed" vm "test ! -e /etc/rc.conf.d/infrafence"
check "plugin files gone" vm "test ! -e /usr/local/etc/inc/plugins.inc.d/infrafence.inc && test ! -e /usr/local/sbin/infrafence-agent"
vm "ls -la /usr/local/etc/infrafence /var/db/infrafence 2>&1" > "$WORK/artifacts/leftovers.txt" || true

curl -fsS "$API/state" > "$WORK/artifacts/mockapi-state.json" || true
log "result: $pass passed, $fail failed (artifacts in $WORK/artifacts)"
[ "$fail" -eq 0 ]
