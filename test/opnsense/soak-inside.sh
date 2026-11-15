#!/usr/bin/env bash
# Entry point of the OPNsense soak container (see soak-remote.sh). Runs as
# PID 1 in a container without any network (--network none): QEMU's
# user-mode networking connects the VM to the mock dashboard and a file
# server on the container's own loopback, and to nothing else.
#
# /work (the host's soak directory) holds everything persistent:
#   disk.img       the VM's disk (OPNsense 26.7 nano, installed once)
#   installed      marker: plugin installed, Suricata on, agent registered
#   started_at     soak start (epoch); the soak ends SOAK_DAYS after it
#   health.log     one JSON line every 10 minutes
#   console.log    the VM's serial console
#   done           marker: the soak is over (the container then idles)
set -uo pipefail

W=/work
SRC=/opt/soak
SOCK=$W/run/console.sock
DAYS=${SOAK_DAYS:-7}
MEM=${SOAK_VM_MEM:-4096}
REBOOT_HOURS=${SOAK_REBOOT_HOURS:-24}
RELOAD_HOURS=${SOAK_RELOAD_HOURS:-6}
TICK=${SOAK_TICK_SECONDS:-600}
# Minutes overrides, for a short test run.
DURATION=$(( ${SOAK_MINUTES:-0} > 0 ? ${SOAK_MINUTES:-0} * 60 : DAYS * 86400 ))
REBOOT_SECONDS=$(( ${SOAK_REBOOT_MINUTES:-0} > 0 ? ${SOAK_REBOOT_MINUTES:-0} * 60 : REBOOT_HOURS * 3600 ))
RELOAD_SECONDS=$(( RELOAD_HOURS * 3600 ))
API=http://127.0.0.1:18080

mkdir -p "$W/run" "$W/www" "$W/logs"
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$W/logs/soak.log"; }
# vm CMD [TIMEOUT]: run CMD in the VM. The command travels as a file from
# the container's file server; only a short fetch line is typed on the
# serial console (a busy guest drops typed characters).
CMDN=0
vm() {
	CMDN=$((CMDN + 1))
	mkdir -p "$W/www/cmd"
	printf '%s\n' "$1" > "$W/www/cmd/$CMDN.sh"
	python3 "$SRC/console.py" "$SOCK" run "fetch -q -o /tmp/ifc.sh http://10.0.2.2:18081/cmd/$CMDN.sh && sh /tmp/ifc.sh" "${2:-300}"
	local rc=$?
	rm -f "$W/www/cmd/$CMDN.sh"
	return $rc
}

# ---- services on the container's loopback (the VM sees them at 10.0.2.2) ----
start_services() {
	"$SRC/mockapi" -addr 127.0.0.1:18080 -binary "$SRC/infrafence-agent" -geoip /nonexistent >> "$W/logs/mockapi.log" 2>&1 &
	MOCK_PID=$!
	(cd "$W/www" && exec python3 -m http.server 18081 --bind 127.0.0.1) >> "$W/logs/www.log" 2>&1 &
	WWW_PID=$!
	sleep 1
}

stage_www() {
	cp "$SRC/infrafence-agent" "$W/www/infrafence-agent"
	cp "$SRC/packaging.tar" "$SRC/emerging.rules.tar.gz" "$SRC/soak-vm-health.sh" "$SRC/soak-vm-workload.sh" "$W/www/"
	# Content that ET Open sid 2100498 ("GPL ATTACK_RESPONSE id check
	# returned root") alerts on: fetched by the VM over its WAN.
	printf 'uid=0(root) gid=0(wheel) groups=0(wheel)\n' > "$W/www/id.txt"
}

# qemu_alive: QEMU runs (a zombie, exited but not reaped, does not count).
qemu_alive() {
	[ -n "${QEMU_PID:-}" ] && [ -r "/proc/$QEMU_PID/status" ] && ! grep -q '^State:[[:space:]]*Z' "/proc/$QEMU_PID/status"
}

boot_vm() {
	rm -f "$SOCK"
	# nice 19 / ionice idle: the soak yields to everything else on the host.
	# tb-size: TCG's translation cache defaults to 1 GiB on top of the
	# guest's memory; 256 MiB keeps QEMU inside the container's limit.
	nice -n 19 ionice -c 3 qemu-system-x86_64 -machine q35 -accel tcg,tb-size=256 -cpu max -smp 2 -m "$MEM" -nographic \
		-drive file="$W/disk.img",if=virtio,format=raw \
		-netdev user,id=lan,net=192.168.1.0/24,host=192.168.1.2,dhcpstart=192.168.1.100,restrict=on \
		-device virtio-net-pci,netdev=lan \
		-netdev user,id=wan \
		-device virtio-net-pci,netdev=wan \
		-serial unix:"$SOCK",server=on,wait=off -monitor none -display none >> "$W/logs/qemu.log" 2>&1 &
	QEMU_PID=$!
	for _ in $(seq 60); do [ -S "$SOCK" ] && break; sleep 1; done
}

shutdown_vm() {
	if qemu_alive; then
		vm "shutdown -p now" 30 > /dev/null 2>&1 || true
		for _ in $(seq 120); do qemu_alive || break; sleep 1; done
		kill "$QEMU_PID" 2> /dev/null || true
		wait "$QEMU_PID" 2> /dev/null || true
	fi
}

on_term() {
	log "stop requested: shutting the VM down cleanly"
	shutdown_vm
	kill "${MOCK_PID:-}" "${WWW_PID:-}" 2> /dev/null || true
	exit 0
}
trap on_term TERM INT

# ---- first boot: install plugin, Suricata, register ----
install_once() {
	log "first boot: interface assignment"
	python3 "$SRC/console.py" "$SOCK" boot || return 1
	log "VM: $(vm 'opnsense-version; freebsd-version -k' | tr '\n' ' ')"
	vm "for i in \$(seq 60); do fetch -q -o /dev/null http://10.0.2.2:18081/id.txt && exit 0; sleep 2; done; exit 1" 200 || return 1
	log "building the packages and a signed local repository in the VM"
	vm "mkdir -p /root/if && cd /root/if && fetch -q http://10.0.2.2:18081/infrafence-agent http://10.0.2.2:18081/packaging.tar && tar -xf packaging.tar && chmod 755 infrafence-agent" 300 || return 1
	vm "cd /root/if && sh opnsense/build-pkgs.sh -b ./infrafence-agent -v ${AGENT_VERSION:-1.0.44} -a amd64 -o /root/if/pkgs > /root/if/build.log 2>&1" 900 || return 1
	vm "cd /root/if && openssl genrsa -out repo.key 2048 2>/dev/null && openssl rsa -in repo.key -pubout -out repo.pub 2>/dev/null && sh opnsense/make-repo.sh -k repo.key -r /root/if/repo -a amd64 pkgs/*.pkg > /root/if/repo.log 2>&1" 300 || return 1
	vm "install -d /usr/local/etc/pkg/repos /usr/local/etc/pkg/keys && cp /root/if/repo.pub /usr/local/etc/pkg/keys/infrafence.pub && printf 'InfraFence: {\n  url: \"file:///root/if/repo/\${ABI}/latest\",\n  signature_type: \"pubkey\",\n  pubkey: \"/usr/local/etc/pkg/keys/infrafence.pub\",\n  enabled: yes\n}\n' > /usr/local/etc/pkg/repos/InfraFence.conf" || return 1
	log "installing os-infrafence from the signed repository"
	vm "pkg update -f -r InfraFence > /root/if/pkg.log 2>&1 && pkg install -y -r InfraFence os-infrafence >> /root/if/pkg.log 2>&1" 900 || { vm "tail -20 /root/if/pkg.log" | tee -a "$W/logs/soak.log"; return 1; }

	log "enabling Suricata (IDS on WAN) with ET Open, installed offline"
	vm "mkdir -p /usr/local/etc/suricata/rules && cd /tmp && fetch -q http://10.0.2.2:18081/emerging.rules.tar.gz && tar -xzf emerging.rules.tar.gz && cp rules/*.rules /usr/local/etc/suricata/rules/ && rm -rf /tmp/rules /tmp/emerging.rules.tar.gz && ls /usr/local/etc/suricata/rules/*.rules | wc -l" 600 | tee -a "$W/logs/soak.log"
	vm "cd /usr/local/opnsense/mvc && php -r 'require_once \"script/load_phalcon.php\"; \$m = new \\OPNsense\\IDS\\IDS(); \$m->general->enabled = \"1\"; \$m->general->mode = \"pcap\"; \$m->general->interfaces = \"wan\"; \$m->serializeToConfig(); \\OPNsense\\Core\\Config::getInstance()->save();'" 600 || return 1
	# installRules.py directly: under emulation it outlasts configd's wait.
	vm "configctl template reload OPNsense/IDS > /dev/null; /usr/local/opnsense/scripts/suricata/installRules.py && ls /usr/local/etc/suricata/opnsense.rules/*.rules | wc -l" 1800 | tee -a "$W/logs/soak.log"
	vm "configctl ids restart > /dev/null; sleep 5; configctl ids status" 900 | tee -a "$W/logs/soak.log"

	log "configuring and registering against the mock dashboard (in this container)"
	vm "cd /usr/local/opnsense/mvc && php -r 'require_once \"script/load_phalcon.php\"; \$m = new \\OPNsense\\InfraFence\\General(); \$m->enabled = \"1\"; \$m->server_url = \"http://10.0.2.2:18080\"; \$m->mode = \"protect\"; \$m->interfaces = \"wan\"; \$m->serializeToConfig(); \\OPNsense\\Core\\Config::getInstance()->save();'" 600 || return 1
	vm "install -d -m 0750 /var/db/infrafence && touch /var/db/infrafence/allow-http && umask 077 && echo 'soak-install-token-0123456789' > /var/db/infrafence/register.token" || return 1
	vm "configctl infrafence register" 180 | tee -a "$W/logs/soak.log" | grep -q '"status":"ok"' || return 1
	vm "configctl template reload OPNsense/InfraFence > /dev/null; configctl filter reload > /dev/null; configctl infrafence start > /dev/null; sleep 5; kill -0 \$(cat /var/run/infrafence/agent.pid)" 180 || return 1
	touch "$W/installed"
	log "installed"
}

# A network ban and an allow-list entry from the "dashboard" (the mock
# keeps them in memory: set again after every container start).
seed_dashboard() {
	python3 - "$API" <<'PY' || true
import json, sys, urllib.request
body = json.dumps({"bans": [{"id": 1, "ip_address": "80.94.95.1", "expires_at": None}],
                   "whitelists": [{"id": 1, "ip_address": "37.19.221.10"}]}).encode()
urllib.request.urlopen(urllib.request.Request(sys.argv[1] + "/set-sync", data=body, method="POST"), timeout=10)
PY
}

# ---- workload: what a small office firewall sees, every tick ----
round=0
workload() {
	round=$((round + 1))
	# The address changes every tick, also across restarts (bans last 24 h).
	vm "set -- $(( $(date +%s) / TICK ))
$(cat "$SRC/soak-vm-workload.sh")" 300 > /dev/null 2>&1 || log "workload round $round: console command failed"
}

health() {
	local vmjson
	vmjson=$(vm "$(cat "$SRC/soak-vm-health.sh")" 180 2>/dev/null | sed -n 's/^VMJSON //p' | tail -1)
	[ -n "$vmjson" ] || vmjson='{"console":"no answer"}'
	python3 - "$API" "$vmjson" "$W/health.log" "${QEMU_PID:-0}" "$round" <<'PY'
import json, os, sys, time, urllib.request
api, vmjson, out, qpid, rnd = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "round": rnd}
try:
    rec["vm"] = json.loads(vmjson)
except ValueError:
    rec["vm"] = {"unparsed": vmjson[:300]}
try:
    st = json.load(urllib.request.urlopen(api + "/state", timeout=10))
    ev = {}
    for e in st.get("events") or []:
        ev[e.get("type", "?")] = ev.get(e.get("type", "?"), 0) + 1
    hb = st.get("last_heartbeat") or {}
    rec["dashboard"] = {"heartbeats": st.get("heartbeats"), "syncs": st.get("syncs"), "bans_reported": len(st.get("bans") or []),
                        "events": ev, "protection": (hb.get("appliance") or {}).get("protection"),
                        "agent_rss_bytes": (hb.get("runtime") or {}).get("rss_bytes"),
                        "event_queue": (hb.get("runtime") or {}).get("event_queue_len"),
                        "events_dropped": (hb.get("runtime") or {}).get("event_dropped")}
except Exception as exc:
    rec["dashboard"] = {"error": str(exc)[:200]}
def cg(name):
    try:
        return open("/sys/fs/cgroup/" + name).read().split()[0]
    except OSError:
        return None
oom = None
try:
    for l in open("/sys/fs/cgroup/memory.events"):
        k, v = l.split()
        if k == "oom_kill":
            oom = int(v)
except OSError:
    pass
rec["container"] = {"memory_bytes": cg("memory.current"), "memory_peak_bytes": cg("memory.peak"),
                    "oom_kills": oom, "qemu_alive": qpid > 0 and os.path.exists("/proc/%d" % qpid)}
with open(out, "a") as f:
    f.write(json.dumps(rec, separators=(",", ":")) + "\n")
PY
}

# ---- main ----
log "soak container start (days=$DAYS, vm memory=${MEM} MB, tick=${TICK}s)"
if [ -e "$W/done" ]; then
	log "soak already finished: idling (stop and cleanup with soak-remote.sh)"
	while true; do sleep 3600 & wait $!; done
fi
stage_www
start_services
if [ ! -e "$W/disk.img" ]; then
	log "decompressing the OPNsense image"
	bzip2 -dc "$SRC/opnsense.img.bz2" > "$W/disk.img.tmp" && mv "$W/disk.img.tmp" "$W/disk.img"
fi
boot_vm
if [ ! -e "$W/installed" ]; then
	if ! install_once; then
		log "INSTALL FAILED: see logs/console.log; the container stays up for inspection"
		echo "{\"ts\":\"$(date -u +%FT%TZ)\",\"error\":\"install failed\"}" >> "$W/health.log"
		while true; do sleep 3600 & wait $!; done
	fi
	date +%s > "$W/started_at"
else
	log "resuming: waiting for the VM to boot"
	python3 "$SRC/console.py" "$SOCK" login || log "no login prompt after boot"
fi
[ -e "$W/started_at" ] || date +%s > "$W/started_at"
seed_dashboard
end=$(( $(cat "$W/started_at") + DURATION ))
last_reload=$(date +%s)
last_reboot=$(date +%s)
log "soak running until $(date -u -d @$end +%FT%TZ 2>/dev/null || echo $end)"
while [ "$(date +%s)" -lt "$end" ]; do
	if ! qemu_alive; then
		log "CRASH: QEMU exited; booting the VM again"
		echo "{\"ts\":\"$(date -u +%FT%TZ)\",\"event\":\"qemu_exited\"}" >> "$W/health.log"
		boot_vm
		python3 "$SRC/console.py" "$SOCK" login || log "no login prompt after restart"
				seed_dashboard
	fi
	workload
	now=$(date +%s)
	if [ "$RELOAD_SECONDS" -gt 0 ] && [ $((now - last_reload)) -ge "$RELOAD_SECONDS" ]; then
		log "filter reload"
		vm "configctl filter reload" 300 > /dev/null 2>&1 || true
		last_reload=$now
	fi
	if [ "$REBOOT_SECONDS" -gt 0 ] && [ $((now - last_reboot)) -ge "$REBOOT_SECONDS" ]; then
		log "planned VM reboot"
		echo "{\"ts\":\"$(date -u +%FT%TZ)\",\"event\":\"planned_reboot\"}" >> "$W/health.log"
		vm "shutdown -r now" 30 > /dev/null 2>&1 || true
		sleep 20
		python3 "$SRC/console.py" "$SOCK" login || log "no login prompt after the planned reboot"
		last_reboot=$(date +%s)
	fi
	health
	sleep "$TICK" & wait $!
done
log "soak finished after $((DURATION / 60)) minutes"
health
touch "$W/done"
shutdown_vm
kill "${MOCK_PID:-}" "${WWW_PID:-}" 2> /dev/null || true
while true; do sleep 3600 & wait $!; done
