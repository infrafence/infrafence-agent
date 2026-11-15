#!/bin/sh
# Runs inside the OPNsense VM (fetched by soak-inside.sh): one JSON line
# about the agent, its pf tables and Suricata, prefixed "VMJSON ".
pid=$(cat /var/run/infrafence/agent.pid 2>/dev/null)
alive=0 rss=0 cpu=0 vsz=0
if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
	alive=1
	set -- $(ps -o rss= -o %cpu= -o vsz= -p "$pid")
	rss=$1 cpu=$2 vsz=$3
fi
cnt() { pfctl -t "$1" -T show 2>/dev/null | grep -vc '!'; }
bans=$(cnt infrafence_bans) threat=$(cnt infrafence_threat) geo=$(cnt infrafence_geo)
ref=$(pfctl -vsT 2>/dev/null | grep -cE '^....r..[[:space:]]+infrafence_')
logs=$(ls /var/log/infrafence/infrafence_*.log 2>/dev/null)
starts=0 panics=0
if [ -n "$logs" ]; then
	starts=$(cat $logs | grep -c 'Starting InfraFence agent')
	panics=$(cat $logs | grep -ciE 'panic:|fatal error|SIGSEGV|goroutine [0-9]+ \[')
fi
sur=0; pgrep -q suricata && sur=1
eve=$(grep -c '"event_type":"alert"' /var/log/suricata/eve.json 2>/dev/null); eve=${eve:-0}
prot=$(/usr/local/sbin/infrafence-agent appliance status 2>/dev/null | sed -n 's/.*"protection": "\([a-z_]*\)".*/\1/p' | head -1)
boot=$(sysctl -n kern.boottime | sed 's/^{ sec = \([0-9]*\),.*/\1/')
free=$(( $(sysctl -n vm.stats.vm.v_free_count) * $(sysctl -n hw.pagesize) / 1048576 ))
load=$(sysctl -n vm.loadavg | awk '{print $2}')
echo "VMJSON {\"agent_alive\":$alive,\"agent_pid\":\"$pid\",\"agent_rss_kb\":$rss,\"agent_cpu_pct\":$cpu,\"agent_vsz_kb\":$vsz,\"agent_starts\":$starts,\"agent_panics\":$panics,\"tables_referenced\":$ref,\"bans\":$bans,\"threat\":$threat,\"geo\":$geo,\"protection\":\"$prot\",\"suricata\":$sur,\"eve_alerts\":$eve,\"vm_boot\":$boot,\"vm_free_mb\":$free,\"vm_load1\":$load}"
