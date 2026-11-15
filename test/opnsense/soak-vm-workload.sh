#!/bin/sh
# Runs inside the OPNsense VM every tick (soak-inside.sh): what a small
# office firewall sees. $1 = round number.
a=$(( ($1 % 250) + 1 )) # $1: a counter that changes every tick
# SSH brute force through syslog-ng: a new address each round, so bans
# pile up and expire after 24 h.
for i in 1 2 3 4 5 6; do
	logger -p auth.info -t sshd "Failed password for root from 45.155.205.$a port 4$i$a ssh2"
done
# A port scan in the filter log (reported, never banned).
p=30000
while [ $p -lt 30020 ]; do
	logger -p local0.info -t filterlog "96,,,02f4bab031b57d1e30553ce08e0ec131,vtnet1,match,block,in,4,0x0,,242,54321,0,none,6,tcp,40,193.32.162.$a,10.0.2.15,51234,$p,0,S,1449382391,,1024,,"
	p=$((p + 1))
done
# Real WAN traffic Suricata alerts on (ET Open sid 2100498).
fetch -q -o /dev/null http://10.0.2.2:18081/id.txt
true
