#!/bin/sh
# The last 200 lines of the agent's newest log file (syslog-ng writes
# /var/log/infrafence/infrafence_YYYYMMDD.log; latest.log may not exist yet).
f=$(ls -t /var/log/infrafence/infrafence_*.log 2> /dev/null | head -n 1)
if [ -z "$f" ]; then
	echo "No log yet."
	exit 0
fi
tail -n 200 "$f"
