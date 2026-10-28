# Sourced by inside.sh: a passive-mode FTP client is not a port scan. Like
# FileZilla, it opens a data connection to a new port of the server for every
# listing and upload (here 40 of them, ports 40000-40100); with port-scan
# bans on, it must get no port_scan event and no ban. The same address
# sweeping 20 closed ports while it holds a connection to port 21 is still a
# port scan, and banned. Pure-FTPd (cPanel's FTP server) on Debian/Ubuntu,
# vsftpd on the RHEL family; the client is namespace c7 (100.64.7.2).
# Adds "ftp=... ftp_scan=..." to EXTRA_RESULT and sets EXTRA_FAIL on a
# failure; reported as skip where the FTP server or curl's FTP is missing.

R_FTP=fail R_FTP_SCAN=fail
FTP_API=http://127.0.0.1:8080
FTP_HOST=100.64.7.1 FTP_CLIENT=100.64.7.2 FTP_USER=ftptest FTP_PASS=Ftp-test-4821
ftp_sync() { curl -s -X POST -d "$1" "$FTP_API/set-sync" >/dev/null; }
ftp_syncs() { local n; n=$(curl -s "$FTP_API/state" | grep -o '"syncs":[0-9]*' | cut -d: -f2); echo "${n:-0}"; }
ftp_scan_event() { curl -s "$FTP_API/state" | grep -o "{\"type\":\"port_scan\",\"severity\":\"[a-z]*\",\"source_ip\":\"$FTP_CLIENT\"[^}]*}" | tail -1; }
ftp_banned() {
  curl -s "$FTP_API/state" | sed -n 's/.*"bans":\(\[[^]]*\]\).*/\1/p' | grep -qF "\"$FTP_CLIENT\"" ||
    ipset list infrafence-bans 2>/dev/null | grep -q "^$FTP_CLIENT" || iptables -S INFRAFENCE 2>/dev/null | grep -q "$FTP_CLIENT"
}
in_c7() { ip netns exec c7 "$@"; }

ip netns add c7
ip link add veth10 type veth peer name veth11
ip link set veth11 netns c7
ip addr add $FTP_HOST/24 dev veth10 && ip link set veth10 up
in_c7 ip addr add $FTP_CLIENT/24 dev veth11
in_c7 ip link set veth11 up
in_c7 ip link set lo up

ftpd=""
if command -v apt-get >/dev/null; then
  { export DEBIAN_FRONTEND=noninteractive; apt-get install -y -qq --no-install-recommends pure-ftpd </dev/null; } >/tmp/ftp-pkg.log 2>&1 &&
    [ -d /etc/pure-ftpd/conf ] && ftpd=pure-ftpd
  # Debian's wrapper: one file per option.
  [ -n "$ftpd" ] && echo "40000 40100" >/etc/pure-ftpd/conf/PassivePortRange
else
  dnf install -y -q vsftpd >/tmp/ftp-pkg.log 2>&1 && [ -f /etc/vsftpd/vsftpd.conf ] && ftpd=vsftpd
  if [ -n "$ftpd" ]; then
    sed -i -E '/^(pasv_enable|pasv_min_port|pasv_max_port|seccomp_sandbox|write_enable|local_enable)=/d' /etc/vsftpd/vsftpd.conf
    printf 'local_enable=YES\nwrite_enable=YES\npasv_enable=YES\npasv_min_port=40000\npasv_max_port=40100\nseccomp_sandbox=NO\n' >>/etc/vsftpd/vsftpd.conf
  fi
fi
curl_ftp=no
curl -V 2>/dev/null | grep -i '^Protocols:' | grep -qw ftp && curl_ftp=yes

if [ -n "$ftpd" ] && [ "$curl_ftp" = yes ]; then
  useradd -m -s /bin/bash "$FTP_USER" >/dev/null 2>&1
  echo "$FTP_USER:$FTP_PASS" | chpasswd
  systemctl restart "$ftpd" >/dev/null 2>&1
  systemctl enable "$ftpd" >/dev/null 2>&1
  sleep 2
  # Port-scan bans on, so "no ban" means something; wait for the sync.
  before=$(ftp_syncs)
  ftp_sync '{"config":{"bf_threshold":5,"bf_window":60,"monitor_mode":false,"monitor_config":{"port_scan_ban":true}}}'
  for _ in $(seq 1 120); do [ "$(ftp_syncs)" -gt "$before" ] && break; sleep 1; done
  sleep 2
  # The agent reads the FTP configuration every minute: wait until it has
  # the passive range.
  got_conf=no
  for _ in $(seq 1 90); do
    journalctl -u infrafence-agent --no-pager | grep -q 'FTP server: .*passive ports 40000-40100' && { got_conf=yes; break; }
    sleep 1
  done
  journalctl -u infrafence-agent --no-pager | grep 'FTP server:' | tail -1 | sed 's/^/[agent] /'

  # One session of 20 uploads, one of 20 listings: a new data port each.
  mkdir -p /tmp/ftp-up
  names=""
  for i in $(seq -w 1 20); do echo "file $i" >/tmp/ftp-up/up$i.txt; names="$names,up$i.txt"; done
  in_c7 curl -s --max-time 120 -u "$FTP_USER:$FTP_PASS" -T "/tmp/ftp-up/{${names#,}}" "ftp://$FTP_HOST/" 2>/tmp/ftp-up.err
  up_rc=$?
  urls=""
  for _ in $(seq 1 20); do urls="$urls ftp://$FTP_HOST/"; done
  # shellcheck disable=SC2086
  listings=$(in_c7 curl -s --max-time 120 -u "$FTP_USER:$FTP_PASS" $urls 2>/tmp/ftp-list.err | grep -c 'up[0-9]*\.txt')
  uploaded=$(find "/home/$FTP_USER" -maxdepth 1 -name 'up*.txt' | wc -l)
  sleep 8
  scan=$(ftp_scan_event)
  ftp_log="ftpd=$ftpd config=$got_conf uploads=$uploaded/20 rc=$up_rc listings=$listings"
  if [ "$got_conf" = yes ] && [ "$up_rc" = 0 ] && [ "$uploaded" = 20 ] && [ "$listings" = 400 ] && [ -z "$scan" ] && ! ftp_banned; then
    R_FTP=ok
  else
    log "ftp: $ftp_log event=${scan:-none}"; cat /tmp/ftp-up.err /tmp/ftp-list.err 2>/dev/null | tail -5
    journalctl -u infrafence-agent --no-pager | grep -i portscan | tail -5
    journalctl -u "$ftpd" --no-pager | tail -5
  fi
  log "ftp: $ftp_log"

  # Still an FTP client (connected to 21), now trying 20 closed ports.
  in_c7 bash -c "exec 3<>/dev/tcp/$FTP_HOST/21; sleep 40" &
  holder=$!
  sleep 2
  for p in $(seq 2000 2019); do in_c7 timeout 1 bash -c "</dev/tcp/$FTP_HOST/$p" 2>/dev/null; done
  for _ in $(seq 1 20); do
    scan=$(ftp_scan_event)
    [ -n "$scan" ] && ftp_banned && { R_FTP_SCAN=ok; break; }
    sleep 1
  done
  [ "$R_FTP_SCAN" = ok ] || { log "ftp: sweep from the FTP client: event=${scan:-none}"; journalctl -u infrafence-agent --no-pager | grep -i portscan | tail -5; }
  # Data ports must not be in the reported sample.
  grep -Eq '"ports_sample":"([0-9]+,)*40[01][0-9]{2}[,"]' <<<"$scan" && { R_FTP_SCAN=fail; log "ftp: data ports counted: $scan"; }
  kill "$holder" 2>/dev/null

  ftp_sync '{"config":{"bf_threshold":5,"bf_window":60,"monitor_mode":false}}'
  systemctl disable --now "$ftpd" >/dev/null 2>&1
else
  R_FTP=skip R_FTP_SCAN=skip
  log "ftp: no FTP server ($ftpd) or curl without FTP ($curl_ftp)"; tail -3 /tmp/ftp-pkg.log 2>/dev/null
fi

EXTRA_RESULT="${EXTRA_RESULT:-} ftp=$R_FTP ftp_scan=$R_FTP_SCAN"
{ [ "$R_FTP" = fail ] || [ "$R_FTP_SCAN" = fail ]; } && EXTRA_FAIL=1
true
