# Sourced by inside.sh: mail attacks carry what the log line says, and an
# exposed database says where it listens. Lines in the format of Dovecot,
# Postfix and Exim are appended to the mail logs the agent watches (the
# syslog mail log and Exim's main log, created when missing, as on a mail
# server); each must give an event with the mailbox, protocol, method or
# recipient. Then the same without a syslog mail log file (as on Debian 12+,
# Fedora and Amazon Linux, where rsyslog is not installed): Postfix and
# Dovecot messages sent to the journal must give the same events. A listener on [::]:5432 and one on a public address
# (203.0.113.1:3306) must give db_exposed events with bind_address.
# Adds "mail=... mail_journal=... db_bind=..." to EXTRA_RESULT and sets EXTRA_FAIL on a
# failure.

R_MAIL=fail R_DBBIND=fail
MAIL_API=http://127.0.0.1:8080
# mail_event TYPE IP: the event of TYPE from IP, details included (keys
# sorted, no nested braces).
mail_event() { curl -s "$MAIL_API/state" | grep -o "{\"type\":\"$1\",\"severity\":\"[a-z]*\",\"source_ip\":\"$2\"[^}]*}" | tail -1; }

maillog=""
for f in /var/log/mail.log /var/log/maillog; do [ -f "$f" ] && { maillog=$f; break; }; done
[ -n "$maillog" ] || { maillog=/var/log/mail.log; : >"$maillog"; }
mkdir -p /var/log/exim4
[ -f /var/log/exim4/mainlog ] || : >/var/log/exim4/mainlog

# Databases listening where the internet reaches them (198.51.100.200+ is
# outside the mock country database's blocked range) (the mock dashboard
# holds the sockets).
curl -s "$MAIL_API/listen?addr=%5B::%5D:5432&net=tcp6" >/dev/null
curl -s "$MAIL_API/listen?addr=203.0.113.1:3306&net=tcp4" >/dev/null

# The agent looks for mail logs and exposed databases when it starts.
since=$(date '+%Y-%m-%d %H:%M:%S')
systemctl restart infrafence-agent
watching=no
# 60 s: on a loaded CI runner the agent took more than 30 s to get there.
for _ in $(seq 1 60); do
  journalctl -u infrafence-agent --no-pager --since "$since" | grep -q "\[mailwatcher\] watching /var/log/exim4/mainlog" && { watching=yes; break; }
  sleep 1
done
journalctl -u infrafence-agent --no-pager --since "$since" | grep -E '\[mailwatcher\]|\[dbwatcher\]' | tail -6 | sed 's/^/[mail] agent: /'
sleep 2

ts=$(date '+%b %e %H:%M:%S')
ets=$(date '+%Y-%m-%d %H:%M:%S')
host=$(cat /proc/sys/kernel/hostname)
{
  echo "$ts $host dovecot: imap-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<info@example.com>, method=PLAIN, rip=198.51.100.231, lip=203.0.113.1, TLS, session=<e2eA>"
  echo "$ts $host postfix/smtpd[4242]: NOQUEUE: reject: RCPT from unknown[198.51.100.232]: 554 5.7.1 <victim@relay-target.example>: Relay access denied; from=<spam@example.net> to=<victim@relay-target.example> proto=ESMTP helo=<x>"
} >>"$maillog"
{
  echo "$ets dovecot_login authenticator failed for (User) [198.51.100.233]:51234: 535 Incorrect authentication data (set_id=sales@example.com)"
} >>/var/log/exim4/mainlog

why=""
dov="" pfx="" exm=""
for _ in $(seq 1 60); do
  dov=$(mail_event mail_brute_force 198.51.100.231)
  pfx=$(mail_event mail_relay_scan 198.51.100.232)
  exm=$(mail_event mail_brute_force 198.51.100.233)
  [ -n "$dov" ] && [ -n "$pfx" ] && [ -n "$exm" ] && break
  sleep 1
done
for kv in '"protocol":"imap"' '"target_user":"info@example.com"' '"auth_method":"plain"' '"attempts":"1"' '"mta":"dovecot"'; do
  grep -qF "$kv" <<<"$dov" || why="$why,dovecot:$kv"
done
for kv in '"recipient":"victim@relay-target.example"' '"recipient_domain":"relay-target.example"' '"protocol":"smtp"'; do
  grep -qF "$kv" <<<"$pfx" || why="$why,postfix:$kv"
done
for kv in '"target_user":"sales@example.com"' '"auth_method":"login"' '"mta":"exim"'; do
  grep -qF "$kv" <<<"$exm" || why="$why,exim:$kv"
done
if [ "$watching" = yes ] && [ -z "$why" ]; then
  R_MAIL=ok
else
  log "mail: watching exim=$watching log=$maillog missing=${why#,}"
  printf '%s\n' "$dov" "$pfx" "$exm" | sed 's/^/[mail] event: /'
  journalctl -u infrafence-agent --no-pager | grep -i mailwatcher | tail -5 | sed 's/^/[mail] agent: /'
fi

# ── the same from the systemd journal: no syslog mail log file ──
# rsyslog is stopped and the mail log files are set aside (put back
# afterwards); the agent must follow the journal's mail messages. Postfix
# logs with the mail facility (sent by the mock to /dev/log), Dovecot is
# matched by name (systemd-cat, no facility).
R_MAILJ=skip
if command -v journalctl >/dev/null && [ -d /run/systemd/journal ]; then
  R_MAILJ=fail
  rsys=no
  systemctl is-active -q rsyslog 2>/dev/null && { rsys=yes; systemctl stop rsyslog; }
  for f in /var/log/mail.log /var/log/maillog; do
    [ -f "$f" ] && mv "$f" "$f.e2e-saved"
  done
  since=$(date '+%Y-%m-%d %H:%M:%S')
  systemctl restart infrafence-agent
  jwatching=no
  for _ in $(seq 1 60); do
    journalctl -u infrafence-agent --no-pager --since "$since" | grep -q "\[mailwatcher\] watching the systemd journal (mail)" && { jwatching=yes; break; }
    sleep 1
  done
  journalctl -u infrafence-agent --no-pager --since "$since" | grep '\[mailwatcher\]' | tail -4 | sed 's/^/[mail_journal] agent: /'
  sleep 3

  curl -s -G "$MAIL_API/syslog" --data-urlencode "tag=postfix/smtpd" \
    --data-urlencode "msg=NOQUEUE: reject: RCPT from unknown[198.51.100.234]: 554 5.7.1 <victim@journal-target.example>: Relay access denied; from=<spam@example.net> to=<victim@journal-target.example> proto=ESMTP helo=<x>" >/dev/null
  curl -s -G "$MAIL_API/syslog" --data-urlencode "tag=postfix/submission/smtpd" \
    --data-urlencode "msg=warning: unknown[198.51.100.236]: SASL LOGIN authentication failed: UGFzc3dvcmQ6, sasl_username=admin@example.com" >/dev/null
  echo "imap-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<journal@example.com>, method=PLAIN, rip=198.51.100.235, lip=203.0.113.1, TLS, session=<e2eJ>" | systemd-cat -t dovecot -p info

  jwhy=""
  jpfx="" jsub="" jdov=""
  for _ in $(seq 1 60); do
    jpfx=$(mail_event mail_relay_scan 198.51.100.234)
    jsub=$(mail_event mail_brute_force 198.51.100.236)
    jdov=$(mail_event mail_brute_force 198.51.100.235)
    [ -n "$jpfx" ] && [ -n "$jsub" ] && [ -n "$jdov" ] && break
    sleep 1
  done
  sleep 2 # a second copy of a line would come now
  for kv in '"recipient":"victim@journal-target.example"' '"recipient_domain":"journal-target.example"' '"protocol":"smtp"' '"mta":"postfix"' '"attempts":"1"'; do
    grep -qF "$kv" <<<"$jpfx" || jwhy="$jwhy,postfix:$kv"
  done
  for kv in '"target_user":"admin@example.com"' '"auth_method":"login"' '"protocol":"submission"' '"mta":"postfix"'; do
    grep -qF "$kv" <<<"$jsub" || jwhy="$jwhy,submission:$kv"
  done
  for kv in '"protocol":"imap"' '"target_user":"journal@example.com"' '"auth_method":"plain"' '"attempts":"1"' '"mta":"dovecot"'; do
    grep -qF "$kv" <<<"$jdov" || jwhy="$jwhy,dovecot:$kv"
  done
  for ip in 198.51.100.234 198.51.100.235 198.51.100.236; do
    n=$(curl -s "$MAIL_API/state" | grep -o "\"source_ip\":\"$ip\"" | wc -l)
    [ "$n" -eq 1 ] || jwhy="$jwhy,events_from_$ip=$n"
  done
  if [ "$jwatching" = yes ] && [ -z "$jwhy" ]; then
    R_MAILJ=ok
  else
    log "mail_journal: watching=$jwatching missing=${jwhy#,}"
    printf '%s\n' "$jpfx" "$jsub" "$jdov" | sed 's/^/[mail_journal] event: /'
    journalctl --no-pager -n 10 SYSLOG_FACILITY=2 + SYSLOG_IDENTIFIER=dovecot 2>&1 | sed 's/^/[mail_journal] journal: /'
  fi

  for f in /var/log/mail.log /var/log/maillog; do
    [ -f "$f.e2e-saved" ] && mv "$f.e2e-saved" "$f"
  done
  [ "$rsys" = yes ] && systemctl start rsyslog
fi

db6="" dbp=""
for _ in $(seq 1 60); do
  db6=$(curl -s "$MAIL_API/state" | grep -o '{"type":"db_exposed"[^}]*' | grep -F '"bind_address":"[::]:5432"' | tail -1)
  dbp=$(curl -s "$MAIL_API/state" | grep -o '{"type":"db_exposed"[^}]*' | grep -F '"bind_address":"203.0.113.1:3306"' | tail -1)
  [ -n "$db6" ] && [ -n "$dbp" ] && break
  sleep 1
done
if [ -n "$db6" ] && [ -n "$dbp" ]; then
  R_DBBIND=ok
else
  log "db_exposed: [::]:5432=${db6:-none} 203.0.113.1:3306=${dbp:-none}"
  curl -s "$MAIL_API/state" | grep -o '{"type":"db_exposed"[^}]*' | sed 's/^/[mail] db event: /'
  grep -E ':(1538|0CEA) ' /proc/net/tcp /proc/net/tcp6 2>/dev/null | sed 's/^/[mail] socket: /'
fi

EXTRA_RESULT="${EXTRA_RESULT:-} mail=${R_MAIL} mail_journal=${R_MAILJ} db_bind=${R_DBBIND}"
[ "$R_MAIL" = ok ] && [ "$R_MAILJ" != fail ] && [ "$R_DBBIND" = ok ] || EXTRA_FAIL=1
