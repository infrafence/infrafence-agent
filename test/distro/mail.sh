# Sourced by inside.sh: mail attacks carry what the log line says, and an
# exposed database says where it listens. Lines in the format of Dovecot,
# Postfix and Exim are appended to the mail logs the agent watches (the
# syslog mail log and Exim's main log, created when missing, as on a mail
# server); each must give an event with the mailbox, protocol, method or
# recipient. A listener on [::]:5432 and one on a public address
# (203.0.113.1:3306) must give db_exposed events with bind_address.
# Adds "mail=... db_bind=..." to EXTRA_RESULT and sets EXTRA_FAIL on a
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
for _ in $(seq 1 30); do
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
for _ in $(seq 1 30); do
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

db6="" dbp=""
for _ in $(seq 1 30); do
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

EXTRA_RESULT="${EXTRA_RESULT:-} mail=${R_MAIL} db_bind=${R_DBBIND}"
[ "$R_MAIL" = ok ] && [ "$R_DBBIND" = ok ] || EXTRA_FAIL=1
