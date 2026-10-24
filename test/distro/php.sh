# Sourced by inside.sh before the uninstall: PHP configuration hardening.
# nginx and PHP-FPM from the distribution's packages serve one test site;
# allow_url_include = On is introduced in a file of the PHP scan directory,
# the agent must report it (php_config_risk) within 60 s, the fix from the
# mock dashboard must turn it off for PHP-FPM itself (asked through nginx)
# with the site still answering, and the revert must remove the drop-in.
# Adds "php_detect=... php_fix=... php_revert=..." to EXTRA_RESULT and sets
# EXTRA_FAIL on a failure; reported as skip where the packages are missing.

R_PHP_DETECT=fail R_PHP_FIX=fail R_PHP_REVERT=fail
api=http://127.0.0.1:8080
set_sync() { curl -s -X POST -d "$1" "$api/set-sync" >/dev/null; }
php_event() { curl -s "$api/state" | grep -o "{\"type\":\"$1\"[^}]*" | grep -F "$2" | tail -1; }
wait_php_event() {
  for _ in $(seq 1 "$3"); do
    [ -n "$(php_event "$1" "$2")" ] && return 0
    sleep 1
  done
  return 1
}
field() { sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p" <<<"$2"; }
ask() { curl -s -H 'Host: php.test' http://127.0.0.1/ini.php; }

# The WAF case left Apache on port 80.
for u in apache2 httpd; do systemctl disable --now "$u" >/dev/null 2>&1; done
if command -v apt-get >/dev/null; then
  { export DEBIAN_FRONTEND=noninteractive; apt-get install -y -qq --no-install-recommends nginx php-fpm </dev/null; } >/tmp/php-pkg.log 2>&1
  rm -f /etc/nginx/sites-enabled/default
else
  dnf install -y -q nginx php-fpm >/tmp/php-pkg.log 2>&1
fi
fpm=$(systemctl list-unit-files 'php*fpm.service' --no-legend 2>/dev/null | awk '{print $1}' | head -1)
systemctl enable --now "$fpm" nginx >/dev/null 2>&1
sock=$(ls /run/php/php*-fpm.sock /run/php-fpm/www.sock 2>/dev/null | head -1)
scandir=$(ls -d /etc/php/*/fpm/conf.d /etc/php.d 2>/dev/null | head -1)

if [ -n "$sock" ] && [ -n "$scandir" ] && command -v nginx >/dev/null; then
  mkdir -p /var/www/phptest
  echo '<?php echo "allow_url_include=", var_export((bool) ini_get("allow_url_include"), true);' >/var/www/phptest/ini.php
  cat >/etc/nginx/conf.d/phptest.conf <<EOF
server {
  listen 80;
  server_name php.test;
  root /var/www/phptest;
  location ~ \.php\$ {
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    fastcgi_pass unix:$sock;
  }
}
EOF
  systemctl reload nginx
  log "php: fpm=$fpm socket=$sock scan dir=$scandir before: $(ask)"
  # Restart so the agent sees nginx, the site and PHP (baseline: no risk).
  systemctl restart infrafence-agent
  sleep 20

  echo 'allow_url_include = On' >"$scandir/50-test-risk.ini"
  systemctl reload "$fpm"
  start=$(date +%s)
  if wait_php_event php_config_risk '"directive":"allow_url_include"' 75; then
    took=$(( $(date +%s) - start ))
    ev=$(php_event php_config_risk '"directive":"allow_url_include"')
    log "php: detected in ${took}s: $ev"
    [ "$took" -le 65 ] && grep -qF "\"file\":\"$scandir/50-test-risk.ini\"" <<<"$ev" && R_PHP_DETECT=ok
    id="PHP_ALLOW_URL_INCLUDE@$(field runtime "$ev")/$(field pool "$ev")"
    on=$(ask)

    set_sync "{\"hardening_fixes\":[{\"id\":701,\"check_id\":\"$id\",\"action\":\"apply\"}]}"
    if wait_php_event hardening_fix_applied '"fix_id":"701"' 120; then
      off=$(ask)
      code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: php.test' http://127.0.0.1/ini.php)
      log "php: fix applied: before=$on after=$off http=$code $(php_event hardening_fix_applied '"fix_id":"701"')"
      [ "$on" = allow_url_include=true ] && [ "$off" = allow_url_include=false ] && [ "$code" = 200 ] &&
        grep -q '^allow_url_include = Off' "$scandir/zz-infrafence-hardening.ini" && R_PHP_FIX=ok
    fi
    [ "$R_PHP_FIX" = ok ] || { php_event hardening_fix '"fix_id":"701"'; journalctl -u infrafence-agent --no-pager | grep -E 'remediation|php' | tail -10; }

    set_sync "{\"hardening_fixes\":[{\"id\":702,\"check_id\":\"$id\",\"action\":\"revert\"}]}"
    if wait_php_event hardening_fix_applied '"fix_id":"702"' 120; then
      back=$(ask)
      log "php: reverted: $back"
      [ ! -e "$scandir/zz-infrafence-hardening.ini" ] && [ "$back" = allow_url_include=true ] && R_PHP_REVERT=ok
    fi
    [ "$R_PHP_REVERT" = ok ] || { php_event hardening_fix '"fix_id":"702"'; journalctl -u infrafence-agent --no-pager | grep -E 'remediation|php' | tail -10; }
    set_sync '{"hardening_fixes":null}'
  else
    log "php: no php_config_risk event"; journalctl -u infrafence-agent --no-pager | grep -i php | tail -10
  fi
  rm -f "$scandir/50-test-risk.ini"
  systemctl reload "$fpm" >/dev/null 2>&1
else
  R_PHP_DETECT=skip R_PHP_FIX=skip R_PHP_REVERT=skip
  log "php: nginx or PHP-FPM not available"; tail -3 /tmp/php-pkg.log 2>/dev/null
fi

EXTRA_RESULT="${EXTRA_RESULT:-} php_detect=$R_PHP_DETECT php_fix=$R_PHP_FIX php_revert=$R_PHP_REVERT"
{ [ "$R_PHP_DETECT" = fail ] || [ "$R_PHP_FIX" = fail ] || [ "$R_PHP_REVERT" = fail ]; } && EXTRA_FAIL=1
true
