# Sourced by inside.sh: the SSH hardening checks read the configuration sshd
# uses. As on a fresh cloud VPS, sshd_config says "PasswordAuthentication no"
# but /etc/ssh/sshd_config.d/50-cloud-init.conf, read first, says yes: the
# finding must fail and name that file and line. sshd itself is not
# reloaded (sshd -T and the parser read the files). Sets R_SSHCONF; appends
# to EXTRA_RESULT and sets EXTRA_FAIL=1 on a failure.
R_SSHCONF=fail
API=http://127.0.0.1:8080
main=/etc/ssh/sshd_config
dropin=/etc/ssh/sshd_config.d/50-cloud-init.conf
if grep -qE '^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf' "$main" && [ ! -e "$dropin" ]; then
  cp -p "$main" /tmp/sshd_config.orig
  printf 'PasswordAuthentication no\n' >>"$main"
  printf 'PasswordAuthentication yes\n' >"$dropin"
  log "sshd -T: $(/usr/sbin/sshd -T 2>&1 | grep -iE '^passwordauthentication|privilege' | head -2)"
  curl -s -X POST "$API/set-sync" -d '{"hardening_scan_requested": true}' >/dev/null
  found=""
  for _ in $(seq 1 120); do
    found=$(curl -s "$API/state" | grep -o '"check_id":"SSH_PASSWORD_AUTH"[^}]*}[^}]*' | head -1)
    [ -n "$found" ] && grep -q '50-cloud-init.conf:1' <<<"$found" && break
    sleep 1
  done
  curl -s -X POST "$API/set-sync" -d '{"hardening_scan_requested": null}' >/dev/null
  if grep -q '"passed":false' <<<"$found" && grep -q "PasswordAuthentication is 'yes' (set in $dropin:1)" <<<"$found" \
     && grep -q "$dropin (line 1)" <<<"$found"; then
    R_SSHCONF=ok
  else
    log "SSH_PASSWORD_AUTH finding: ${found:-none}"
  fi
  rm -f "$dropin"
  cp -p /tmp/sshd_config.orig "$main"
else
  log "sshd_config does not include sshd_config.d first, or $dropin exists: skipped"
  R_SSHCONF=skip
fi
EXTRA_RESULT="${EXTRA_RESULT:-} sshconfig=${R_SSHCONF}"
[ "$R_SSHCONF" != fail ] || EXTRA_FAIL=1
