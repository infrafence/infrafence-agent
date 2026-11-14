#!/bin/sh
# InfraFence free server audit: a read-only security check of this server.
#
#   curl -fsSL https://infrafence.com/audit.sh | sh
#   curl -fsSL https://infrafence.com/audit.sh | sh -s -- --no-upload
#
# It downloads the latest released InfraFence agent for this architecture,
# verifies its checksum and its release signature (cosign key, checked
# with openssl as install.sh does: without openssl nothing is downloaded),
# runs `infrafence-agent audit`, then deletes the binary
# and its temp directory. It installs nothing and changes nothing on the
# server: no service, no firewall rule, no package, no configuration file.
#
# By default the report (ids and facts, never the host name, the server's
# addresses, user names, file contents or secrets; every field is printed
# first) is sent to InfraFence and you get a private link to the result.
# --no-upload sends nothing and prints the report in the terminal only.
#
# POSIX sh: works with dash, busybox sh and bash.

set -u

# Overridable for tests and mirrors; a visible line says so when either is set.
RELEASE_BASE_OVERRIDDEN=0
UPLOAD_URL_OVERRIDDEN=0
[ -n "${RELEASE_BASE:-}" ] && RELEASE_BASE_OVERRIDDEN=1
[ -n "${INFRAFENCE_AUDIT_URL:-}" ] && UPLOAD_URL_OVERRIDDEN=1
RELEASE_BASE="${RELEASE_BASE:-https://github.com/infrafence/infrafence-agent/releases/latest/download}"
UPLOAD_URL="${INFRAFENCE_AUDIT_URL:-https://infrafence.com/api/v1/audit/report}"
TMP_DIR=""

say() { printf '[infrafence] %s\n' "$*" >&2; }
die() { printf '[infrafence] error: %s\n' "$*" >&2; exit 1; }

cleanup() {
    if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT
trap 'cleanup; exit 129' HUP
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

usage() {
    cat >&2 <<'EOF'
usage: curl -fsSL https://infrafence.com/audit.sh | sh [-s -- --no-upload]

  --no-upload   send nothing: print the report as text and JSON only
EOF
}

# Everything runs from main, called on the last line: a download cut short
# runs nothing.
main() {
    NO_UPLOAD=0
    for arg in "$@"; do
        case "$arg" in
            --no-upload) NO_UPLOAD=1 ;;
            -h|--help) usage; exit 0 ;;
            *) usage; die "unknown argument: $arg" ;;
        esac
    done

    # ── checks ──
    [ "$(uname -s 2>/dev/null)" = Linux ] || die "the audit runs on Linux servers only."

    if [ "$(id -u 2>/dev/null)" != 0 ]; then
        say "The audit needs root: it reads the authentication logs (failed SSH logins),"
        say "the SSH server's configuration and /etc/shadow (accounts without a password)."
        say "It only reads; it changes nothing. Run it again as root:"
        say "  curl -fsSL https://infrafence.com/audit.sh | sudo sh"
        exit 1
    fi

    case "$(uname -m)" in
        x86_64|amd64) ARCH=amd64 ;;
        aarch64|arm64) ARCH=arm64 ;;
        *) die "unsupported architecture $(uname -m) (supported: x86_64, aarch64)." ;;
    esac

    DISTRO="unknown"
    if [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091
        DISTRO="$(. /etc/os-release && printf '%s' "${PRETTY_NAME:-${ID:-unknown} ${VERSION_ID:-}}")"
    fi
    say "Server: ${DISTRO} (${ARCH})"
    if [ "$RELEASE_BASE_OVERRIDDEN" = 1 ]; then
        say "Note: using a non-default release base (RELEASE_BASE): ${RELEASE_BASE}"
    fi
    if [ "$UPLOAD_URL_OVERRIDDEN" = 1 ] && [ "$NO_UPLOAD" = 0 ]; then
        say "Note: using a non-default upload URL (INFRAFENCE_AUDIT_URL): ${UPLOAD_URL}"
    fi

    command -v curl >/dev/null 2>&1 || die "curl is needed to download the agent; install it and run the audit again. Nothing was downloaded and nothing on this server was changed."
    # The release signature is checked with openssl (as install.sh does):
    # without it nothing is downloaded.
    for tool in openssl base64; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            say "error: $tool is needed to verify the agent's release signature, and it is not installed."
            say "Nothing was downloaded and nothing on this server was changed."
            say "Install it and run the audit again:"
            say "  Debian, Ubuntu:                          apt-get install -y openssl coreutils"
            say "  RHEL, Rocky, Alma, Oracle, Fedora, Amazon: dnf install -y openssl coreutils"
            say "  older systems with yum:                  yum install -y openssl coreutils"
            exit 1
        fi
    done

    # sha256 of a file: sha256sum where present, else openssl.
    sha256_of() {
        if command -v sha256sum >/dev/null 2>&1; then
            sha256sum "$1" | awk '{print $1}'
        else
            openssl dgst -sha256 "$1" | awk '{print $NF}'
        fi
    }

    # ── a temp dir that may run programs (/tmp may be mounted noexec) ──
    BIN=""
    make_tmp() {
        for base in "${TMPDIR:-/tmp}" /var/tmp /dev/shm; do
            case "$base" in
            /*) ;;
            *) continue ;;
        esac
        [ -d "$base" ] || continue
            d="$(mktemp -d "${base%/}/infrafence-audit.XXXXXX" 2>/dev/null)" || continue
            printf '#!/bin/sh\nexit 0\n' > "$d/exec-test" && chmod 700 "$d/exec-test"
            if "$d/exec-test" 2>/dev/null; then
                rm -f "$d/exec-test"
                TMP_DIR="$d"
                return 0
            fi
            rm -rf "$d"
        done
        return 1
    }
    make_tmp || die "no temp directory where a program can run (/tmp, /var/tmp, /dev/shm)."
    chmod 700 "$TMP_DIR"
    BIN="$TMP_DIR/infrafence-agent"

    # ── download and verify ──
    URL="${RELEASE_BASE}/infrafence-agent-linux-${ARCH}"
    say "Downloading the InfraFence agent from ${URL}"
    curl -fsSL --proto =https,http --proto-redir =https --connect-timeout 15 --max-time 180 --max-filesize 104857600 -o "$BIN" "$URL" \
        || die "download failed from ${URL}. See https://infrafence.com/docs/troubleshooting"
    curl -fsSL --proto =https,http --proto-redir =https --connect-timeout 15 --max-time 30 --max-filesize 4096 -o "$TMP_DIR/sha256" "${URL}.sha256" \
        || die "could not download the checksum, so the agent can't be verified; nothing was run."
    curl -fsSL --proto =https,http --proto-redir =https --connect-timeout 15 --max-time 30 --max-filesize 4096 -o "$TMP_DIR/sig" "${URL}.sig" \
        || die "could not download the release signature, so the agent can't be verified; nothing was run."

    expected="$(awk '{print $1}' "$TMP_DIR/sha256")"
    actual="$(sha256_of "$BIN")"
    case "$expected" in
        *[!0-9a-f]*|"") die "the published checksum is not valid; nothing was run." ;;
    esac
    [ "${#expected}" -eq 64 ] && [ "$expected" = "$actual" ] \
        || die "checksum mismatch: the download is not the published release; nothing was run."

    # The release signing key (cosign.pub in the repository).
    cat > "$TMP_DIR/key.pub" <<'KEYEOF'
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERVH98zew+vZQGObB+mbYnSxnyX0u
4nMAv78ZY/KNi7ko3VA7rigdf7lVoW9ndgov5Xt/fl2xQDzBhB5ZGIsDBQ==
-----END PUBLIC KEY-----
KEYEOF
    if ! openssl base64 -d -A -in "$TMP_DIR/sig" -out "$TMP_DIR/sig.der" 2>/dev/null \
       || ! openssl dgst -sha256 -verify "$TMP_DIR/key.pub" -signature "$TMP_DIR/sig.der" "$BIN" >/dev/null 2>&1; then
        die "the release signature is not valid: the download was not signed by InfraFence; nothing was run."
    fi
    say "Checksum and release signature verified."
    chmod 700 "$BIN"

    # ── run ──
    if [ "$NO_UPLOAD" = 1 ]; then
        set -- audit --no-upload
    else
        set -- audit --upload "$UPLOAD_URL"
    fi
    echo >&2
    # The agent's own temp files go in this directory too.
    TMPDIR="$TMP_DIR" "$BIN" "$@" </dev/null
    status=$?
    cleanup
    TMP_DIR=""
    if [ "$status" -eq 0 ]; then
        say "Done. The agent binary and its temp directory were deleted; nothing was installed."
    fi
    exit "$status"
}

main "$@"
