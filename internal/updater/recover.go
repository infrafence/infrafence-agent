package updater

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

const recoveryScriptPath = "/usr/local/bin/infrafence-agent-recover.sh"
const recoveryMarkerPath = "/tmp/infrafence-agent-recovered"

const recoveryScript = `#!/usr/bin/env bash
# InfraFence Agent Recovery Script
# Called by systemd ExecStartPre to verify the binary before starting.
# If the binary is corrupted or missing, attempts recovery:
#   1. Restore from backup (.bak)
#   2. Download fresh binary from GitHub releases

BINARY="/usr/local/bin/infrafence-agent"
BACKUP="/usr/local/bin/infrafence-agent.bak"
GITHUB_REPO="infrafence/infrafence-agent"
RELEASE_URL="https://github.com/${GITHUB_REPO}/releases/latest/download"
MARKER="/tmp/infrafence-agent-recovered"

log_msg() {
    if command -v systemd-cat >/dev/null 2>&1; then
        echo "[infrafence-recover] $*" | systemd-cat -t infrafence-agent -p info
    fi
    echo "[infrafence-recover] $*"
}

detect_arch() {
    case "$(uname -m)" in
        x86_64)        echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        *)             echo "amd64" ;;
    esac
}

verify_binary() {
    local bin="$1"
    [[ -f "$bin" ]] || return 1
    [[ -x "$bin" ]] || return 1
    timeout 30 "$bin" check >/dev/null 2>&1
}

restore_from_backup() {
    [[ -f "$BACKUP" ]] || return 1
    if verify_binary "$BACKUP"; then
        log_msg "restoring from backup $BACKUP"
        cp "$BACKUP" "${BINARY}.recover"
        chmod 755 "${BINARY}.recover"
        mv "${BINARY}.recover" "$BINARY"
        if verify_binary "$BINARY"; then
            log_msg "backup restore successful"
            echo "backup" > "$MARKER"
            rm -f /tmp/infrafence-agent-crash-count
            return 0
        fi
    fi
    return 1
}

download_fresh() {
    # Only a binary signed by InfraFence is installed: checksum and signature
    # are both required, and without openssl nothing is downloaded.
    command -v curl >/dev/null 2>&1 || return 1
    if ! command -v openssl >/dev/null 2>&1 || ! command -v base64 >/dev/null 2>&1; then
        log_msg "openssl/base64 not available: can't verify a downloaded binary, not downloading"
        return 1
    fi
    local arch
    arch="$(detect_arch)"
    local url="${RELEASE_URL}/infrafence-agent-linux-${arch}"
    local dir
    dir="$(mktemp -d)" || return 1
    local tmp="${dir}/infrafence-agent"

    log_msg "downloading fresh binary from ${url}"

    if ! curl -fsSL --connect-timeout 15 --max-time 120 -o "$tmp" "$url" 2>/dev/null \
       || ! curl -fsSL --connect-timeout 10 --max-time 30 -o "${dir}/sha256" "${url}.sha256" 2>/dev/null \
       || ! curl -fsSL --connect-timeout 10 --max-time 30 -o "${dir}/sig" "${url}.sig" 2>/dev/null; then
        rm -rf "$dir"
        log_msg "download failed"
        return 1
    fi

    local expected actual
    expected="$(awk '{print $1}' "${dir}/sha256")"
    actual="$(sha256sum "$tmp" | awk '{print $1}')"
    if [[ -z "$expected" || "$expected" != "$actual" ]]; then
        log_msg "checksum mismatch — aborting download recovery"
        rm -rf "$dir"
        return 1
    fi

    cat > "${dir}/key.pub" <<'KEYEOF'
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERVH98zew+vZQGObB+mbYnSxnyX0u
4nMAv78ZY/KNi7ko3VA7rigdf7lVoW9ndgov5Xt/fl2xQDzBhB5ZGIsDBQ==
-----END PUBLIC KEY-----
KEYEOF
    if ! base64 -d < "${dir}/sig" > "${dir}/sig.der" 2>/dev/null \
       || ! openssl dgst -sha256 -verify "${dir}/key.pub" -signature "${dir}/sig.der" "$tmp" >/dev/null 2>&1; then
        log_msg "release signature invalid — aborting download recovery"
        rm -rf "$dir"
        return 1
    fi
    log_msg "checksum and release signature verified"

    chmod 755 "$tmp"

    if ! verify_binary "$tmp"; then
        rm -rf "$dir"
        log_msg "downloaded binary failed verification"
        return 1
    fi

    cp "$tmp" "${BINARY}.recover" && chmod 755 "${BINARY}.recover" && mv "${BINARY}.recover" "$BINARY"
    rm -rf "$dir"
    log_msg "fresh binary installed successfully"
    echo "download" > "$MARKER"
    rm -f /tmp/infrafence-agent-crash-count
    return 0
}

# --- Main ---
if verify_binary "$BINARY"; then
    exit 0
fi

log_msg "binary verification failed — attempting recovery"

if restore_from_backup; then
    exit 0
fi

if download_fresh; then
    exit 0
fi

log_msg "all recovery methods failed — manual intervention needed"
# Exit 0 anyway — if we exit 1, systemd won't attempt to start at all,
# which is worse than letting it try (maybe crash counter will help).
exit 0
`

// DeployRecoveryScript writes the recovery script to disk and ensures
// the systemd service includes ExecStartPre. Called at agent startup
// to self-deploy the recovery mechanism on existing installations.
func DeployRecoveryScript() {
	// Only relevant on systemd systems
	if _, err := exec.LookPath("systemctl"); err != nil {
		return
	}

	// Write the recovery script if missing or outdated
	needsWrite := true
	if existing, err := os.ReadFile(recoveryScriptPath); err == nil {
		if string(existing) == recoveryScript {
			needsWrite = false
		}
	}

	if needsWrite {
		if err := os.WriteFile(recoveryScriptPath, []byte(recoveryScript), 0755); err != nil {
			log.Printf("[updater] failed to write recovery script: %v", err)
			return
		}
		log.Printf("[updater] recovery script deployed at %s", recoveryScriptPath)
	}

	// Check if systemd service already has ExecStartPre
	serviceFile := "/etc/systemd/system/infrafence-agent.service"
	data, err := os.ReadFile(serviceFile)
	if err != nil {
		return
	}

	if strings.Contains(string(data), "ExecStartPre") {
		return
	}

	// Add ExecStartPre before ExecStart
	content := strings.Replace(string(data),
		"ExecStart=",
		fmt.Sprintf("ExecStartPre=%s\nExecStart=", recoveryScriptPath),
		1,
	)

	if err := os.WriteFile(serviceFile, []byte(content), 0644); err != nil {
		log.Printf("[updater] failed to update service file: %v", err)
		return
	}

	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		log.Printf("[updater] daemon-reload failed: %v", err)
	} else {
		log.Printf("[updater] systemd service updated with ExecStartPre recovery")
	}
}

// CheckRecoveryMarker checks if the recovery script restored the binary
// before this process started. If so, reports the event and removes the marker.
func CheckRecoveryMarker(currentVersion string, reportEvent EventReporter) {
	data, err := os.ReadFile(recoveryMarkerPath)
	if err != nil {
		return
	}

	method := strings.TrimSpace(string(data))
	os.Remove(recoveryMarkerPath)

	log.Printf("[updater] binary was recovered via %s before startup", method)

	if reportEvent != nil {
		reportEvent("binary_recovered", "critical", map[string]string{
			"version":         currentVersion,
			"recovery_method": method,
			"reason":          "binary_corrupted_or_missing",
		})
	}
}
