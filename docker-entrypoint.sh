#!/usr/bin/env bash
set -euo pipefail

# Allow running arbitrary commands (e.g. `docker run ... infrafence-agent check`)
if [[ "${1:-}" == "infrafence-agent" ]]; then
    exec "$@"
fi

CONFIG_DIR="/etc/infrafence"
CONFIG_FILE="${CONFIG_DIR}/config.json"
BINARY="/usr/local/bin/infrafence-agent"
SERVER_URL="${INFRAFENCE_SERVER_URL:-https://infrafence.com}"
AGENT_NAME="${INFRAFENCE_AGENT_NAME:-$(hostname -s)}"

# ── Resolve secrets (supports Docker secrets via _FILE suffix) ────────────────
if [[ -z "${INFRAFENCE_TOKEN:-}" ]] && [[ -n "${INFRAFENCE_TOKEN_FILE:-}" ]] && [[ -f "$INFRAFENCE_TOKEN_FILE" ]]; then
    INFRAFENCE_TOKEN="$(cat "$INFRAFENCE_TOKEN_FILE")"
    export INFRAFENCE_TOKEN
fi

if [[ -z "${INFRAFENCE_API_KEY:-}" ]] && [[ -n "${INFRAFENCE_API_KEY_FILE:-}" ]] && [[ -f "$INFRAFENCE_API_KEY_FILE" ]]; then
    INFRAFENCE_API_KEY="$(cat "$INFRAFENCE_API_KEY_FILE")"
    export INFRAFENCE_API_KEY
fi

# ── Register if not already configured ────────────────────────────────────────
if [[ ! -f "$CONFIG_FILE" ]]; then
    mkdir -p "$CONFIG_DIR"

    # ── K8s mode: register via API key (multi-use, one key for entire cluster) ──
    if [[ -n "${INFRAFENCE_API_KEY:-}" ]]; then
        NODE_NAME="${NODE_NAME:-$(hostname -s)}"
        CLUSTER_NAME="${CLUSTER_NAME:-}"
        OS_INFO=$(cat /etc/os-release 2>/dev/null | grep '^PRETTY_NAME=' | cut -d= -f2 | tr -d '"\n' || echo "Linux")
        OS_VERSION=$(uname -r 2>/dev/null | tr -d '\n' || echo "unknown")
        IP_ADDR=$(hostname -I 2>/dev/null | awk '{print $1}' | tr -d '\n' || echo "0.0.0.0")
        AGENT_VERSION="${INFRAFENCE_VERSION:-unknown}"

        echo "[infrafence] Registering K8s node '${NODE_NAME}' with ${SERVER_URL}..."

        # Build JSON payload (avoid multiline -d issues in Alpine curl)
        PAYLOAD="{\"api_key\":\"${INFRAFENCE_API_KEY}\",\"name\":\"${NODE_NAME}\",\"hostname\":\"${NODE_NAME}\",\"ip_address\":\"${IP_ADDR}\",\"os\":\"${OS_INFO}\",\"os_version\":\"${OS_VERSION}\",\"version\":\"${AGENT_VERSION}\",\"node_name\":\"${NODE_NAME}\",\"cluster_name\":\"${CLUSTER_NAME}\"}"

        # API URL: always use api. subdomain (separable from web server)
        API_BASE="${INFRAFENCE_API_URL:-$(echo "$SERVER_URL" | sed 's|://|://api.|')}"

        HTTP_CODE=$(curl -sS -o /tmp/register-response.json -w "%{http_code}" \
            -X POST "${API_BASE}/api/v1/agents/register-k8s" \
            -H "Content-Type: application/json" \
            -H "User-Agent: InfraFenceAgent/${AGENT_VERSION}" \
            -L --post301 --post302 --post303 \
            -d "${PAYLOAD}" 2>/tmp/register-error.txt)

        RESPONSE=$(cat /tmp/register-response.json 2>/dev/null)
        CURL_ERR=$(cat /tmp/register-error.txt 2>/dev/null)

        if [[ "$HTTP_CODE" != "200" && "$HTTP_CODE" != "201" ]]; then
            echo "[infrafence] ERROR: K8s registration failed (HTTP ${HTTP_CODE})."
            [[ -n "$CURL_ERR" ]] && echo "[infrafence] curl: ${CURL_ERR}"
            [[ -n "$RESPONSE" ]] && echo "[infrafence] Response: ${RESPONSE}"
            echo "[infrafence] API URL: ${API_BASE}/api/v1/agents/register-k8s"
            echo "[infrafence] Check: API key is valid, server slots available, server URL reachable."
            exit 1
        fi

        # Parse response and write config
        AGENT_TOKEN=$(echo "$RESPONSE" | grep -o '"token":"[^"]*"' | head -1 | cut -d'"' -f4)
        AGENT_ID=$(echo "$RESPONSE" | grep -o '"id":[0-9]*' | head -1 | cut -d: -f2)
        REVERB_URL=$(echo "$RESPONSE" | grep -o '"url":"[^"]*"' | head -1 | cut -d'"' -f4)
        REVERB_KEY=$(echo "$RESPONSE" | grep -o '"app_key":"[^"]*"' | head -1 | cut -d'"' -f4)
        AUTH_ENDPOINT=$(echo "$RESPONSE" | grep -o '"auth_endpoint":"[^"]*"' | head -1 | cut -d'"' -f4)

        if [[ -z "$AGENT_TOKEN" || -z "$AGENT_ID" ]]; then
            echo "[infrafence] ERROR: Could not parse registration response."
            echo "[infrafence] Response: ${RESPONSE}"
            exit 1
        fi

        cat > "$CONFIG_FILE" << CONF
{
    "server_url": "${SERVER_URL}",
    "agent_token": "${AGENT_TOKEN}",
    "agent_id": ${AGENT_ID},
    "reverb_url": "${REVERB_URL}",
    "reverb_app_key": "${REVERB_KEY}",
    "auth_endpoint": "${AUTH_ENDPOINT}"
}
CONF
        chmod 600 "$CONFIG_FILE"
        echo "[infrafence] K8s registration complete (agent_id=${AGENT_ID}, node=${NODE_NAME})."

    # ── Standard mode: register via single-use install token ──────────────────
    elif [[ -n "${INFRAFENCE_TOKEN:-}" ]]; then
        echo "[infrafence] Registering agent '${AGENT_NAME}' with ${SERVER_URL}..."
        "$BINARY" register "$SERVER_URL" "$AGENT_NAME" "$INFRAFENCE_TOKEN"
        echo "[infrafence] Registration complete."

    else
        echo "[infrafence] ERROR: No credentials provided for registration."
        echo "[infrafence]"
        echo "[infrafence] For Kubernetes (DaemonSet):"
        echo "[infrafence]   Set INFRAFENCE_API_KEY (multi-use, one key for the whole cluster)"
        echo "[infrafence]   helm install infrafence-agent oci://ghcr.io/infrafence/charts/infrafence-agent --set apiKey=<KEY>"
        echo "[infrafence]"
        echo "[infrafence] For Docker / bare metal:"
        echo "[infrafence]   Set INFRAFENCE_TOKEN (single-use install token)"
        echo "[infrafence]   docker run -e INFRAFENCE_TOKEN=<TOKEN> ghcr.io/infrafence/infrafence-agent"
        echo "[infrafence]"
        echo "[infrafence] Get credentials at https://infrafence.com/dashboard"
        exit 1
    fi
fi

# ── Start agent ───────────────────────────────────────────────────────────────
echo "[infrafence] Starting agent..."
exec "$BINARY" start
