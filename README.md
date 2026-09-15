<p align="center">
  <a href="README.md">English</a> ·
  <a href="README.it.md">Italiano</a> ·
  <a href="README.pt-br.md">Português (BR)</a>
</p>

<p align="center">
  <img src="docs/logo.png" alt="InfraFence" width="200">
</p>

<h3 align="center">Server security that installs in 30 seconds</h3>

<p align="center">
  Lightweight Go agent that detects attacks in real time and blocks them automatically — inbound and outbound.<br>
  SSH brute force, WAF, malware scanning, bot management, egress & DNS threat detection, Docker and Kubernetes — zero configuration.
</p>

<p align="center">
  <a href="https://github.com/infrafence/infrafence-agent/releases"><img src="https://img.shields.io/github/v/release/infrafence/infrafence-agent?label=version&color=brightgreen" alt="Version"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://go.dev"><img src="https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white" alt="Go"></a>
  <a href="https://github.com/infrafence/infrafence-agent"><img src="https://img.shields.io/badge/Platform-Linux-orange?logo=linux&logoColor=white" alt="Platform"></a>
  <a href="https://github.com/infrafence/infrafence-agent/pkgs/container/infrafence-agent"><img src="https://img.shields.io/badge/Docker-ghcr.io-2496ED?logo=docker&logoColor=white" alt="Docker"></a>
  <a href="https://artifacthub.io/packages/helm/infrafence/infrafence-agent"><img src="https://img.shields.io/badge/Helm-Artifact_Hub-0F1689?logo=helm&logoColor=white" alt="Helm"></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/infrafence/infrafence-agent"><img src="https://api.securityscorecards.dev/projects/github.com/infrafence/infrafence-agent/badge" alt="OpenSSF Scorecard"></a>
</p>

<p align="center">
  <a href="https://infrafence.com">Website</a> ·
  <a href="https://infrafence.com/docs">Docs</a> ·
  <a href="https://infrafence.com/docs/installation">Install Guide</a> ·
  <a href="https://infrafence.com/pricing">Pricing</a> ·
  <a href="https://github.com/infrafence/infrafence-agent/issues">Issues</a>
</p>

---

## The problem

Spin up a fresh Linux VPS and the clock starts immediately — automated bots are scanning it, brute-forcing SSH, and probing for exploits within minutes, often before you've even finished the initial setup.

Most of that activity goes unnoticed. Nobody's watching the logs as it happens.

**fail2ban** only reacts after the fact and tells you nothing about what happened. **CrowdSec** is capable but takes real effort to configure properly. The enterprise tools that give you both visibility and automation start at $20-200+ per host.

InfraFence sits in between: **install with one command, watch everything live from a dashboard, and let it block automatically — for €9/server**.

## Quick start

```bash
# Linux (one-liner)
curl -fsSL https://infrafence.com/install.sh | sudo bash -s -- --token <YOUR_TOKEN>

# Docker
docker run -d --name infrafence-agent --restart unless-stopped \
  --network host --pid host \
  -v /var/log:/var/log:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -e INFRAFENCE_TOKEN=<YOUR_TOKEN> \
  ghcr.io/infrafence/infrafence-agent:latest

# Kubernetes (Helm)
helm install infrafence-agent \
  oci://ghcr.io/infrafence/charts/infrafence-agent \
  --set config.organizationApiKey=<YOUR_API_KEY> \
  --namespace infrafence-system --create-namespace
```

> **[Get your token at infrafence.com](https://infrafence.com)** — free tier includes 1 server with full protection.

---

## Why InfraFence

| | fail2ban | CrowdSec | BitNinja | **InfraFence** |
|---|:---:|:---:|:---:|:---:|
| Real-time dashboard | — | Paid ($2K+/yr) | Yes | **Yes** |
| One-command install | — | — | cPanel only | **Yes** |
| SSH detection | Yes | Yes | Yes | **Yes (15 patterns)** |
| SSH session risk scoring (post-login behavior) | — | — | — | **Yes** |
| Web Application Firewall | — | Partial | Yes | **Yes (15 OWASP types)** |
| Bot management | — | — | Yes | **Yes (70+ fingerprints)** |
| Malware scanning | — | — | Yes | **Yes (YARA + hash DB + quarantine)** |
| File integrity & persistence monitoring | — | — | WP core only | **Yes (system-wide)** |
| Docker container awareness | — | — | — | **Yes** |
| Kubernetes / Helm | — | Yes | — | **Yes (DaemonSet)** |
| Outbound threat detection (egress & DNS) | — | — | — | **Yes** |
| Monitor mode (detect only) | — | — | — | **Yes** |
| Works on any Linux | Yes | Yes | cPanel/Plesk | **Yes** |
| Price | Free | Free / $2K+ | €14-52/srv | **€9/srv** |

---

## What it detects

### SSH & brute force
15 detection patterns: failed passwords, invalid users, PAM failures, pre-auth scanning, protocol mismatches, kex negotiation drops. Patterns are synced from the dashboard — enable/disable per server without restarting the agent.

### Web Application Firewall

| Attack type | Score | Mode |
|---|:---:|---|
| RCE / Web shell / Shellshock | +50 | Score-based |
| Scanner UA (sqlmap, nikto, nmap, nuclei...) | +50 | Score-based |
| SQL injection / SSRF / Web exploit | +40 | Score-based |
| Honeypot trap (50+ decoy endpoints) | +40 | Score-based |
| Path traversal / Header injection | +30 | Score-based |
| WordPress brute force | +30 | Threshold (10 req / 2 min) |
| XSS / `.env` probe / XMLRPC | +25 | Score-based |
| Config probing / Scanner pattern | +20 | Score-based |
| 404 flood | +15 | Threshold (30 req / 5 min) |

Each detection adds points to a per-IP score. Scores decay at -5 pts/min. Action levels: **observe** (30) → **throttle** (60) → **block 1h** (80) → **blacklist 24h** (100+). All weights configurable per server.

### Bot management
70+ bot fingerprints (search engines, AI crawlers, SEO tools, scanners). Per-org policies: **allow** / **log** / **block**. Blocked bots are rejected at nginx/Apache level — connection closed before your app is reached.

### Malware scanner
- **Signature scanning** — 24 built-in patterns for webshells, backdoors, crypto miners, phishing kits
- **Hash matching** — 64,000+ known malware hashes from MalwareBazaar and Linux Malware Detect
- **YARA engine** — 229 web-relevant rules (uses yara CLI if installed, optional)
- **Framework detection** — auto-detects Laravel, WordPress, Django, Symfony, CakePHP, CodeIgniter, Node/Express, Rails, Joomla, Drupal
- **Framework security checks** — .env exposure, DEBUG mode, APP_KEY, loose permissions, Telescope, wp-config
- **Heuristic analysis** — Shannon entropy detection, timestamp anomalies in upload directories
- **System integrity** — `dpkg -V` / `rpm -Va` for modified binaries, rootkit indicators (ld.so.preload, hidden processes, /tmp executables)
- **Credential scan** — exposed .env files, SSH key permissions, .git in web root, cloud provider credentials
- **WP database scan** — injected scripts in posts/options, rogue admin users
- **Process detection** — running crypto miners, reverse shells, suspicious scripts from /tmp
- **Security posture score** — 0-100 (A-F grade) with breakdown by category
- **Quarantine** — move malicious files to `/var/lib/infrafence/quarantine/` with restore capability
- **Scheduled scans** — configurable frequency, time, and intensity from the dashboard
- **Realtime watcher** — polls upload directories every 30s for new PHP files
- **False positive prevention** — WP core checksums, context-based severity, user allowlist with cross-network herd immunity

### ModSecurity inline WAF
- **Auto-detects** Apache + mod_security2 at startup (standard on cPanel/WHM)
- **14 static rules** — SQL injection, XSS, RCE, SSRF, path traversal, Shellshock, Log4Shell, Spring4Shell, scanner blocking
- **Blocks on first request** — ModSecurity intercepts before traffic reaches your application
- **IP ban rules** — banned IPs synced from dashboard to ModSecurity for HTTP-level blocking
- **Zero config** — automatically writes rules, configures Include, graceful reload (no downtime)
- **No impact** on servers without ModSecurity — falls back to iptables-only blocking

### Outbound threat detection (egress & DNS)
Most tools only watch traffic coming *in*. InfraFence also watches what an already-compromised host does *out* — the same threat feed used for inbound bans (Spamhaus DROP, Feodo Tracker, and more) is checked against outbound activity too:
- **Egress threat matching** — flags established outbound connections to any IP on your threat feed, catching a compromised host beaconing out to C2 infrastructure that inbound-only firewall rules never see
- **DNS resolver monitoring** — flags outbound DNS traffic (UDP/53) to threat-feed IPs, to resolvers outside your configured `/etc/resolv.conf`, and to "resolver hopping" (many distinct external resolvers in a short window) — an early signal of DNS tunneling
- Poll-based on the same cycle as the other monitors: reliably catches *sustained* traffic — tunneling, repeated beaconing — rather than a single one-off query

### File integrity & persistence monitoring
SHA-256 baseline hashing with instant alerts on change, covering both classic tripwire targets and common persistence techniques:
- Core system files — `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/sudoers` (+ `sudoers.d/*`), `/etc/ssh/sshd_config`, `/etc/hosts`, `/etc/resolv.conf`
- Scheduled-task persistence — `/etc/crontab`, `/etc/cron.d/*`, and **per-user crontabs** (`/var/spool/cron/crontabs/*` on Debian, `/var/spool/cron/*` on RHEL)
- SSH persistence — `authorized_keys` for root and every user under `/home/*`
- Rootkit / hijack points — `/etc/ld.so.preload` (classic userspace LD_PRELOAD hijack)
- Systemd persistence — `/etc/systemd/system/*.service` and `*.timer` (a common cron replacement for planting persistence)

### SSH session risk scoring
Tracks every SSH session end-to-end — auth method, source IP reputation, login hour, privileged commands (`sudo`, `useradd`, `passwd`, `crontab`, `su`) — and scores it 0-100 on close. **Sigma correlation**: if any other detector (WAF, integrity, malware, port scan, egress, DNS) fires while a session is open, that session's risk score jumps — turning scattered low-confidence signals into one high-confidence alert tied to exactly who was logged in when it happened.

### And more
- **Mail & FTP protection** — Postfix, Dovecot, Pure-FTPD, MySQL brute force detection
- **Docker-aware** — auto-detects web containers, reads logs via bind mounts and volumes
- **GeoIP blocking** — block entire countries from the dashboard
- **Network ban propagation** — ban on one server applies to all your servers
- **Security scanner** — 30+ hardening checks with auto-remediation
- **Vulnerability scanning** — CVE matching via NVD + Exploit-DB, EPSS scoring
- **Monitor mode** — detect threats without blocking (new servers default to this)
- **System metrics** — CPU, memory, disk reported to dashboard
- **cPanel/WHM addon** — native sidebar integration with cPHulk and domlog auto-detection

---

## How it works

```
auth.log / web access logs / Docker logs / K8s ingress logs
    │
    ▼
Log auto-detection
    │  nginx -T / apachectl -S / docker inspect / K8s API
    │  Resolves bind mounts, volumes, symlinks
    ▼
Watcher goroutines
    │  Detect brute force, SQLi, XSS, SSRF, path traversal, web shells...
    ▼
Bot Scoring Engine (per-IP, decaying)
    │
    ├─ < 30 pts  → observe (log only)
    ├─ ≥ 30 pts  → throttle
    ├─ ≥ 80 pts  → block 1h
    └─ ≥ 100 pts → blacklist 24h
            │
            ▼
    ipset add infrafence-bans <IP>
            │  Falls back to iptables -I INPUT -s <IP> -j DROP
            │  ipset: 65K+ IPs  ·  iptables fallback: 500 (FIFO rotation)
            │
            ├──► POST /api/v1/agent/bans → dashboard
            └──► WebSocket propagates ban to all your servers
```

The agent **never bans** reserved IPs, your server's own IPs, or the InfraFence API endpoint — even if the backend sends a bad rule.

---

## Install

### Linux (recommended)

```bash
curl -fsSL https://infrafence.com/install.sh | sudo bash -s -- --token <YOUR_TOKEN>
```

**Supported:** Ubuntu 20+, Debian 11+, CentOS 7+, RHEL 8+, Rocky, Alma, Amazon Linux 2023, Fedora
**Requires:** `iptables`, `systemd`, root access · **Recommended:** `ipset` (increases ban capacity to 65K+)

### Docker

```bash
docker run -d --name infrafence-agent --restart unless-stopped \
  --network host --pid host \
  -v /var/log:/var/log:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v infrafence-config:/etc/infrafence \
  -e INFRAFENCE_TOKEN=<YOUR_TOKEN> \
  ghcr.io/infrafence/infrafence-agent:latest
```

**Image:** `ghcr.io/infrafence/infrafence-agent` — multi-arch (amd64 + arm64), ~40MB

<details>
<summary>Docker Compose</summary>

```yaml
services:
  infrafence-agent:
    image: ghcr.io/infrafence/infrafence-agent:latest
    container_name: infrafence-agent
    restart: unless-stopped
    privileged: true
    network_mode: host
    pid: host
    environment:
      - INFRAFENCE_TOKEN=${INFRAFENCE_TOKEN}
    volumes:
      - /var/log:/var/log:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - infrafence-config:/etc/infrafence

volumes:
  infrafence-config:
```

```bash
INFRAFENCE_TOKEN=<YOUR_TOKEN> docker compose up -d infrafence-agent
```

</details>

<details>
<summary>Docker Swarm (global service)</summary>

```bash
# Store token as a Docker secret
echo "<YOUR_TOKEN>" | docker secret create infrafence_token -

# Deploy 1 agent per node
docker stack deploy -c docker-compose.swarm.yml infrafence
```

See [docker-compose.swarm.yml](docker-compose.swarm.yml) for the full stack definition.

</details>

### Kubernetes (Helm)

```bash
helm install infrafence-agent \
  oci://ghcr.io/infrafence/charts/infrafence-agent \
  --set config.organizationApiKey=<YOUR_API_KEY> \
  --set config.serverUrl=https://infrafence.com \
  --namespace infrafence-system --create-namespace
```

Deploys a **DaemonSet** — one agent per node (including control-plane). RBAC, tolerations, and resource limits pre-configured.

<details>
<summary>Custom values.yaml</summary>

```yaml
config:
  organizationApiKey: "your-org-api-key"
  serverUrl: "https://infrafence.com"
  clusterName: "production"    # auto-detected if omitted

resources:
  limits:
    cpu: 100m
    memory: 128Mi
  requests:
    cpu: 50m
    memory: 64Mi

tolerations:
  - operator: Exists           # run on all nodes
```

```bash
helm install infrafence-agent \
  oci://ghcr.io/infrafence/charts/infrafence-agent \
  -f values.yaml -n infrafence-system --create-namespace
```

</details>

**Chart:** [Artifact Hub](https://artifacthub.io/packages/helm/infrafence/infrafence-agent) · Images signed with [Cosign](https://github.com/sigstore/cosign) · Helm chart with GPG provenance

### Uninstall

```bash
curl -fsSL https://infrafence.com/install.sh | sudo bash -s -- --uninstall
```

---

## Configuration

<details>
<summary><strong>Per-server WAF configuration</strong></summary>

Each attack type can be independently configured from the dashboard (Server → Web Protection). Changes sync within 60 seconds.

- **Enable/disable types** — disable rules irrelevant to your stack (e.g. `wp_bruteforce` on a non-WordPress server)
- **Detect-only mode** — record events without banning
- **Custom thresholds** — override defaults for `wp_bruteforce`, `xmlrpc_abuse`, `scanner_detected`, `404_flood`
- **Custom score weights** — adjust points per detection type

`null` WAF config → all 15 types active with default thresholds (fully backward compatible).

</details>

<details>
<summary><strong>Docker labels</strong></summary>

Configure monitoring per container via Docker labels — no agent restart needed:

```yaml
services:
  nginx:
    image: nginx
    labels:
      infrafence.monitor: "true"
      infrafence.log-path: "/var/log/nginx/access.log"
      infrafence.domain: "example.com,api.example.com"
    volumes:
      - /var/log/nginx:/var/log/nginx
```

| Label | Values | Effect |
|---|---|---|
| `infrafence.monitor` | `true` / `false` | Force-include or exclude a container |
| `infrafence.log-path` | Host path(s), comma-separated | Explicit log path (skips auto-detection) |
| `infrafence.domain` | Domain(s), comma-separated | Associate domain names with logs |
| `infrafence.waf` | `true` / `false` | Informational (WAF is controlled from the panel) |

**Priority**: `infrafence.log-path` label > `nginx -T` auto-detection > bind-mount scan > `docker logs`.

</details>

<details>
<summary><strong>Manual log path override</strong></summary>

If auto-detection doesn't find your logs, set `WEB_LOG_PATH`:

```bash
sudo systemctl edit infrafence-agent
```

```ini
[Service]
Environment="WEB_LOG_PATH=/var/log/httpd/access_log,/var/log/nginx/custom.log"
```

```bash
sudo systemctl restart infrafence-agent
```

</details>

<details>
<summary><strong>Environment variables</strong></summary>

Stored in `/etc/infrafence/agent.conf`:

| Variable | Description | Default |
|---|---|---|
| `INFRAFENCE_TOKEN` | Agent auth token | *(from registration)* |
| `INFRAFENCE_SERVER` | Panel server URL | `https://infrafence.com` |
| `INFRAFENCE_LOG_PATH` | Auth log file path | *(auto-detected)* |
| `INFRAFENCE_HEARTBEAT` | Heartbeat interval (seconds) | `30` |
| `INFRAFENCE_BAN_THRESHOLD` | Failed attempts before ban | `5` |
| `INFRAFENCE_WS_ENABLED` | Enable WebSocket | `true` |
| `INFRAFENCE_GEOIP_ENABLED` | Enable GeoIP lookups | `true` |
| `WEB_LOG_PATH` | Override web log paths | *(auto-detected)* |

</details>

---

## Troubleshooting

<details>
<summary><code>"Peer's Certificate issuer is not recognized"</code> during install</summary>

Affects CentOS 7, RHEL 7, and systems with outdated `ca-certificates`:

```bash
curl -sk https://letsencrypt.org/certs/isrgrootx1.pem -o /tmp/isrg.pem
export CURL_CA_BUNDLE=/tmp/isrg.pem
curl -fsSL https://infrafence.com/install.sh | sudo bash -s -- --token <YOUR_TOKEN>
```

</details>

<details>
<summary>Agent shows <code>203/EXEC</code> — service fails to start</summary>

Binary missing or corrupted. Restore from backup:

```bash
cp /usr/local/bin/infrafence-agent.bak /usr/local/bin/infrafence-agent
chmod 755 /usr/local/bin/infrafence-agent
systemctl reset-failed infrafence-agent && systemctl start infrafence-agent
```

If `start-limit-hit`:

```bash
systemctl reset-failed infrafence-agent
systemctl start infrafence-agent
```

</details>

<details>
<summary>WAF not detecting attacks</summary>

Check which logs the agent is monitoring:

```bash
journalctl -u infrafence-agent | grep webwatcher
```

If no logs found: your web server logs must be accessible on the host. For Docker web servers, bind-mount the log directory:

```yaml
volumes:
  - /var/log/nginx:/var/log/nginx
```

</details>

More troubleshooting at [infrafence.com/docs/troubleshooting](https://infrafence.com/docs/troubleshooting).

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    InfraFence Cloud                        │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐  │
│  │ Dashboard │  │ REST API │  │ WebSocket│  │ Threat │  │
│  │  (Vue 3) │  │ (Laravel)│  │ (Reverb) │  │  Intel │  │
│  └──────────┘  └──────────┘  └──────────┘  └────────┘  │
└───────────────────────┬─────────────────────────────────┘
                        │ HTTPS + WSS
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
   ┌─────────┐    ┌─────────┐    ┌─────────────┐
   │  Agent  │    │  Agent  │    │ Agent (K8s) │
   │  (VPS)  │    │(Docker) │    │ (DaemonSet) │
   └─────────┘    └─────────┘    └─────────────┘
   SSH + WAF      SSH + WAF +     Ingress WAF +
   + GeoIP        Docker detect   Pod events +
   + Metrics      + Container     API audit
                  inventory
```

The agent is a single static Go binary (~12MB). No dependencies, no runtime, no garbage. Runs as `systemd` service, Docker container, or Kubernetes DaemonSet.

**Resource usage:** <1% CPU, <30MB RAM on a typical server.

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for the full version history.

Recent highlights:

| Version | Highlight |
|---|---|
| v1.0.0 | First official InfraFence release — Sigma session risk correlation, egress/DNS threat detection, extended persistence monitoring, signed releases |
| v0.9.80+ | Kubernetes DaemonSet support, Helm chart, ingress WAF |
| v0.9.63 | Docker Swarm global service, Docker secrets |
| v0.9.62 | Docker labels (`infrafence.monitor`, `infrafence.log-path`, `infrafence.domain`) |
| v0.9.50+ | Cumulative per-IP WAF scoring engine with configurable weights |
| v0.9.44 | Dynamic detection rules from dashboard (SSH patterns per server) |
| v0.9.42 | Monitor mode (detect without blocking) |
| v0.9.40 | Bot management with allow/log/block policies |
| v0.9.33 | ipset firewall backend (65K+ ban capacity) |
| v0.9.27 | Security scanner (30+ hardening checks) |
| v0.9.20 | Docker container detection and log discovery |
| v0.9.0 | Initial WAF: 15 OWASP attack types |

---

## Security & trust

Running this agent means granting it privileged access to your server — that's a real ask, and we don't take it lightly. Here's exactly what backs that trust in production:

| | Detail |
|---|---|
| **Open source** | Every line of code is MIT licensed. Audit it before installing. |
| **Minimal footprint** | Reads auth logs and web access logs. No access to app code, databases, env vars, SSH keys, or user data. |
| **Dedicated firewall chain** | Uses its own `INFRAFENCE` iptables chain — your existing rules are never modified. |
| **Data transparency** | Only attack metadata is sent to your dashboard (attacker IP, type, timestamp). Raw logs never leave your server. No telemetry, no third-party sharing. |
| **Signed binaries** | Every release is built by GitHub Actions CI with [Cosign](https://github.com/sigstore/cosign) signatures and [build provenance attestation](https://github.com/infrafence/infrafence-agent/attestations). |
| **Monitor mode** | Start in detect-only mode — see everything, block nothing. Enable protection when ready. |
| **Clean uninstall** | `curl -fsSL https://infrafence.com/install.sh \| sudo bash -s -- --uninstall` — removes binary, config, and firewall chain. No residual changes. |

Full details in [SECURITY.md](SECURITY.md) and [infrafence.com/docs/trust](https://infrafence.com/docs/trust).

---

## Contributing

Contributions are welcome. Please [open an issue](https://github.com/infrafence/infrafence-agent/issues) before submitting large changes.

```bash
# Build
go build -o infrafence-agent ./cmd/infrafence-agent

# Run locally
./infrafence-agent start
```

---

## License

[MIT](LICENSE) — use it however you want.

---

<p align="center">
  <a href="https://infrafence.com">infrafence.com</a> · Live Security Operations
</p>
