<p align="center">
  <a href="README.md">English</a> ·
  <a href="README.it.md">Italiano</a> ·
  <a href="README.pt-br.md">Português (BR)</a> ·
  <a href="README.es.md">Español</a> ·
  <a href="README.fr.md">Français</a> ·
  <a href="README.de.md">Deutsch</a>
</p>

<p align="center">
  <img src="docs/logo.png" alt="InfraFence" width="200">
</p>

<h3 align="center">Server security that installs in 30 seconds</h3>

<p align="center">
  Lightweight Go agent for Linux servers that detects attacks in real time and blocks them automatically — inbound and outbound.<br>
  SSH brute force, web attacks, bots, malware, DNS and outbound threats, file integrity, Docker — with safe defaults, managed from one dashboard.
</p>

<p align="center">
  <a href="https://github.com/infrafence/infrafence-agent/releases"><img src="https://img.shields.io/github/v/release/infrafence/infrafence-agent?label=version&color=brightgreen" alt="Version"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://go.dev"><img src="https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white" alt="Go"></a>
  <a href="https://github.com/infrafence/infrafence-agent"><img src="https://img.shields.io/badge/Platform-Linux-orange?logo=linux&logoColor=white" alt="Platform"></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/infrafence/infrafence-agent"><img src="https://api.securityscorecards.dev/projects/github.com/infrafence/infrafence-agent/badge" alt="OpenSSF Scorecard"></a>
</p>

<p align="center">
  <a href="https://infrafence.com">Website</a> ·
  <a href="https://infrafence.com/pricing">Pricing</a> ·
  <a href="CHANGELOG.md">Changelog</a> ·
  <a href="https://github.com/infrafence/infrafence-agent/issues">Issues</a>
</p>

---

## The problem

Spin up a fresh Linux VPS and the clock starts immediately — automated bots are scanning it, brute-forcing SSH, and probing for exploits within minutes, often before you've even finished the initial setup.

Most of that activity goes unnoticed. Nobody's watching the logs as it happens.

Classic tools react to log lines one server at a time and show you little of what happened. Full security suites give you visibility and automation, but take real effort to set up and cost more per server.

InfraFence sits in between: **install with one command, watch everything live from a dashboard, and let it block automatically — for €9/server**.

## Quick start

Create an install token in the dashboard (Servers → Add server), then on the server, as root:

```bash
curl -fsSL https://github.com/infrafence/infrafence-agent/releases/latest/download/install.sh | sudo bash -s -- --token <YOUR_TOKEN>
```

Want to see what it would do first? Add `--dry-run`: it downloads the agent, checks the server read-only, prints the plan and changes nothing.

> **[Get your token at infrafence.com](https://infrafence.com)** — the free plan includes 1 server with full protection.

---

## What it detects

### SSH & brute force
15 detection patterns in the SSH log: failed passwords, invalid users, PAM failures, pre-auth scanning, protocol mismatches, key-exchange drops. Attackers are banned at the firewall for escalating durations — 24 hours, 7 days, 30 days, then permanent — or for the duration you choose in the dashboard.

### Web Application Firewall
Reads your web servers' access logs and scores every visitor IP:

| Attack type | Score | Mode |
|---|:---:|---|
| RCE / Web shell / Shellshock | +50 | Score-based |
| Scanner UA (sqlmap, nikto, nmap, nuclei…) | +50 | Score-based |
| SQL injection / SSRF / Web exploit | +40 | Score-based |
| Honeypot trap (decoy paths you define as custom rules) | +40 | Score-based |
| Path traversal / Header injection | +30 | Score-based |
| WordPress brute force | +30 | Threshold (10 req / 2 min) |
| XSS / `.env` probe / XMLRPC | +25 | Score-based |
| Config probing | +20 | Score-based |
| 404 flood | +15 | Threshold (15 req / 5 min) |

Scores decay by 5 points per minute. Action levels: **observe** (30) → **slow down** (60) → **block** (80) → **firewall ban** (100). From the dashboard you can see every built-in rule, change weights, thresholds and per-type mode, turn off single patterns, and add your own rules (URL, User-Agent or Referer, plain text or regex). Each release publishes the built-in catalog as `waf-catalog.json`.

### Bot management
About 1,500 bots recognized from public lists updated daily ([crawler-user-agents](https://github.com/monperrus/crawler-user-agents), [ai.robots.txt](https://github.com/ai-robots-txt/ai.robots.txt), both MIT) — search engines, AI crawlers, SEO tools, scanners, monitoring, link previews and more. Fake search-engine bots are unmasked through reverse DNS. For each category, or each single bot, you choose in the dashboard: **allow**, **log only** or **block**. Blocked bots are banned at the firewall; if you allow web server changes, they are also refused by nginx/Apache.

### Malware scanner
- **Signature scanning** — 28 built-in patterns for web shells, backdoors, crypto miners and phishing kits
- **YARA engine** — web-relevant community rules from [YARA Forge](https://github.com/YARAHQ/yara-forge), refreshed daily, only from sources whose license allows commercial use (signature-base, ReversingLabs). Needs the `yara` tool, installable with one click from the dashboard
- **Every finding** explains why it matched, its severity and the file's SHA-256, with links to check it on public malware databases
- **Framework detection** — WordPress, Laravel, Django, Symfony, CakePHP, CodeIgniter, Node/Express, Rails, Joomla, Drupal
- **Framework security checks** — `.env` exposure, DEBUG mode, APP_KEY, loose permissions, Telescope, wp-config
- **Heuristics** — Shannon entropy detection, timestamp anomalies in upload directories
- **System integrity** — modified system binaries (`dpkg -V` / `rpm -Va`), rootkit indicators
- **Credential scan** — exposed `.env` files, SSH key permissions, `.git` in the web root, cloud credentials
- **WordPress database scan** — injected scripts in posts and options, rogue admin users
- **Process detection** — running crypto miners, reverse shells, suspicious scripts from `/tmp`
- **Quarantine and ignore** — one click moves a malicious file to `/var/lib/infrafence/quarantine/` (restorable) or marks a false positive so future scans skip it
- **Scheduled scans** every 3, 6, 12 or 24 hours, plus "Scan now" from the dashboard
- **Real-time watcher** — checks upload directories every 30 seconds for new PHP files

### ModSecurity inline WAF (optional)
- Only when you allow web server changes in the dashboard settings — off by default
- Never on servers whose configuration is managed by a hosting panel or a configuration-management tool
- For Apache with mod_security2: 13 rules (SQL injection, XSS, RCE, SSRF, path traversal, Shellshock, Log4Shell, Spring4Shell, scanner blocking), blocking on the first request
- Safe: if Apache's configuration test fails, the change is rolled back

### Outbound and DNS threat detection
- **Outbound connections** to IPs on public threat-intelligence lists, downloaded by each server once a day (known-hijacked netblocks, the Emerging Threats compromised-hosts list)
- **DNS inspection** — every DNS query and answer is read at packet level (UDP 53, read-only, with a filter run in the kernel) and tied to the program that made it: queries to unexpected or malicious DNS servers, domains resolving to known malicious IPs, DNS tunnels, and malware generating random domains (DGA)
- The server's own DNS service and antivirus or anti-spam lookups are recognized and not reported
- Inbound blocking of the listed networks is off by default and can be turned on in the dashboard (needs `ipset`)

### File integrity & persistence monitoring
SHA-256 baselines with an alert on every change:
- Core system files — `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/sudoers` (+ `sudoers.d/*`), `/etc/ssh/sshd_config`, `/etc/hosts`, `/etc/resolv.conf`
- Scheduled tasks — `/etc/crontab`, `/etc/cron.d/*`, per-user crontabs
- SSH persistence — `authorized_keys` for root and every user under `/home/*`
- `/etc/ld.so.preload` and systemd units (`/etc/systemd/system/*.service`, `*.timer`)

### SSH session risk scoring
Tracks every SSH session end-to-end — auth method, source IP reputation, login hour, privileged commands (`sudo`, `useradd`, `passwd`, `crontab`, `su`) — and scores it 0-100 on close. **Sigma correlation**: if another detector (WAF, integrity, malware, port scan, egress, DNS) fires while a session is open, that session's risk score jumps.

### And more
- **Mail, database and FTP** — brute force detection for Postfix, Dovecot, MySQL, PostgreSQL, MongoDB, Pure-FTPd, ProFTPD and vsftpd
- **Docker-aware** — finds web containers' logs and protects published container ports (`DOCKER-USER`)
- **Country blocking** from the dashboard (needs `ipset`)
- **Hosting panels recognized** (24, e.g. cPanel/WHM, Plesk, DirectAdmin, CyberPanel, HestiaCP, Coolify, Easypanel) and **LiteSpeed / OpenLiteSpeed** — InfraFence never edits a configuration a panel or LiteSpeed manages
- **Monitor mode** — detect everything, block nothing
- **System metrics** — CPU, memory, disk and network

---

## Safe on production servers

- **Checks before it changes** — `infrafence-agent preflight` is a read-only scan of the server (firewall and other security tools, web servers, hosting panels, configuration management, package operations, resources). The installer runs it before changing anything; the agent runs it at start and daily.
- **Conservative defaults** — web server changes and inbound threat-list blocking are off until you turn them on; auto-updates can be set to notify-only.
- **Dedicated firewall chains** — every rule lives in the agent's own `INFRAFENCE` chains, jumped to from `INPUT` (and `DOCKER-USER`), rebuilt atomically and repaired automatically within a minute if another tool (ufw, firewalld, CSF) removes them. Your existing rules are never modified. Whitelisted IPs are exempted, never opened.
- **Clean uninstall** — removes the agent and everything it added: firewall chains, web server changes, the service.

---

## How it works

```
SSH, web, mail, database and FTP logs · DNS packets · connections · files
    │
    ▼
Detectors (per log line, per packet, periodic scans)
    │
    ▼
Per-IP scoring (web) / thresholds (SSH, mail, DB, FTP)
    │
    ▼
Ban → ipset "infrafence-bans" in the INFRAFENCE chain
      (without ipset: one rule per IP in the chain, up to 500)
    │
    └──► event and ban reported to the dashboard (HTTPS)

Dashboard changes (settings, bans, whitelist, rules, scans)
    └──► pushed to the agent in about a second (real-time channel),
         checked on every heartbeat (60 s), full sync every 5 minutes
```

The agent **never bans** reserved or private IPs, the server's own addresses, the dashboard's address, or whitelisted IPs — even if it's asked to.

---

## Install

### Linux

```bash
curl -fsSL https://github.com/infrafence/infrafence-agent/releases/latest/download/install.sh | sudo bash -s -- --token <YOUR_TOKEN>
```

| Option | Effect |
|---|---|
| `--dry-run` | Check the server and print the plan; change nothing |
| `--no-ipset` | Don't install `ipset` (bans still work, up to 500; country and threat-list blocking need it) |
| `--uninstall` | Remove the agent and everything it added |

**Requires:** x86-64 or ARM64, root access, `iptables`; systemd, upstart or sysvinit. The installer uses `apt`, `dnf` or `yum` for missing dependencies and installs `ipset` only when the server check says it's safe.

**Tested so far:** Ubuntu 24.04 (in production) and Debian 12 (installer and firewall, on both iptables backends, with and without ipset). Other RHEL- and Debian-family distributions are expected to work but aren't verified yet — see [Not available yet](#not-available-yet).

### Docker

```bash
docker run -d --name infrafence-agent --restart unless-stopped \
  --privileged --network host --pid host \
  -v /var/log:/var/log:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v infrafence-config:/etc/infrafence \
  -e INFRAFENCE_TOKEN=<YOUR_TOKEN> \
  ghcr.io/infrafence/infrafence-agent:latest
```

Multi-arch image (amd64 + arm64) published with every release. A Docker Swarm stack is in [docker-compose.swarm.yml](docker-compose.swarm.yml).

### Uninstall

```bash
curl -fsSL https://github.com/infrafence/infrafence-agent/releases/latest/download/install.sh | sudo bash -s -- --uninstall
```

---

## Configuration

Almost everything is configured from the dashboard and reaches the servers in about a second: brute-force thresholds, ban duration, monitor mode, WAF rules, bot choices, whitelist, blocked countries, malware scan schedule, DNS inspection, web server changes, threat-list blocking, auto-updates.

On the server:

| Environment variable | Effect |
|---|---|
| `AUTH_LOG_PATH` | SSH log to read (default: `/var/log/auth.log` or `/var/log/secure`) |
| `WEB_LOG_PATH` | Web access logs, comma-separated (default: auto-detected from nginx, Apache, LiteSpeed, panels, Docker) |
| `MAIL_LOG_PATH`, `DB_LOG_PATH`, `FTP_LOG_PATH` | Override the detected mail, database and FTP logs |
| `MODSEC_AUDIT_LOG` | ModSecurity audit log |
| `GEOIP_DB_PATH` | GeoIP country database |
| `INFRAFENCE_CONFIG` | Agent config file (default `/etc/infrafence/config.json`) |

Set them with `sudo systemctl edit infrafence-agent` (`[Service]` → `Environment=...`), then restart the service.

**Docker labels** on your containers: `infrafence.monitor` (`true`/`false`), `infrafence.log-path` (host paths), `infrafence.domain` (domains).

**Commands:** `infrafence-agent preflight [--json]` (read-only server check), `infrafence-agent check`, `infrafence-agent uninstall --clean`.

---

## Not available yet

Honest list of what isn't there today:

- **Kubernetes** — the Helm chart and DaemonSet exist, but the dashboard can't register cluster agents yet
- **Ban propagation** — a ban applies to the server that detected it, not yet to all your servers
- **Hardening checks and CVE scanning** — the code is in the agent, but the dashboard can't start them yet
- **Security score** (0-100) — computed by the agent, not yet shown in the dashboard
- **SSH detection patterns per server** from the dashboard
- **ModSecurity IP bans** synced from the dashboard
- **Logs only in journald** — SSH detection needs `/var/log/auth.log` or `/var/log/secure`; servers without rsyslog (Debian 12+ minimal, Fedora) aren't covered yet
- **More distributions verified** (Rocky, AlmaLinux, CentOS Stream, Fedora, Amazon Linux)

These are being worked on; the [changelog](CHANGELOG.md) says when they land.

---

## Architecture

```
┌──────────────────────────────────────────────┐
│              InfraFence dashboard             │
│   web app + API · Postgres · real-time push   │
└───────────────────────┬──────────────────────┘
                        │ HTTPS (agent → dashboard)
                        │ real-time channel (dashboard → agent)
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
   ┌─────────┐    ┌─────────┐    ┌─────────┐
   │  Agent  │    │  Agent  │    │  Agent  │
   │  (VPS)  │    │ (Docker)│    │  (...)  │
   └─────────┘    └─────────┘    └─────────┘
```

The agent is a single static Go binary (~9 MB, no dependencies), running as a systemd (or upstart/sysvinit) service or a Docker container. On the demo server it uses about 25 MB of memory and under 1% CPU.

---

## Security & trust

| | Detail |
|---|---|
| **Open source** | The agent is MIT licensed. Audit every line before installing. |
| **What it reads** | System and web server logs, website files for the malware scan (including `.env` and configuration files), WordPress posts and users for the WordPress scan, and the server's DNS traffic and network connections. |
| **What it sends** | Security events only: attacker IP, type, time and the details needed to understand them — for a web attack the single log line that triggered it, for malware the file path and the matched text. Full logs and files never leave your server. No telemetry, no third-party sharing. |
| **Firewall** | Its own `INFRAFENCE` chains; your existing rules are never modified. |
| **Signed binaries** | Every release is built by GitHub Actions with [Cosign](https://github.com/sigstore/cosign) signatures and [build provenance attestation](https://github.com/infrafence/infrafence-agent/attestations). |
| **Clean uninstall** | `install.sh --uninstall` removes the agent and everything it added. |

Details in [SECURITY.md](SECURITY.md).

---

## Contributing

Contributions are welcome. Please [open an issue](https://github.com/infrafence/infrafence-agent/issues) before large changes.

```bash
go build -o infrafence-agent ./cmd/infrafence-agent
go test ./...
bash scripts/firewall-integration.sh   # real firewall tests in Docker
```

## License

[MIT](LICENSE)

<p align="center">
  <a href="https://infrafence.com">infrafence.com</a>
</p>
