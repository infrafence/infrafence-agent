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

<h3 align="center">Stop the attack. Fix what let it in.</h3>

<p align="center">
  InfraFence blocks attacks on your Linux servers as they happen, inbound and outbound. Then it hardens, patches and checks the result, and undoes any fix that breaks something.<br>
  SSH brute force, web attacks, bots, malware, DNS and outbound threats, file integrity, Docker — with safe defaults, managed from one dashboard.
</p>

<p align="center">
  <a href="https://github.com/infrafence/infrafence-agent/releases"><img src="https://img.shields.io/github/v/release/infrafence/infrafence-agent?label=version&color=brightgreen" alt="Version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-BSL%201.1-blue.svg" alt="License: BSL 1.1"></a>
  <a href="https://go.dev"><img src="https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white" alt="Go"></a>
  <a href="https://github.com/infrafence/infrafence-agent"><img src="https://img.shields.io/badge/Platform-Linux-orange?logo=linux&logoColor=white" alt="Platform"></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/infrafence/infrafence-agent"><img src="https://api.securityscorecards.dev/projects/github.com/infrafence/infrafence-agent/badge" alt="OpenSSF Scorecard"></a>
</p>

<p align="center">
  <a href="https://infrafence.com">Website</a> ·
  <a href="https://infrafence.com/pricing">Pricing</a> ·
  <a href="https://infrafence.com/docs">Docs</a> ·
  <a href="CHANGELOG.md">Changelog</a> ·
  <a href="https://github.com/infrafence/infrafence-agent/issues">Issues</a>
</p>

---

## Why InfraFence

- **It sees what leaves the server.** It reports outbound connections to known-bad IPs and reads every DNS query at packet level, tied to the program that made it: DNS tunnels and DGA lookups arrive with a process name and pid.
- **It knows who was logged in.** Every SSH session gets a risk score from 0 to 100, which rises when the WAF, file integrity, malware, port scan, egress or DNS detectors fire while it is open.
- **Fixes that don't take production down.** After every change (closing a port, blocking outbound traffic, a hardening fix, a virtual patch) it checks SSH and the monitored sites, and undoes the change if they stop answering.
- **AI that acts only within fixed limits.** AutoMode picks from a fixed catalogue of actions, never runs commands of its own, and never blocks your own addresses or SSH logins. Actions that aren't automatic (for example closing a MySQL or PostgreSQL port that isn't under attack, some PHP fixes, a virtual patch outside the automatic rule) wait for approval in the dashboard, and only an owner or admin signed in with two-factor authentication can decide them. [What needs your approval](https://infrafence.com/docs/automode#what-needs-your-approval)

Starter is free for one server, paid plans from $8.90 per server per month: [see pricing](https://infrafence.com/pricing).

## Quick start

Create an install token in the dashboard (Servers → Add server), then on the server, as root:

```bash
curl -fsSL https://github.com/infrafence/infrafence-agent/releases/latest/download/install.sh | sudo bash -s -- --token <YOUR_TOKEN>
```

Want to see what it would do first? Add `--dry-run` (no token needed): it downloads the agent, checks the server read-only, prints the plan and changes nothing.

> **[Get your token at infrafence.com](https://infrafence.com/add-server)** — the Starter plan is free and includes 1 server with full protection.

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
- **Country blocking** from the dashboard (needs `ipset`). The agent downloads the country database from your dashboard ([DB-IP](https://db-ip.com) IP to Country Lite, CC BY 4.0) only while a country is blocked, at most once a day. The allow list, the server's own addresses and the SSH sessions logged in when a country is blocked are never blocked (a connection still trying to log in, such as a brute force, does not count). [Country blocking](https://infrafence.com/docs/country-blocking)
- **Hosting panels recognized** (24, e.g. cPanel/WHM, Plesk, DirectAdmin, CyberPanel, HestiaCP, Coolify, Easypanel) and **LiteSpeed / OpenLiteSpeed** — InfraFence never edits a configuration a panel or LiteSpeed manages
- **Monitor mode** — detect everything, block nothing
- **System metrics** — CPU, memory, disk and network

---

## Beyond detection

What InfraFence adds on top of the detectors above, each with its page in the [docs](https://infrafence.com/docs):

- **Hardening, vulnerabilities and security score** — about 40 hardening checks, with one-click fixes for the safe ones; known vulnerabilities (CVE) of the installed packages in order of real risk: exploited in the wild (CISA KEV) first, then exploit probability (EPSS); a security score from 0 to 100. The SSH checks read the configuration sshd really uses (`sshd -T`, or the files in sshd's own order) and name the file and line that set each value: a drop-in in `sshd_config.d`, such as cloud-init's `50-cloud-init.conf`, wins over `sshd_config`. The SSH fixes never edit `sshd_config`: they go in a drop-in read first and are undone if sshd still uses another value. [Hardening and vulnerabilities](https://infrafence.com/docs/hardening-cve)
- **PHP hardening** — finds risky PHP settings in every runtime and pool, and fixes the safe ones. Fixes go in a file of its own (`zz-infrafence-hardening.ini`), are tested and undone if a site stops answering; `cgi.fix_pathinfo` and `disable_functions` need approval. The agent also watches the PHP configuration and reports a risky value as soon as it appears. This is configuration hardening and watching: nothing is loaded into PHP, and it is not a protection running inside your applications. [PHP hardening](https://infrafence.com/docs/hardening-cve#php-hardening)
- **Close exposed ports, block bad destinations** (Pro · AutoMode) — each change is checked and undone if it breaks something. Egress is never blocked to an address logged in over SSH; a connection to SSH that has not logged in protects nobody. [Ports and egress blocking](https://infrafence.com/docs/ports-egress)
- **Virtual patches for exploited vulnerabilities** (Pro · AutoMode) — a targeted ModSecurity rule shields vulnerable software until you install the update; Apache with ModSecurity. [Virtual patches](https://infrafence.com/docs/virtual-patches)
- **Emergency mode** — one red button: for 24 hours InfraFence responds to the attack by itself, with the same safe catalogue and limits as AutoMode (Basic and higher). [Emergency mode](https://infrafence.com/docs/emergency-mode)
- **Alerts** by email, Slack, Discord, Telegram or webhook, plus a weekly summary email. [Alerts](https://infrafence.com/docs/alerts)
- **AI analysis** — an instant analysis of every incident on every plan, computed in the dashboard; an AI analysis with one-click safe fixes on Pro and higher. [Events and activity](https://infrafence.com/docs/events-activity)
- **InfraFence network and attack map** — optional sharing: addresses that attack several customers are flagged, and network figures are shown only where 3 or more organizations contributed. [The InfraFence network](https://infrafence.com/docs/infrafence-network) · [Attack map](https://infrafence.com/docs/attack-map)
- **Trust badge** — the “Monitored by InfraFence” badge links to a public trust page with the last check, the attacks blocked in the last 30 days and the protections active. To prove the domain is served by your server, the agent places a verification file, `/.well-known/infrafence-verification.txt`, in the site's document root, and removes it when the badge is turned off. It is not a certificate. [Trust badge](https://infrafence.com/features#trust-badge) · [See an example trust page](https://infrafence.com/trust/demo)
- **Protection when the dashboard is unreachable** — bans, the allow list and country blocks stay in force, new attacks are still banned, and events wait in a queue. [When the dashboard is unreachable](https://infrafence.com/docs/dashboard-unreachable)
- **Next to CSF and other tools** — InfraFence keeps to its own chains and never edits CSF's files or another tool's rules; after `csf -r` it puts its own rules back within seconds. [Coexistence with other security tools](https://infrafence.com/docs/coexistence)
- **cPanel & WHM plugin** (available) **and Plesk extension** (in development), included in the Basic, Pro and AutoMode plans — protection status, bans, findings, events and per-site scans inside the panel. [cPanel & WHM](https://infrafence.com/integrations/cpanel-whm) · [Hosting panels](https://infrafence.com/docs/hosting-panels) · [WHM plugin](https://infrafence.com/docs/whm-plugin)

---

## Safe on production servers

- **Checks before it changes** — `infrafence-agent preflight` is a read-only scan of the server (firewall and other security tools, web servers, hosting panels, configuration management, package operations, resources). The installer runs it before changing anything; the agent runs it at start and daily.
- **Conservative defaults** — web server changes and inbound threat-list blocking are off until you turn them on; agent updates are notify-only until you choose automatic updates, and only cosign-signed releases are installed.
- **Dedicated firewall chains** — every rule lives in the agent's own `INFRAFENCE` chains, jumped to from `INPUT` (and `DOCKER-USER`), rebuilt atomically and repaired automatically within seconds if another tool (ufw, firewalld, CSF) removes them. Your existing rules are never modified. Whitelisted IPs are exempted, never opened.
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
| `--dry-run` | Check the server and print the plan; change nothing. No token needed |
| `--no-ipset` | Don't install `ipset` (bans still work, up to 500; country and threat-list blocking need it) |
| `--skip-checksum` | **Unsafe.** Install even when the release checksum can't be downloaded (the binary is not verified). Only for a network that blocks the `.sha256` file and nothing else |
| `--uninstall` | Remove the agent and everything it added |

The agent is downloaded only from GitHub Releases, and the installer stops if the release checksum is missing or doesn't match. The Let's Encrypt root certificate it may need (ISRG Root X1) is built into the script, with a pinned fingerprint, instead of being downloaded. [What the installer does](https://infrafence.com/docs/what-the-installer-does)

**Requires:** x86-64 or ARM64, root access, `iptables`; systemd, upstart or sysvinit. The installer uses `apt`, `dnf` or `yum` for missing dependencies and installs `ipset` only when the server check says it's safe.

**Tested before every release** on 15 distributions: Ubuntu 20.04, 22.04, 24.04 and 26.04, Debian 12 and 13, Rocky Linux 8 and 9, AlmaLinux 8 and 9, CentOS Stream 9, Oracle Linux 9, Fedora 41 and 42, Amazon Linux 2023. Each one runs the real installer, detects an SSH brute-force attack, bans it at the firewall and uninstalls cleanly. Other Debian- and RHEL-family distributions usually work: run the installer with `--dry-run` first. See [Supported distributions](https://infrafence.com/docs/supported-distributions).

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

### Kubernetes

Create a cluster key in the dashboard (Settings → Kubernetes), then:

```bash
helm install infrafence-agent oci://ghcr.io/infrafence/charts/infrafence-agent \
  --namespace infrafence --create-namespace \
  --set apiKey="IFK-..." --set clusterName="production"
```

Every node registers as its own server. All the values, upgrades and GitOps: [Kubernetes](https://infrafence.com/docs/kubernetes) in the docs, and the [chart README](charts/infrafence-agent/README.md).

### Uninstall

```bash
curl -fsSL https://github.com/infrafence/infrafence-agent/releases/latest/download/install.sh | sudo bash -s -- --uninstall
```

---

## Configuration

Almost everything is configured from the dashboard and reaches the servers in about a second: brute-force thresholds, ban duration, monitor mode, WAF rules, bot choices, whitelist, blocked countries, malware scan schedule, DNS inspection, web server changes, threat-list blocking, auto-updates. Full reference: [Configuration](https://infrafence.com/docs/configuration).

On the server:

| Environment variable | Effect |
|---|---|
| `AUTH_LOG_PATH` | SSH log file to read instead of the systemd journal (default: the journal on systemd hosts, otherwise `/var/log/auth.log` or `/var/log/secure`) |
| `WEB_LOG_PATH` | Web access logs, comma-separated (default: auto-detected from nginx, Apache, LiteSpeed, panels, Docker) |
| `MAIL_LOG_PATH`, `DB_LOG_PATH`, `FTP_LOG_PATH` | Override the detected mail, database and FTP logs |
| `MODSEC_AUDIT_LOG` | ModSecurity audit log |
| `GEOIP_DB_PATH` | Country database (MaxMind DB format) to use instead of the one downloaded from the dashboard to `/etc/infrafence/geoip-country.mmdb`; when set, nothing is downloaded |
| `INFRAFENCE_CONFIG` | Agent config file (default `/etc/infrafence/config.json`) |

Set them with `sudo systemctl edit infrafence-agent` (`[Service]` → `Environment=...`), then restart the service.

**Docker labels** on your containers: `infrafence.monitor` (`true`/`false`), `infrafence.log-path` (host paths), `infrafence.domain` (domains).

**Commands:** `infrafence-agent preflight [--json]` (read-only server check), `infrafence-agent version` (installed version), `infrafence-agent check`, `infrafence-agent uninstall --clean`. All commands: [Command reference](https://infrafence.com/docs/cli).

**Hosting panels (cPanel/WHM, Plesk):** the panel plugins run `infrafence-agent panel <command> --json` as root and read one JSON object from stdout (`{"ok": true, ...}` or `{"ok": false, "error": "<code>", "message": "..."}`, exit status 0 only when ok). Commands: `status`, `bans [--limit N]`, `unban <ip>`, `allow <ip> [--note ...]`, `allowlist`, `disallow <ip>`, `findings [--limit N]`, `events [--limit N] [--since 24h]`, `coexistence`, `sites`, `scan <document root>`, `map [--hours 24|168]`, `score`; the ones that change something need `--actor <panel user>` and are reported to the dashboard as events with source `panel`. The command talks to the running agent over `/run/infrafence/panel.sock` (root only, mode 0600, no network listener); without a running agent it still answers, with `"agent_running": false`. The plugins are for the Basic, Pro and AutoMode plans (agent 1.0.34 or later): `status` always answers, with `"entitled"` and `"entitlement"` (`ok`, `plan_required`, `unpaid`, `unknown`); every other command answers only that error, with no data, when the organization is not entitled (a plan without the plugins, protection switched off after 24 hours of refusal, or a plan not known yet). The plan of the last successful sync is kept across restarts, so a dashboard outage doesn't blank the plugin. `map` (this server's attacks by country and category) and `score` (its security score and 30-day trend) come from the dashboard, need agent 1.0.33 or later, and are cached by the agent: at most one request every 5 minutes for the map and 15 minutes for the score, with `"stale": true` when the dashboard can't be reached. Every field of every reply: [docs/panel-json.md](docs/panel-json.md).

**Open or resolved:** every problem event the agent reports (an exposed database port, a changed system file, a risky PHP setting, malware...) carries `details.subject` (`port:tcp/3306`, `file:/etc/passwd`...). From 1.0.34, `panel events` and `panel findings` say whether each problem is still `open` or `resolved` (`subject`, `state`, `resolved_at`, `resolved_how`): resolved in the dashboard, or fixed by the agent itself (a port its firewall closed, a fix applied and verified, a file quarantined, a package updated). A database port the agent's firewall closes is no longer reported as exposed when the agent restarts. Details: [docs/panel-json.md](docs/panel-json.md#problems-and-resolution).

**Plugin version:** the panel plugin is updated from the dashboard (Panel plugins), not with the agent. From 1.0.35 the agent reads the installed WHM plugin's version (read only: `/usr/local/share/infrafence-whm/VERSION`, else the `infrafence-whm` package; at start and at most hourly) and sends it with the heartbeat (`panel_plugin`). `panel status` shows it as `plugin_installed`, next to `plugin_latest`, the latest release the dashboard sends in the sync, so the plugin can say when an update is available. Details: [docs/panel-json.md](docs/panel-json.md#status).

---

## Not available yet

Honest list of what isn't there today:

- **SSH detection patterns per server** from the dashboard

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
| **Source-available** | The agent is licensed under BSL 1.1: free for production use on your own and your customers' servers, fully transparent, and you can audit every line before installing. |
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

The agent is source-available under the [Business Source License 1.1](LICENSE) (licensor: ComCart S.r.l.). Production use is free on any number of servers, including your customers' servers, as long as you don't use it to build a competing product. Four years after each release, that version becomes available under the Apache License 2.0.

<p align="center">
  <a href="https://infrafence.com">infrafence.com</a>
</p>
