# Changelog

All notable changes to the InfraFence Agent.

## v1.0.15
- **feat: threat intelligence and bot fingerprints downloaded on each server, daily.** Egress/DNS threat matching and bot fingerprinting relied on lists the dashboard never sent, so they could not fire. Each server now downloads public lists directly from their publishers once a day (cached across restarts): known-hijacked netblocks (~1,800), the Emerging Threats compromised-hosts list (~670), and ~1,580 bot user-agent fingerprints (crawler-user-agents and ai.robots.txt, MIT). The threat lists always feed egress/DNS detection; inbound blocking uses a single ipset (only when ipset is installed and not in monitor mode) and never covers reserved, local, protected or whitelisted IPs, or anything broader than /8. Known crawlers are allowed (FCrDNS-verified where possible); AI crawlers, scanners, HTTP libraries and browser automation are logged. Bot matching uses a literal-prefix index (~70µs per request instead of ~3ms) and emits at most one event per IP and bot per hour.
- **feat: built-in WAF rule catalog.** Each release now publishes `waf-catalog.json` (every built-in pattern with a stable ID, threshold rules, score points, action levels), which the dashboard's WAF page reads. `waf_config.disabled_patterns` turns off individual built-in patterns, e.g. for a false positive.
- **fix: SSH brute force never showed up as an event outside monitor mode.** The SSH watcher only banned; the attack reached the bans table but not the event stream. It now emits a `brute_force` event alongside the ban.
- **docs:** READMEs no longer name third-party feed providers; the "50+ decoy endpoints" honeypot didn't exist (honeypots are custom WAF rules now).

## v1.0.14
- **feat: real YARA rules, refreshed daily.** YARA was installed on servers but never scanned anything: rules only came from the dashboard, which never sent any. The agent now checks the latest [YARA Forge](https://github.com/YARAHQ/yara-forge) release daily (hourly while none is installed) and keeps only web-relevant rules from sources whose license allows commercial use, verified against each repo's LICENSE: signature-base (Detection Rule License 1.1) and ReversingLabs (MIT). ~920 rules today. A new set is installed only if `yara` compiles it; otherwise the previous one stays. Reports `yara_rules_updated`.
- **feat: richer findings.** YARA matches now carry the rule's description, author (required by DRL 1.1 wherever a match is reported), reference, source, license, a severity derived from the rule's score, the matched text and its line number. Every finding now includes the file's SHA-256.
- **fix: quarantine could move any file on the server.** Requests from the dashboard were executed as root with no path check. The agent now refuses anything but a regular file inside a detected web root, resolved through symlinks.
- **fix: the AniShell signature never matched.** Its pattern was declared as a literal, so the scanner searched for the text `AniShell|Ani-Shell` including the pipe. A new test fails if any literal signature contains regex syntax.
- **docs:** README claims corrected — there were no "229 YARA rules", and the "64,000 MalwareBazaar hashes" lookup was a stub.

## v1.0.13
- **fix: a YARA install request stayed pending forever if YARA was already installed.** The sync handler only acted on the dashboard's install request when YARA was missing; otherwise it skipped it without reporting anything, so the request flag (cleared when the agent reports `yara_installed`) was never cleared. The agent now acknowledges the request with `yara_installed` (`status: already_installed`).

## v1.0.12
- **feat: malware scans can now run on an interval (every 3, 6, 12 or 24 hours).** The scheduler is a plain interval ticker driven by `interval_hours` in the dashboard's malware scan config, replacing the daily/weekly-at-HH:MM model, which no dashboard could ever actually configure. The first scheduled scan fires one full interval after the schedule is enabled; the dashboard's per-server "Scan now" button covers wanting a result immediately (already supported by the sync loop).
- **fix: agents that registered before the server offered real-time push never picked it up.** The Reverb websocket URL was only read during first registration, so those agents stayed on heartbeat/sync polling until someone re-registered manually. The heartbeat response can now carry it: when the agent has no websocket connection and the server starts reporting one, it saves it to its config and connects without a restart.

## v1.0.11
- **fix: Helm chart never got a new version, so Artifact Hub stopped picking up updates.** The release workflow bumped `appVersion` in `Chart.yaml` on every release but never `version` — and `version` is the OCI tag Helm charts get published under, so every release silently overwrote the same "0.6.0" tag with different content underneath. Confirmed on Artifact Hub: its security scanner kept running normally, but its version tracker had been stuck for days, since (from its point of view) there was never a new version to index. `version` now tracks the release tag exactly like `appVersion` already did, so every release is a genuinely new, unique chart version.
- **cleanup: removed a stray, fully orphaned `charts/charts/infrafence-agent/` directory** — a duplicate, unrelated-to-the-real-one chart nested a level too deep, referenced by no workflow or Chart.yaml dependency, just confusing dead weight sitting in the repo.

## v1.0.10
- **fix: dashboard "Uptime" reset on every agent update.** It was computed from the agent process's own start time, so any routine agent restart (an update, a crash-restart, a manual `systemctl restart`) reset it to zero — reported live as confusing since it happens frequently and made the field look broken. Now reads the server's real OS uptime from `/proc/uptime`, independent of the agent process's own lifetime — only a genuine server reboot resets it, matching what "Uptime" means on an operations dashboard.

## v1.0.9
- **diagnostics: WAF score/event decisions and event-reporting failures are now logged.** Investigating a live report of WAF test requests (clear SQLi/XSS payloads, correctly reaching nginx and matching the built-in patterns by inspection) never showing up as events in the dashboard — the code path looked correct end to end but had zero visibility into where it was actually going wrong. `addScore` now logs every scored match and whether it crossed the observe threshold to report an event; the webwatcher's event-reporting callback now logs `ReportEvents` failures instead of silently swallowing them (every other callback already did this — this one was the exception). No behavior change, purely for diagnosing this live.

## v1.0.8
- **cleanup: `go vet ./...` now passes clean across the whole module.** Two pre-existing issues surfaced while testing: `internal/scanner/scanner.go`'s `isPortOpen` built its address with `fmt.Sprintf("%s:%d", host, port)`, which breaks on IPv6 hosts — now uses `net.JoinHostPort`. `internal/malware/wp_database.go`'s `queryForMalware` had a leftover `append([]string{...})` call with nothing actually appended (its result was immediately discarded by the next line, which rebuilt the full arg list by hand) — rewritten to build the mysql args in one straight line without the dead step. Both are behavior-preserving; no functional change.

## v1.0.7
- **fix: the agent could ban its own public IP.** Reproduced live during testing: SSHing into a server from a shell already on that same server (targeting its own public IP) can get logged by sshd with the source IP being the server's own public address — depending on the provider's routing, this doesn't always land on a directly interface-bound address, so `collectLocalIPs()`'s self-protection (which only enumerates local network interfaces) didn't recognize it as "self" and banned the server's own IP after 5 failed attempts. The agent now also explicitly protects its own detected outbound IP (the same one it reports in `agents.ip_address`), the same mechanism already used to protect the InfraFence API server's IP.

## v1.0.6
- **fix: re-running the installer to update an already-running agent never actually restarted it.** Confirmed live on a real server after the v1.0.5 fix: the binary on disk was replaced correctly, but `install_service` called `systemctl start` (and the equivalent for Upstart/SysVinit), which is a no-op on a unit that's already active — the old process kept running in memory, unchanged, indefinitely. All three init systems now force an actual restart (`systemctl restart`, stop-then-start for Upstart, the init script's own `restart` case for SysVinit), so re-running the one-liner now genuinely takes effect.

## v1.0.5
- **fix: the documented one-liner still required `--token` when updating an already-registered server.** The v1.0.4 fix stopped the re-register prompt from hanging the script, but the token requirement check ran before that logic and didn't know about it — so re-running the exact same install command to pick up a new release (with no `--token`, since install tokens are single-use and typically long gone by then) still failed immediately with "Install token is required," before ever reaching the code that would have skipped registration anyway. The token is now only required for a genuinely new registration (no existing config, or `--force-register`).

## v1.0.4
- **fix: install.sh could hang (again) when re-running on an already-registered server.** The "Existing config found — re-register?" prompt used a plain `read`, which reads from the piped script itself (not the operator's keyboard) in the documented `curl | sudo bash` flow — with `set -e` active, the failed read killed the script silently right after printing the warning, with the binary already updated but the service never restarted. The prompt is gone: re-running now always keeps the existing registration, updates the binary, and restarts the service, with a new `--force-register` flag for the rare case you actually want to re-register.

## v1.0.3
- **fix: heartbeat never reported listening ports or agent runtime stats.** `DetectListeningServices()` and the whole `RuntimeStats` payload (uptime, goroutine count, heap, RSS, event queue depth/drops) were fully implemented but never actually called from the heartbeat loop — the dashboard always showed "0 porte" and a blank uptime regardless of what was really running. Both are now populated on every heartbeat.
- **fix: websocket client retried forever with a noisy dial error when the server has no Reverb URL.** Some backends intentionally never implement the Reverb push channel (the agent works fine without it via heartbeat/sync). The agent now skips starting the websocket client entirely in that case instead of logging a reconnect failure every 30s.

## v1.0.2
- **fix: install.sh could hang waiting for input on a real interactive install.** The v1.0.1 fix made the server-URL prompt actually work when a real terminal is attached (reading from `/dev/tty`) — but that meant it now *always* paused to ask, even though a sensible default exists, which contradicts "one command, zero configuration" and was caught immediately on the next real-server test (an operator running the documented one-liner over SSH has a real tty, so it always paused). Removed the interactive prompt entirely: `INFRAFENCE_SERVER_URL` / `INFRAFENCE_AGENT_NAME` env vars still override, otherwise it silently uses the default — never waits for input.

## v1.0.1
- **fix: `install.sh` failed with "Server URL is required" on every real install.** Found during the first real-server test: the documented one-liner (`curl ... | sudo bash -s -- --token <TOKEN>`, no env var) tried to interactively prompt for the server URL, but `read` was reading from stdin — which is the piped script itself when run via `curl | bash`, not the operator's keyboard — so the prompt got nothing and the install aborted immediately. `server_url` now defaults to `https://infrafence.com` (matching the pattern already used elsewhere in the script), and the interactive prompt (still available for custom/self-hosted servers) now reads from `/dev/tty` so it actually works when a real terminal is attached.

## v1.0.0
- **First official InfraFence release.** This agent was forked and fully rebranded from an MIT-licensed upstream codebase (previously versioned up to v1.4.57 under its original name). Version numbering restarts at 1.0.0 for the InfraFence project — entries below this line predate the rebrand and describe the codebase under its original name.
- **Sigma correlation wired up** — cross-detector session risk scoring (WAF, integrity, malware, port scan, egress, DNS signals now credit open SSH sessions with a correlated risk hit; previously a synced config field with no effect).
- **Egress & DNS threat detection** — outbound connections and DNS resolvers are now checked against the same threat feed used for inbound bans, catching an already-compromised host beaconing out.
- **Extended persistence monitoring** — file integrity baseline now also covers `/etc/ld.so.preload`, per-user crontabs, and systemd `.service`/`.timer` units.
- **Release signing** — binaries, container images, and the Helm chart are now signed with InfraFence's own Cosign and GPG keys.

## v1.4.51
- **fix: false positive CORE_FILE_MODIFIED on wp-includes/version.php** — this file changes on every WordPress update and is not a useful injection target. Now excluded from core file integrity checks.

## v1.4.50
- **fix: false positive PHP in uploads** — standard anti-directory-listing `index.php` files (< 120 bytes, "Silence is golden") in `wp-content/uploads/` subdirectories are now skipped by the framework checker. Affects plugins like Astra, Elementor, MainWP, iThemes Security.

## v1.4.49
- **feat: cancel malware scan from dashboard** — new WebSocket event `malware_scan.cancelled` stops the scan between root iterations. Reports partial results before exiting.

## v1.4.48
- **fix: MariaDB deprecation warning causing false positive malware findings** — `CombinedOutput()` mixed stderr warnings ("Deprecated program name") into query results, triggering `WP_DB_INJECTED_POST`, `WP_DB_INJECTED_OPTION`, and `WP_DB_ROGUE_ADMIN` on every WordPress site using MariaDB. Now uses `Output()` (stdout only) and filters any remaining warning lines.
- **fix: false positive HEURISTIC_RECENT_PHP on plugin index.php files** — standard anti-directory-listing files (`<?php // Silence is golden`) in plugin asset directories are now skipped.

## v1.4.47
- **fix: custom scan paths ending in `/` were silently ignored** — a trailing separator makes `filepath.Glob` return zero matches *and* a nil error, so a path like `/home/*/web/*/public_html/` never got scanned and never reported an error. Patterns are now trimmed before matching, and blank entries are skipped instead of resolving to `.` or `/` (which made the scanner walk the whole filesystem).
- **HestiaCP / VestaCP support** — `/home/*/web/*/public_html` is now detected automatically, no custom path needed. The vhost directory is the domain, so each web root is reported with its domain.
- **fix: stop tailing bandwidth accounting logs** — HestiaCP/VestaCP write a second `CustomLog <domain>.bytes` per vhost holding byte counters, not HTTP requests. These are now skipped, removing roughly 40% of watched log sources on those servers.

## v1.4.25
- **fix: iptables rule ordering** — geo DROP rules now use -A (append) instead of -I (insert first), ensuring ACCEPT rules for panel IP and whitelisted IPs always take precedence

## v1.4.24
- **fix: geoblocking never blocks panel IP** — resolves InfraFence panel URL to IP and inserts iptables ACCEPT rule before any geo DROP rules. Also protects all whitelisted IPs from geoblocking.

## v1.4.23
- **fix: WAF disable toggle** — empty `enabled_types` array from panel now correctly disables WAF detection (previously treated as "use all defaults")

## v1.4.22
- **ipset for ALL bans** — BanIP/UnbanIP use `infrafence-bans` hash:ip set (65K capacity)
- Eliminates iptables "Memory allocation problem" — from 1,200+ rules to 3
- Batch `ipset restore` for ApplyBans (sub-second for 1,000+ IPs)
- CleanupStaleBans works with ipset members

## v1.4.21
- **Proactive country geoblocking** — ipset hash:net with full CIDR ranges from MaxMind mmdb
- Blocks ALL traffic from a country at kernel level (not reactive per-IP anymore)
- One ipset set per country, batch-loaded via `ipset restore` (sub-second)
- CIDR extraction cached after first call per country
- IPv4 only filter (ipset hash:net doesn't support IPv6)
- Graceful fallback to reactive blocking if ipset not installed
- Added `firewall.Init()`, `FirewallStatus()`, ipset detection

## v1.2.0
- **ModSecurity inline WAF** — auto-detects Apache + mod_security2, writes 14 static rules (SQLi, XSS, RCE, SSRF, Shellshock, Log4Shell, Spring4Shell), configures Include + graceful reload. Blocks on first request. Zero impact without ModSecurity.
- Reports `modsec_active` in heartbeat

## v1.1.5
- **YARA install from dashboard** — "Install YARA" button auto-detects apt/dnf/yum/apk
- Reports `yara_installed` in heartbeat

## v1.1.4
- **YARA engine** — uses yara CLI if installed, 229 web rules from LMD synced from backend, cached locally

## v1.1.3
- Cap dynamic signatures at 200 to prevent scan stall on large servers
- Disabled LMD HEX regex patterns (need native YARA for performance)

## v1.1.2
- Removed UPLOAD_SHELL_PNG (too many FPs), skip WP <5.0 checksums, core file cap at 10

## v1.1.1
- Cap CORE_FILE_MODIFIED at 10 in scanner walk

## v1.1.0
- **Phase 3 complete** — WP database scanning, malicious process detection, quarantine, security posture score (0-100, A-F grade)

## v1.0.8
- Disabled exe/cmdline mismatch rootkit check (too many FPs on production servers)

## v1.0.7
- Fix rootkit exe/cmdline FPs (cron, php-fpm, redis, postgres, case-insensitive)
- Fix hash lookup empty JSON response

## v1.0.6
- Fix rootkit exe/cmdline FPs (python, busybox, interpreters)

## v1.0.5
- **Credential scan** — .env exposure, SSH key permissions, .git in web root, cloud credentials

## v1.0.4
- Malware scanner fully opt-in — nothing runs until user enables from dashboard

## v1.0.3
- **Phase 2 complete** — entropy analysis, timestamp anomalies, realtime watcher, system integrity (dpkg -V/rpm -Va), rootkit checks

## v1.0.2
- **Hash matching** — 64K+ hashes from MalwareBazaar + LMD, lookup via backend API

## v1.0.1
- **Dynamic signatures** — admin panel management, synced to agents via /sync

## v1.0.0
- **Scheduled malware scans** — configurable frequency/time/intensity from dashboard
- Allowlist sync from backend for user-ignored findings

## v0.9.99
- **Symfony, CakePHP, CodeIgniter** detection and security checks

## v0.9.98
- Framework checks FP prevention — production-only debug checks, line-level parsing

## v0.9.97
- Signature test suite — FP and detection tests for all signatures
- Fixed patterns with | (OR) using IsRegex
- Reduced FPs: MINER_GENERIC PHPOnly, narrowed PHISH_PAYPAL, FilesMan context

## v0.9.96
- Removed OBFUSC_HEX_DECODE and OBFUSC_LONG_BASE64 (getID3, theme configs FPs)
- Cap modified core files at 20

## v0.9.95
- **3-layer FP prevention** — WP core checksums, context-based severity, user allowlist with herd immunity

## v0.9.94
- Reduced malware signatures from 40 to 26 (removed TimThumb, preg_replace, iframe, PHPMailer FPs)
- PHPOnly flag, minified file skip, expanded exclusion dirs

## v0.9.93
- **Malware scanner Phase 1** — 40 signatures, framework detection (10 frameworks), framework security checks, dashboard tab with scan history

## v0.9.92
- **Malware scanner foundation** — scan engine, web root detection, signature matching

## v0.9.90
- Fix: auto-discover ingress logs from `/var/log/pods/` using pod UID

## v0.9.89
- Fix: entrypoint version detection + API URL for K8s registration

## v0.9.88
- Fix: entrypoint curl JSON payload on Alpine — single-line to avoid bad argument error

## v0.9.87
- **K8s API key registration** — multi-use Organization API Key for DaemonSet deployments

## v0.9.86
- Fix: remove `docker.sock` mount from Helm DaemonSet (fails on containerd-only K8s)

## v0.9.85
- **K8s ingress-level firewall** — ConfigMap deny list for nginx-ingress controller

## v0.9.84
- Signed releases with SLSA provenance
- Helm chart bumped to 0.3.0

## v0.9.83
- **Kubernetes Level 5** — K8s API integration, containerd log adapter, request counter
- K8s-aware Docker image with dual binary release (bare metal + K8s)

## v0.9.82
- **FTP brute force detection** — vsftpd, ProFTPD, Pure-FTPd

## v0.9.81
- Helm chart bumped to 0.2.0 (appVersion 0.9.80, mail + DB watchers)

## v0.9.80
- **Database auth watcher** — MySQL, PostgreSQL, MongoDB brute force detection + exposed port detection

## v0.9.79
- **Mail watcher** — Postfix SASL, Dovecot IMAP/POP3, Roundcube brute force detection (11 patterns)

## v0.9.78
- Fix: let backend handle ban escalation instead of agent-side `ExpiresAt`

## v0.9.77
- Fix: geoblocking reads `blocked_countries` from sync config (was silently ignored)

## v0.9.76
- Helm chart README with OCI install instructions, Docker labels docs, values table

## v0.9.75
- Fix: install oras in Helm chart workflow for provenance attach

## v0.9.74
- `values.schema.json` for Artifact Hub validation

## v0.9.73
- Fix: add Docker login for Cosign in Helm chart CI job

## v0.9.72
- **Cosign signing** for Docker images and Helm charts

## v0.9.71
- **Security: upgrade Go from 1.22 to 1.26** — fixes 25 CVEs in stdlib

## v0.9.70 – v0.9.66
- CI: Docker Hub push fixes and repo setup

## v0.9.65
- **Docker Hub dual-push** (`infrafence/infrafence-agent`) + fix GHCR tags

## v0.9.64
- **Kubernetes Helm chart** — DaemonSet deployment + OCI chart published to GHCR

## v0.9.63
- **Docker Swarm support** — `docker-compose.swarm.yml` with `deploy: mode: global` (1 agent per node)
- Docker secrets support (`INFRAFENCE_TOKEN_FILE`) for secure multi-node deployments

## v0.9.62
- **Docker labels autoconf** — `infrafence.monitor`, `infrafence.log-path`, `infrafence.domain`, `infrafence.waf`
- Configure monitoring per container via Docker labels without agent restart

## v0.9.61
- **Docker image published to GHCR** (`ghcr.io/infrafence/infrafence-agent`) — multi-arch (amd64 + arm64)
- Auto-register via `INFRAFENCE_TOKEN` env var, docker-compose snippet included
- Automated build + push on every release tag

## v0.9.60
- **Threat feed blocking** — public threat-intelligence blocklists applied to firewall
- Pre-emptive blocking of known-bad IPs

## v0.9.59
- **Virtual patching** — dynamic WAF rules from panel (regex patterns synced via heartbeat)

## v0.9.58
- Heartbeat reports `auth_watcher_method`, `firewall_mode`, `ban_capacity`, `active_bans_count`
- Fix: enable all WAF types by default when `waf_config` is null

## v0.9.57
- Fix: web log detection for Docker containers with non-standard log paths
- Improved Apache log discovery on cPanel servers

## v0.9.56
- Agent reports all bot actions (allow/log/block) as events for dashboard visibility
- Fix: skip web server reload when UA blocklist unchanged

## v0.9.55
- **UA bot blocking at web server level** — nginx `map+include` / Apache `SetEnvIfNoCase`
- Zero app load, graceful reload on every policy change

## v0.9.54
- `bot_unknown` events for unrecognized bot User-Agents — surfaces unknown crawlers in dashboard

## v0.9.53
- **Restore ipset firewall backend** — `infrafence-bans` hash:ip set (65K capacity)
- Automatic FIFO rotation at 500 bans when ipset absent
- Migrates existing DROP rules on first run

## v0.9.52
- Skip private/reserved IPs (Docker bridge, localhost) in both SSH and WAF watchers

## v0.9.51
- Fix: deduplicate WAF scoring when same request appears in multiple log files

## v0.9.50
- **Cumulative per-IP WAF scoring engine** with configurable weights

## v0.9.49
- Fix: check WAF patterns against both raw and decoded URI to catch encoded attacks
- Private IP filter for WAF

## v0.9.48
- WAF config debug logging to confirm sync applies correctly

## v0.9.47
- Fix: connect WAF config from panel sync to web watcher — WAF detection was completely disabled

## v0.9.46
- Fix: remove duplicate `EventFunc` declaration

## v0.9.45
- User-Agent `InfraFenceAgent/{version}` header on all API calls
- Allowed bots reported as `bot_crawl` events

## v0.9.44
- **Dynamic detection rules** from panel sync — SSH patterns configurable per server from dashboard

## v0.9.43
- **Expanded SSH detection** — 15 patterns (9 auth failures + 6 pre-auth scanning)

## v0.9.42
- **Monitor mode** — detect threats without blocking; new servers default to monitor mode

## v0.9.41
- Bot fingerprint detection with pre-filter gate before WAF scoring

## v0.9.40
- Report allowed bots as events for full visibility in dashboard

## v0.9.39
- **Bot fingerprint detection** from panel sync with allow/log/block policies

## v0.9.38
- Fix: nil pointer crash in `syncAndApply` when WAF disabled and BotFingerprints non-empty

## v0.9.37
- Dynamic WAF rules synced from panel (Phase 1)

## v0.9.36
- **Regex support** for dynamic WAF rules (OWASP CRS compatible)

## v0.9.35
- **Bot management** — pre-filter gate with allow/log/block policies per fingerprint

## v0.9.34
- **Configurable score weights** per server via WAF config from dashboard

## v0.9.33
- **ipset firewall backend** (65K+ ban capacity) with iptables FIFO fallback (500 bans)
- Startup trim for existing rules exceeding capacity

## v0.9.32
- Replace malware detection with WAF bot scoring engine

## v0.9.31
- Expand malware detection with YARA-sourced signatures and multi-language support

## v0.9.30
- Report monitor scan summaries to API
- Port scan detection, SYN flood monitoring, file integrity checks

## v0.9.29
- Add `port_scan`, `flood`, `integrity_change`, `malware` detectors

## v0.9.28
- Report `auth_watcher_method` in heartbeat
- **Honeypot trap detection** (50+ decoy endpoints)

## v0.9.27
- Fix: prefer journald on RHEL-family path (`/var/log/secure`) for CloudLinux 9.7/cPanel

## v0.9.26
- **Auto-remediation** — agent can fix 12 security findings on demand from dashboard

## v0.9.25
- **Security scanner** — 30+ hardening checks (SSH, web server, file permissions, CVEs)

## v0.9.24
- **CloudLinux/cPanel support** — journald fallback, `Invalid user` pattern, domlogs detection

## v0.9.23
- Fix: associate `server_name` domains with global `access_log` in nginx multi-vhost configs

## v0.9.22
- Improved Apache detection for CentOS/RHEL — `ServerRoot` resolution, symlink following, `apachectl -S`

## v0.9.21
- Fix: web container detection matches container port (`->80/tcp`) not host port (`:80->`)

## v0.9.20
- **Docker container detection** — auto-detect Docker, container inventory, web container identification
- Stdout log reader for containers using `docker logs`
- Docker info in heartbeat (`docker_version`, `docker_containers`)
- Bind mount + volume log discovery

## v0.9.19
- Whitelisted IPs are detected (events reported) but **never banned**

## v0.9.18
- Raw access log line included in event details for attack evidence

## v0.9.17
- Fix: Apache `${APACHE_LOG_DIR}` resolution
- Monitored domains and log paths reported in heartbeat

## v0.9.16
- Instant whitelist propagation via `sync.requested` WebSocket event

## v0.9.15
- WAF disabled by default until explicitly configured from panel
- Fix: false rollback on `"signal: terminated"`

## v0.9.14
- Fix: removed `updateServiceFile()` from updater — caused regression loop on every update

## v0.9.13
- Fix: clean up partial `.rollback` staging file on copy failure
- `StartLimitIntervalSec=0` moved to `[Unit]` section

## v0.9.12
- Fix: `ExecStartPre` also restores when binary is not executable
- Improved updater diagnostics, `recent_logs` in failure event payloads

## v0.9.11
- Fix: move `StartLimitIntervalSec` to `[Unit]` and auto-patch service file on update

## v0.9.10
- Fix: prevent binary loss during failed rollback
- Health-check window extended, stale ban cleanup on sync

## v0.9.9
- Fix: prevent `start-limit-hit` during auto-updates
- Fix: cross-device rename failure in updater

## v0.9.8
- Report `waf_disabled` event to panel when no web logs found
- Preflight check uses `check` subcommand; atomic rollback

## v0.9.7
- **Docker container log detection** via bind-mounts

## v0.9.6
- **Web exploit detection** — Spring4Shell, Log4Shell, Struts OGNL, ThinkPHP RCE, Drupalgeddon2

## v0.9.5
- **Atomic binary replacement** + 15s post-restart health check; rollback on crash

## v0.9.4
- Fix: double URL-decode bypass detection
- Reduce 404 flood threshold

## v0.9.3
- **Per-server WAF configuration** — enable/disable types, detect-only mode, custom thresholds

## v0.9.2
- **XSS, SSRF, web shell, header injection** detection

## v0.9.1
- Fix: restore release workflow, LICENSE

## v0.9.0
- **Initial WAF** — SQL injection, path traversal, RCE, shellshock, `.env` probe, config probe, WordPress brute force, XMLRPC abuse, 404 flood, scanner detection

## v0.8.5
- Fix: prevent banning server's own IPs and organization sibling IPs

## v0.8.4
- Fix: prevent banning reserved IPs (loopback, private, link-local)

## v0.8.3
- Include recent service logs in update failure events

## v0.8.2
- Report update outcomes (success/failure) to server via events API

## v0.8.1
- **Robust auto-updater** with backup, preflight check, and rollback

## v0.8.0
- **System metrics collection** — CPU, memory, disk, load, network reported to dashboard

## v0.7.0
- Fix: skip systemd hardening on old kernels

## v0.6.1
- **Force update via WebSocket** command

## v0.6.0
- **Multi-vhost domain mapping** — auto-detect nginx/Apache vhosts, hot-reload every 5 min

## v0.5.2
- Maintenance release

## v0.5.1
- **Multi-log web watcher** — monitor multiple log files simultaneously
- Software version scanner, updater improvements

## v0.3.1
- Fix: support upstart and sysvinit restart in auto-updater

## v0.3.0
- **Software audit collector** and sync via API/WebSocket

## v0.2.2
- Fix: static-link binary + support upstart/sysvinit

## v0.2.1
- Fix: resolve "text file busy" error on auto-update
- Allow ldflags version injection

## v0.2.0
- **IP detection, auto-update via heartbeat, install-only mode**
- DigitalOcean Marketplace support

## v0.1.0
- Initial release — SSH brute force detection, GeoIP blocking, heartbeat, ban enforcement via iptables
