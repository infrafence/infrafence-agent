# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability, please report it responsibly:

1. **Do NOT open a public GitHub issue**
2. Email **info@infrafence.com** with details (the same contact as https://infrafence.com/.well-known/security.txt)
3. Include steps to reproduce if possible
4. We will respond within 48 hours

We appreciate responsible disclosure and will credit reporters (with permission) in the release notes.

---

## What the Agent Accesses

The agent runs as root: it manages the firewall, reads system logs and network state, scans website files and applies the changes you ask for. Here is the complete list of what it reads and writes.

"When" says how each access is triggered:

- **Always**: whenever the agent runs.
- **Setting**: only while the named dashboard setting is on.
- **On request**: only when someone asks for it from the dashboard, or AutoMode or the emergency mode asks on their behalf. The agent cannot tell these apart and has no automatic actions of its own.

### Reads

| Resource | Access | Purpose | When |
|---|---|---|---|
| SSH authentication log: systemd journal, `/var/log/auth.log` or `/var/log/secure` | Read | SSH brute force detection | Always |
| Same log, plus login records (`last`, wtmp) | Read | SSH session timeline and `sudo` commands; recent admin addresses, so the agent never blocks them | Session tracking: setting (off by default). Login records: always |
| Web server access logs and configuration (nginx, Apache, LiteSpeed, panel `domlogs`). In Docker, through the `docker` CLI, including `docker exec <container> nginx -T`. Any custom log path set in the dashboard | Read | Web attack and bot detection; finding logs and domains | Always |
| ModSecurity audit log | Read | ModSecurity events | Always, if present |
| Mail, database and FTP logs | Read | Brute force on those services | Only while that service is running |
| `/proc`: network tables, CPU, memory and load, per-process `comm`, `exe`, `status`, `fd`. `/etc/resolv.conf` | Read | Metrics, listening services, port scans, outbound connections and the process that owns them | Always |
| `/proc/<pid>/environ` | Read | Find open SSH sessions (only the `SSH_CONNECTION` variable is used), so their ports are never closed | Always |
| Raw packet sockets: DNS packets (UDP port 53) and TCP SYN headers | Read | DNS threats (tunnelling, malicious resolvers and answers); port scans | On by default; each can be switched off |
| Files under each detected web root and any custom scan path, including uploads, `.env`, `wp-config.php` and other framework configuration. Full scans follow symbolic links inside web roots | Read | Malware scan (signatures, YARA, heuristics), framework checks, plugin and theme inventory | Scheduled scans: setting. Also on request, or a scan started from a hosting panel plugin. While scheduled scanning is on, upload folders are checked every 30 seconds |
| WordPress database, with the credentials in `wp-config.php` | Read (`SELECT` only) | Injected posts and options, administrators created in the last 7 days | During malware scans (not panel scans) |
| Process command lines (`/proc/<pid>/cmdline`) | Read | Crypto miners, reverse shells | Full malware scans |
| Package verification (`dpkg -V`, `rpm -Va`), `/etc/ld.so.preload`, executables in `/tmp` and `/dev/shm` | Read | Modified system binaries, rootkit signs | Full malware scans |
| `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/sudoers` and `sudoers.d`, `/etc/ssh/sshd_config`, crontabs, `/etc/hosts`, `/etc/resolv.conf`, `/etc/ld.so.preload`, `authorized_keys` of root and users, systemd units in `/etc/systemd/system` | Read (SHA-256 only) | File integrity | Always, every 30 minutes |
| `sshd -T` and the sshd configuration, `/etc/passwd`, `/etc/shadow` (only to count empty password fields), permissions of `.env` and `/root/.ssh` | Read | Hardening scan | Daily, and on request |
| Installed packages and available updates | Read | Vulnerability (CVE) check | Daily, and on request |
| cPanel: `/var/cpanel/users`, `/var/cpanel/userdata`, `/etc/trueuserdomains`. Plesk: `plesk db` (`SELECT` only) and `plesk bin`. DirectAdmin: `domains.list` | Read | Sites, document roots and accounts | Only on those panels |
| `/var/run/docker.sock` | Read (`GET /version` only) | Software inventory | Only if Docker is present and its CLI is not |
| Kubernetes API (pods, nodes, events, ingresses, namespaces, network policies, two ConfigMaps) and pod log files | Read | Container and ingress monitoring | Only when running in Kubernetes |
| Existing `INPUT` firewall rules | Read | Shown in the dashboard | At start, and on request |

### Writes

| Resource | Access | Purpose | When |
|---|---|---|---|
| iptables chains `INFRAFENCE`, `INFRAFENCE-RULES`, `INFRAFENCE-PORTS`, `INFRAFENCE-EGRESS`; ip6tables chain `INFRAFENCE-PORTS`; jumps to them from `INPUT`, `OUTPUT` and `DOCKER-USER` | Read + Write | Bans, allow list, firewall rules created in the dashboard (an "allow" rule becomes `ACCEPT` in `INFRAFENCE-RULES`), closed ports, outbound blocks | Chains and jumps: always. Their content: on request, and from detections |
| ipsets `infrafence-bans`, `infrafence-allow`, `infrafence-egress`, `infrafence-threat`, `infrafence-geo-<country>` | Read + Write | Ban list, allow list, outbound blocks, threat feed and country blocking | Bans and allow list: always. Threat feeds and countries: setting (threat feeds off by default) |
| Other chains' rules | Write, rarely | At the first ban sync, removes `INPUT -s <ip> -j DROP` rules for addresses the agent itself bans (left by older versions). No other rule is ever changed | Once |
| `conntrack` | Write | Drops established public connections to a port it has just closed | On request (closing a port) |
| Closing ports, blocking outbound addresses | Write | Only a fixed list of database, cache and admin ports can be closed, never SSH or web ports. An outbound block needs an address the agent flagged in the last 24 hours. SSH and the sites are checked afterwards and the change is undone if they stop answering | On request |
| CSF: `/etc/csf/csf.conf` (`TCP_IN`, `TCP_OUT`), then `csf -r` | Write | Open or close a port in CSF | On request, only if CSF is installed |
| `/etc/modsecurity/infrafence/` and one `Include` line in the ModSecurity configuration (Apache) | Write | ModSecurity rules, bans and virtual patches | Setting: **Allow web server configuration changes**, and only where no panel or configuration manager owns the web server. Virtual patches: on request. The configuration is tested before reload and restored if the test fails |
| nginx: `/etc/nginx/conf.d/infrafence-ua-block.conf` and one marked line (`# infrafence`) in each `server` block. Apache: `infrafence-ua-block.conf` in `conf-available` or `conf.d` | Write | Blocking bots by user agent | Same setting, and only when a bot is set to "block". Tested before reload, restored if the test fails |
| `/etc/ssh/sshd_config.d/00-infrafence-hardening.conf`, `zz-infrafence-hardening.conf` for nginx or Apache | Write | Hardening fixes | On request. Checked with `sshd -t` or the web server's own test, reloaded, then SSH and the sites are checked; the previous state is restored on failure |
| Permissions of `/etc/shadow`, `/etc/passwd`, `/etc/ssh/sshd_config`, `/root/.ssh/authorized_keys` | Write (`chmod`, only removes bits) | Hardening fixes | On request |
| System packages | Write | Security updates of named packages; installing YARA (and `epel-release` on RHEL-family systems) | On request |
| Files in web roots | Write (move) | Quarantine: the file is moved to `/var/lib/infrafence/quarantine` (mode 0400) with its owner and mode recorded; restore puts it back without overwriting anything | On request, only for regular files inside a detected web root |
| `/etc/infrafence/` | Read + Write | Configuration and agent token (`config.json`, mode 0600), YARA rules, threat feed and bot list caches, GeoIP database | Always |
| `/var/lib/infrafence/` (mode 0700) | Read + Write | `protection-state.json`, `firewall-state.json`, `panel-state.json`, `unsent-events.json`, crash and recovery markers, `quarantine/` | Always |
| `/run/infrafence/panel.sock` | Read + Write | Local socket for the WHM and Plesk plugins. Directory 0700, socket 0600, and every caller must be root (checked with `SO_PEERCRED`) | Only on cPanel or Plesk servers, or with `"panel": true` in the configuration |
| `/etc/motd.d/infrafence` | Write | Login notice while protection is switched off | Only after 24 hours of refusal (see below) |
| `/usr/local/bin/infrafence-agent` (and `.bak`) | Write | Updates, only after the checksum and Cosign signature verify | Setting: automatic updates |
| `/usr/local/bin/infrafence-agent-recover.sh` and its `ExecStartPre` line in `infrafence-agent.service` | Write | Restores the previous or a verified binary if the installed one is broken | Always, on systemd hosts |

Apart from the tables above, the agent does not read or change anything on the server. In particular, it does not read private SSH keys or mailboxes, it uses nothing from other processes' environments except `SSH_CONNECTION`, and it never modifies a website file except to quarantine or restore it.

## What Data Leaves Your Server

All communication with the dashboard uses HTTPS. The agent authenticates with its own token. The real-time channel is private to the agent and carries instructions from the dashboard: bans, rules and scan requests.

**Transmitted to your dashboard:**
- At registration, once: hostname, IP, OS and version, agent version.
- Heartbeats, every 60 s:
  - agent version, outbound IP, system metrics (CPU, memory, disk, load, network);
  - listening ports and the name of the process behind each, SSH and web ports;
  - web server and version, monitored domains and log paths;
  - firewall mode and counters, CSF status, hosting panel and its domains, Kubernetes pods and nodes.
- Security events: type, severity, attacker address and ports, time, country, and details that depend on the event:
  - web attacks and bots: the single access log line that triggered the event (up to 2,000 bytes), the URL and the user agent;
  - SSH, mail, database and FTP brute force: the count and the action taken, no usernames or log lines;
  - DNS: the queried domain and the process that asked;
  - file integrity: the path and the old and new SHA-256 and size;
  - when session tracking is on: SSH logins (user, address, duration, the commands run, up to 2,000 characters) and `sudo` commands;
  - failed agent updates: the last lines of the agent's own service log;
  - security updates: the package manager's output.
- Malware findings:
  - the file path, its SHA-256, the signature or YARA rule, and the matching line or strings (up to 200 bytes);
  - for the WordPress database check: the post ID and title, the option name and the first 100 characters of its value, or the login and email of a new administrator.

  Process and system binary findings stay on the server; only the security score they feed into is sent.
- Malware hash lookup: the SHA-256 of scanned PHP files, sent to the dashboard only, without paths.
- Hardening scan results: each check's outcome and the setting values it looked at.
- Installed packages and versions, for the vulnerability check.
- The existing `INPUT` firewall rules, so they can be shown in the dashboard.
- Bans: address, reason, count and expiry.
- Hosting panel actions (unban, allow, disallow, scan): who did it, the address or path, and a note of up to 200 characters.

The agent pulls its configuration, bans, allow list, rules, signatures and requested actions from the dashboard every 5 minutes, and at once when the dashboard signals a change.

**Never transmitted:**
- Full log files (only the single lines described above)
- Whole files from your sites or system (only paths, hashes and the short excerpts described above)
- Environment variables
- Passwords and keys stored in files: database passwords from `wp-config.php` or `.env`, SSH keys, the contents of `/etc/shadow`. A secret that someone types on a `sudo` command line, or that appears in a requested URL, would be part of the command or log line sent with the event.
- Database contents beyond the WordPress fields listed above

**Direct connections from the agent to third parties** are downloads only and send nothing about your server:
- the Spamhaus DROP and Emerging Threats lists, and two public bot lists on GitHub, once a day;
- YARA Forge rules from GitHub, once a day, if YARA is installed;
- agent updates from GitHub Releases.

The one exception is the WordPress checksum lookup at `api.wordpress.org`, which sends the WordPress version being checked. No data is shared with third parties by default.

**Exception — AI incident analysis (opt-in, dashboard-only):** the dashboard offers an optional feature letting an operator submit incident details — and optionally free-text notes or log excerpts they choose to paste in — to get an AI-generated summary of likely cause, risk, and recommended actions. This is a manual action taken by a human operator in the dashboard, never something the agent does automatically. Anything submitted through it, including any text an operator chooses to paste, is sent to a third-party AI provider to generate the response. The dashboard shows this notice every time the feature is used. Nothing about the agent's own reporting changes — it still only ever transmits what is listed above.

## When the Dashboard Is Unreachable

The agent never needs the dashboard to protect the server. Detection, bans and blocks all run on the server.

**Unreachable.** Network errors, timeouts, DNS failures and server errors (5xx) are never treated as a refusal, and protection stays on for as long as the outage lasts:
- bans, the allow list, country blocks and closed ports stay in force;
- the state is kept in `/var/lib/infrafence/protection-state.json` and restored before the firewall is set up after a restart;
- events wait in a queue (up to 5,000 events and 16 MB) and are sent when the dashboard answers again.

**Refused.** The dashboard refuses an agent explicitly with a 401, or with a 403 from the dashboard itself on the heartbeat, sync, events or bans endpoint (for example, a suspended account).
1. Local protection stays in force. The agent waits before asking again, from 1 minute doubling up to 30 minutes, or every 30 minutes when the account is suspended.
2. After 24 hours of refusal without a single accepted request, the agent switches its protection off cleanly:
   - it removes its firewall chains, jumps and ipsets;
   - it removes its ModSecurity includes and user-agent blocking from the web server (the rule files stay on disk);
   - it stops the real-time malware watcher;
   - detection continues in monitor mode only.

   Other tools' rules are never touched, and SSH is checked afterwards.
3. Where the system shows `/etc/motd.d` at login, the agent writes `/etc/motd.d/infrafence`: *InfraFence no longer protects this server: the account is suspended or the subscription ended. Reactivate it at https://infrafence.com/billing*.
4. The agent keeps asking every 30 minutes. At the first accepted synchronization, protection is switched back on and the notice is removed.

The refusal clock is kept in `protection-state.json`, so a restart does not reset it.

## Binary Verification

Every release is built by [GitHub Actions CI](.github/workflows/release.yml) with full build provenance attestation. Binaries are signed with [Cosign](https://github.com/sigstore/cosign).

### Verify checksum

```bash
# Download checksum file from the release
curl -sL https://github.com/infrafence/infrafence-agent/releases/latest/download/checksums.txt

# Compare with your installed binary
sha256sum /usr/local/bin/infrafence-agent
```

### Verify Cosign signature

```bash
cosign verify-blob \
  --key https://raw.githubusercontent.com/infrafence/infrafence-agent/main/cosign.pub \
  --signature https://github.com/infrafence/infrafence-agent/releases/latest/download/infrafence-agent-linux-amd64.sig \
  /usr/local/bin/infrafence-agent
```

### Verify build provenance

```bash
gh attestation verify infrafence-agent-linux-amd64 --repo infrafence/infrafence-agent
```

### Verify the Helm chart signature

The Helm chart is signed with a dedicated GPG key (separate from the Cosign key used for binaries and container images):

```bash
curl -sL https://raw.githubusercontent.com/infrafence/infrafence-agent/main/infrafence-helm-signing-key.asc | gpg --import
helm verify infrafence-agent-<version>.tgz
```

## Uninstall

Complete removal:

```bash
curl -fsSL https://github.com/infrafence/infrafence-agent/releases/latest/download/install.sh | sudo bash -s -- --uninstall
```

Or manually:

```bash
sudo systemctl stop infrafence-agent
sudo /usr/local/bin/infrafence-agent uninstall --clean
sudo systemctl disable infrafence-agent
sudo rm /etc/systemd/system/infrafence-agent.service
sudo rm /usr/local/bin/infrafence-agent /usr/local/bin/infrafence-agent.bak /usr/local/bin/infrafence-agent-recover.sh
sudo rm -f /etc/motd.d/infrafence
sudo rm -rf /etc/infrafence/
```

`infrafence-agent uninstall --clean` removes every change the agent made to the host:
- its firewall chains, jumps and ipsets;
- its ModSecurity files and includes;
- user-agent blocking;
- the hardening drop-in files.

Some things are not undone:
- **Package updates.** Packages the agent updated or installed on request stay installed.
- **Permissions.** Permissions it tightened stay tightened.
- **CSF.** CSF port changes stay in `csf.conf`.
- **Quarantined files.** Files the agent quarantined stay in `/var/lib/infrafence/quarantine`. Restore any you need from the dashboard before uninstalling, then delete `/var/lib/infrafence` yourself.

## Supported Versions

| Version | Supported |
|---|---|
| Latest release | Yes |
| Previous minor | Security fixes only |
| Older | No |

We recommend always running the latest version. With automatic updates turned on in the dashboard, the agent updates itself from GitHub Releases; otherwise it reports each new version.
