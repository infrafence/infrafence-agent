# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability, please report it responsibly:

1. **Do NOT open a public GitHub issue**
2. Email **security@infrafence.com** with details
3. Include steps to reproduce if possible
4. We will respond within 48 hours

We appreciate responsible disclosure and will credit reporters (with permission) in the release notes.

---

## What the Agent Accesses

The agent requires root privileges for two reasons: reading auth logs and managing iptables rules. Here is the complete list of resources it accesses:

| Resource | Access | Purpose |
|---|---|---|
| `/var/log/auth.log` or `/var/log/secure` | Read | SSH brute force detection |
| Nginx / Apache access logs | Read | WAF attack detection |
| `iptables` / `ipset` | Read + Write | Apply and remove IP bans (dedicated `INFRAFENCE` chain) |
| `/proc/net/tcp` | Read | Port scan detection |
| `/var/run/docker.sock` | Read (optional) | Container discovery (only if Docker present) |
| `/etc/infrafence/` | Read + Write | Agent configuration and auth token |

The agent does **not** access: application source code, databases, environment variables, SSH keys, user files, or any data outside of log files and network state.

## What Data Leaves Your Server

All communication uses HTTPS (TLS 1.2+).

**Transmitted to your dashboard:**
- Heartbeats (every 30s): hostname, IP, OS, agent version
- Security events: attacker IP, attack type, severity, timestamp
- Ban reports: banned IP, reason, duration
- Scan results: hardening check pass/fail status

**Never transmitted:**
- Raw log file contents (only parsed attack metadata)
- Application source code or file contents
- Environment variables, secrets, or credentials
- Database content or user data
- SSH keys or passwords

No data is shared with third parties by default.

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

Complete removal with no residual system changes:

```bash
curl -fsSL https://infrafence.com/install.sh | sudo bash -s -- --uninstall
```

Or manually:

```bash
sudo systemctl stop infrafence-agent
sudo systemctl disable infrafence-agent
sudo rm /usr/local/bin/infrafence-agent
sudo rm -rf /etc/infrafence/
sudo iptables -F INFRAFENCE 2>/dev/null
sudo iptables -D INPUT -j INFRAFENCE 2>/dev/null
sudo iptables -X INFRAFENCE 2>/dev/null
```

The agent only creates a dedicated `INFRAFENCE` iptables chain. Removing it restores your firewall to its pre-installation state. No cron jobs, no kernel modules, no system-wide configuration changes.

## Supported Versions

| Version | Supported |
|---|---|
| Latest release | Yes |
| Previous minor | Security fixes only |
| Older | No |

We recommend always running the latest version. The agent auto-updates from GitHub Releases by default.
