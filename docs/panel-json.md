# Panel JSON reference

What `infrafence-agent panel <command> [args] --json` prints, for the cPanel/WHM and Plesk plugins.
This file and the agent's code are checked against each other: the examples are not written by hand.
`TestPanelJSONReference` (`cmd/infrafence-agent/panel_json_test.go`) starts the real panel socket over a
known agent state (a cPanel server with bans of every source, an allow list, events, findings and two
accounts), runs the CLI as its own process for every command and fills in the examples below. The same
outputs are in [`testdata/panel/`](../testdata/panel), byte for byte as printed (one line, then a newline);
here they are only indented. The test fails if the CLI no longer prints them, if a field is missing from
the tables below, or if a field marked "always" is missing from an output. After a change to the output:
`go test ./cmd/infrafence-agent -run TestPanelJSONReference -update-panel-json`.

The test runs in a temporary directory: its prefix is removed from the paths in the examples, which show
them as on a server (`/home/alice/public_html`).

## Where it runs

The agent opens the panel socket (`/run/infrafence/panel.sock`) only on servers with **cPanel/WHM or Plesk**,
or when `/etc/infrafence/config.json` has `"panel": true`. On every other server nothing of the panel side runs.
There, commands answer as if the agent were not running: `agent_running: false`, and `agent_not_running` for
the commands that need the agent.

## Who may see it

Every reply covers **the whole server**: all accounts' sites, bans, events and findings, and the server's
allow list. The agent has no notion of resellers or account owners. Restricting what a reseller or an
account sees is the plugin's job. In v1 the plugins are for root/administrators only (WHM `acls=all`, the
Plesk administrator), and must not expose any of this to resellers or customers.

## Rules for every reply

- stdout carries exactly one JSON object followed by a newline. Nothing else is printed on stdout or
  stderr. The exit status is 0 when `ok` is `true`, and 1 otherwise.
- **Parse the JSON; don't rely on key order.** The keys are sorted today, but that is not part of the
  contract.
- Every key in the tables below marked **always** is present in every reply of that command, including
  when its value is unknown: then it is `null`, never `""` and never left out.
- Timestamps are ISO 8601 strings. Those the agent produces are UTC with seconds (`2026-10-16T12:00:00Z`).
  Ban times that come from the dashboard are passed through as it sends them, so they may carry fractional
  seconds or an offset (`2026-10-17T12:00:00.123+00:00`). Use an ISO 8601 parser, not string comparison.
- Text that comes from logs, file names or rule names (ban reasons, finding paths and names, notes) is
  cleaned of control characters and length-capped by the agent. It is still untrusted text: **HTML-escape
  everything you display.**
- `agent_running` is `true` when the running agent answered, and `false` when it is not running (only
  `status`, `coexistence` and `sites` then still answer `ok`). It is absent only from replies to arguments
  the command refused before asking the agent (see [Errors](#errors)).

Column "Always": `yes` = the key is in every reply (or every array element); `no` = only in some replies.

## Commands

### `status`

`infrafence-agent panel status --json`

<!-- example:status -->
```json
{
  "agent_id": 42,
  "agent_running": true,
  "automode": null,
  "connected": true,
  "control_panel": "cpanel",
  "dashboard_url": "https://app.infrafence.com/servers/42",
  "last_heartbeat": "2026-10-16T11:59:20Z",
  "last_sync": "2026-10-16T12:00:00Z",
  "monitor_mode": false,
  "ok": true,
  "plan": "pro",
  "suspended": false,
  "version": "1.0.23"
}
```
<!-- /example:status -->

Without a running agent, what the config file says (`/etc/infrafence/config.json`; the agent token is never
printed) and `null` for what only the running agent knows:

<!-- example:status_agent_not_running -->
```json
{
  "agent_id": 42,
  "agent_running": false,
  "automode": null,
  "connected": false,
  "control_panel": null,
  "dashboard_url": "https://app.infrafence.com/servers/42",
  "last_heartbeat": null,
  "last_sync": null,
  "monitor_mode": null,
  "ok": true,
  "plan": null,
  "suspended": null,
  "version": "1.0.23"
}
```
<!-- /example:status_agent_not_running -->

| Field | Type | Values | Always | Meaning |
|---|---|---|---|---|
| `ok` | boolean | `true` | yes | |
| `agent_running` | boolean | | yes | |
| `version` | string | | yes | Version of the installed binary, e.g. `1.0.23`. |
| `agent_id` | integer \| null | | yes | This server's id in InfraFence. `null` only when the agent was never registered. |
| `dashboard_url` | string \| null | | yes | This server's page on the dashboard ("Open in InfraFence", a plain link). |
| `last_heartbeat` | string \| null | timestamp | yes | Last heartbeat the dashboard accepted. `null` before the first one, or when the agent is not running. |
| `last_sync` | string \| null | timestamp | yes | Last configuration sync from the dashboard. |
| `connected` | boolean | | yes | `true` when the last accepted heartbeat is less than 3 minutes old. |
| `plan` | string \| null | e.g. `free`, `basic`, `pro` | yes | The organization's plan, as the dashboard sends it. `null` when the dashboard doesn't send it. |
| `automode` | object \| null | | yes | AutoMode state, read only: the object the dashboard sends, passed through unchanged. `null` when the dashboard doesn't send it (today's dashboards). |
| `monitor_mode` | boolean \| null | | yes | `true`: detections are reported but nothing is banned. |
| `suspended` | boolean \| null | | yes | `true`: the organization exceeded its plan's server limit; protection is off. |
| `control_panel` | string \| null | `cpanel`, `plesk`, `directadmin`, `cyberpanel`, `hestiacp`, `vestacp`, `ispconfig`, `cloudpanel`, `cwp`, `aapanel`, `keyhelp`, `froxlor`, `enhance`, `virtualmin`, `webmin`, `coolify`, `dokploy`, `easypanel`, `caprover`, `runcloud`, `gridpane`, `forge`, `ploi`, `bitnami` | yes | Hosting panel detected on the server. |

### `bans`

`infrafence-agent panel bans [--limit N] --json` (N 1–500, default 50). Newest first where the creation time
is known. Bans lifted from the panel are not listed.

<!-- example:bans -->
```json
{
  "agent_running": true,
  "bans": [
    {
      "created": "2026-10-16T12:00:00Z",
      "expires": "2026-10-17T12:00:00Z",
      "ip": "203.0.113.7",
      "reason": "SSH brute force (8 failed logins in 60s)",
      "source": "local"
    },
    {
      "created": "2026-10-16T10:00:00Z",
      "expires": "2026-10-16T16:00:00Z",
      "ip": "198.51.100.23",
      "reason": "Under attack: HTTP flood",
      "source": "automode"
    },
    {
      "created": null,
      "expires": "2026-10-18T00:00:00Z",
      "ip": "192.0.2.50",
      "reason": null,
      "source": "network"
    },
    {
      "created": null,
      "expires": null,
      "ip": "198.51.100.9",
      "reason": null,
      "source": "manual"
    }
  ],
  "monitor_mode": false,
  "ok": true,
  "total": 4
}
```
<!-- /example:bans -->

| Field | Type | Values | Always | Meaning |
|---|---|---|---|---|
| `ok` | boolean | `true` | yes | |
| `agent_running` | boolean | `true` | yes | |
| `bans` | array | | yes | Empty array when there are none. |
| `bans[].ip` | string | IPv4 or IPv6 address | yes | |
| `bans[].reason` | string \| null | | yes | Why it was banned, when known. |
| `bans[].source` | string | `local`, `network`, `automode`, `manual` | yes | `local`: this agent's own detection. `network`: InfraFence network ban (address blocked by many organizations). `automode`: AutoMode. `manual`: from the dashboard (also any dashboard ban whose origin the dashboard doesn't send). |
| `bans[].created` | string \| null | timestamp | yes | |
| `bans[].expires` | string \| null | timestamp | yes | `null`: permanent. |
| `total` | integer | | yes | Number of active bans before `--limit`. |
| `monitor_mode` | boolean | | yes | `true`: these bans are not enforced right now. |

### `unban`

`infrafence-agent panel unban <ip> --actor <panel user> --json`

The ban is lifted **on this server only** (`scope: "server"`). It is never removed in the dashboard or on the
organization's other servers, whatever its source: a network or AutoMode ban stays in force everywhere else.
The dashboard receives a `panel_unban` event that records the local lift. The lift lasts until the dashboard
stops sending the ban (it expired, or someone removed it there) or **at most 30 days** (`lifted_until`). After
that, a ban the dashboard still sends is enforced on this server again. A new detection of the address
by this agent bans it again at once.

<!-- example:unban -->
```json
{
  "agent_running": true,
  "ip": "198.51.100.9",
  "lifted_until": "2026-11-15T12:00:00Z",
  "ok": true,
  "reported": true,
  "scope": "server",
  "source": "manual",
  "threat_feed": false
}
```
<!-- /example:unban -->

| Field | Type | Values | Always | Meaning |
|---|---|---|---|---|
| `ok` | boolean | `true` | yes | |
| `agent_running` | boolean | `true` | yes | |
| `ip` | string | | yes | The address, in canonical form (e.g. `::ffff:198.51.100.9` becomes `198.51.100.9`). |
| `source` | string | `local`, `network`, `automode`, `manual` | yes | Source of the lifted ban, as in `bans[].source`. |
| `scope` | string | `server` | yes | Where the ban is lifted: this server only. |
| `lifted_until` | string | timestamp | yes | When the lift ends at the latest: the ban's expiry, or 30 days from now for a permanent ban. |
| `reported` | boolean | | yes | `true`: the dashboard received the `panel_unban` event. `false`: it was not reachable; the event is sent after the next sync. The ban is lifted on the server either way. |
| `threat_feed` | boolean | | yes | `true`: the address is also on a threat list the server blocks, so it may still be refused. |
| `firewall_pending` | boolean | `true` | no | Present only when removing the firewall entry failed; it is removed at the next sync. |

Errors: `not_banned`, `invalid_ip`, `invalid_actor`, `internal_error`.

### `allow`

`infrafence-agent panel allow <ip> [--note <text>] --actor <panel user> --json` (note: up to 200 bytes of
printable text).

<!-- example:allow -->
```json
{
  "agent_running": true,
  "banned": false,
  "ip": "198.51.100.77",
  "ok": true,
  "own_address": false,
  "reported": true
}
```
<!-- /example:allow -->

| Field | Type | Values | Always | Meaning |
|---|---|---|---|---|
| `ok` | boolean | `true` | yes | |
| `agent_running` | boolean | `true` | yes | |
| `ip` | string | | yes | Canonical form. |
| `reported` | boolean | | no | Absent when `already` is `true`. As for `unban`. |
| `banned` | boolean | | no | Absent when `already` is `true`. `true`: the address is also banned. The allow list wins: it is not blocked, but the ban is still listed. |
| `already` | boolean | `true` | no | Present when the address was already allowed (this list, the dashboard's, or the server's own addresses). Nothing was changed or reported. Then only `ip` and `own_address` come with it. |
| `own_address` | boolean | | yes | `true`: this is one of the server's own addresses (bound locally, or its public address). It is never banned anyway; show a warning, since this is usually a mistake. |

Errors: `loopback_address`, `invalid_ip`, `invalid_actor`, `bad_request` (invalid note, or 1,000 entries
already), `internal_error`.

### `allowlist`

`infrafence-agent panel allowlist --json`. Entries added from the panel first, then the organization's
allow list from the dashboard.

<!-- example:allowlist -->
```json
{
  "agent_running": true,
  "allowlist": [
    {
      "actor": "root",
      "added": "2026-10-14T12:00:00Z",
      "address": "198.51.100.4",
      "note": "Office VPN",
      "source": "panel"
    },
    {
      "actor": null,
      "added": null,
      "address": "203.0.113.20",
      "note": null,
      "source": "dashboard"
    },
    {
      "actor": null,
      "added": null,
      "address": "10.0.0.0/8",
      "note": null,
      "source": "dashboard"
    }
  ],
  "ok": true
}
```
<!-- /example:allowlist -->

| Field | Type | Values | Always | Meaning |
|---|---|---|---|---|
| `ok` | boolean | `true` | yes | |
| `agent_running` | boolean | `true` | yes | |
| `allowlist` | array | | yes | Empty array when there are none. |
| `allowlist[].address` | string | IP address or CIDR range | yes | Ranges come only from the dashboard. |
| `allowlist[].source` | string | `panel`, `dashboard` | yes | Only `panel` entries can be removed with `disallow`. |
| `allowlist[].note` | string \| null | | yes | `null` for dashboard entries. |
| `allowlist[].actor` | string \| null | | yes | Panel user who added it; `null` for dashboard entries. |
| `allowlist[].added` | string \| null | timestamp | yes | `null` for dashboard entries. |

### `disallow`

`infrafence-agent panel disallow <ip> --actor <panel user> --json`

<!-- example:disallow -->
```json
{
  "agent_running": true,
  "ip": "198.51.100.4",
  "ok": true,
  "reported": true
}
```
<!-- /example:disallow -->

| Field | Type | Values | Always | Meaning |
|---|---|---|---|---|
| `ok` | boolean | `true` | yes | |
| `agent_running` | boolean | `true` | yes | |
| `ip` | string | | yes | |
| `reported` | boolean | | yes | As for `unban`. |

Errors: `not_in_allowlist`, `managed_by_dashboard` (an entry of the organization's allow list: remove it in
the dashboard), `invalid_ip`, `invalid_actor`, `internal_error`.

### `findings`

`infrafence-agent panel findings [--limit N] --json` (N 1–500, default 50). Malware and file-integrity
findings since the agent started (kept in memory, at most 1,000), newest first by `last_seen`.

<!-- example:findings -->
```json
{
  "agent_running": true,
  "findings": [
    {
      "detected": "2026-10-16T11:30:00Z",
      "kind": "malware",
      "last_seen": "2026-10-16T11:30:00Z",
      "name": "Obfuscated eval",
      "path": "/home/bob/public_html/wp-includes/class-wp-cache.php",
      "severity": "high",
      "status": "detected"
    },
    {
      "detected": "2026-10-16T11:00:00Z",
      "kind": "malware",
      "last_seen": "2026-10-16T11:00:00Z",
      "name": "PHP webshell (generic)",
      "path": "/home/alice/public_html/wp-content/uploads/x.php",
      "severity": "critical",
      "status": "quarantined"
    },
    {
      "detected": "2026-10-16T10:30:00Z",
      "kind": "integrity",
      "last_seen": "2026-10-16T10:30:00Z",
      "name": null,
      "path": "/etc/passwd",
      "severity": "warning",
      "status": "detected"
    }
  ],
  "ok": true,
  "total": 3
}
```
<!-- /example:findings -->

| Field | Type | Values | Always | Meaning |
|---|---|---|---|---|
| `ok` | boolean | `true` | yes | |
| `agent_running` | boolean | `true` | yes | |
| `findings` | array | | yes | Empty array when there are none. |
| `findings[].path` | string | absolute path | yes | |
| `findings[].kind` | string | `malware`, `integrity` | yes | `integrity`: a monitored system file changed (`/etc/passwd`, `sshd_config`, crontabs, `authorized_keys`...). |
| `findings[].name` | string \| null | | yes | Signature or rule name; `null` for `integrity`. |
| `findings[].severity` | string | malware: `critical`, `high`, `medium`, `low`; integrity: `critical`, `warning`, `info` | yes | |
| `findings[].status` | string | `detected`, `quarantined` | yes | `quarantined`: the file was moved to quarantine (on request from the dashboard). |
| `findings[].detected` | string | timestamp | yes | First seen. |
| `findings[].last_seen` | string | timestamp | yes | Last seen by a scan or the real-time watcher. |
| `total` | integer | | yes | Number of findings before `--limit`. |

### `events`

`infrafence-agent panel events [--limit N] [--since <time>] --json` (N 1–500, default 50; `--since` is an
RFC 3339 time or a duration back from now such as `24h`, at most 90 days). Recent security events the agent
reported (kept in memory, at most 1,000; progress events are left out), newest first.

<!-- example:events -->
```json
{
  "agent_running": true,
  "events": [
    {
      "severity": "info",
      "source": null,
      "source_ip": null,
      "time": "2026-10-16T11:10:00Z",
      "type": "quarantine_completed"
    },
    {
      "severity": "critical",
      "source": null,
      "source_ip": null,
      "time": "2026-10-16T11:00:00Z",
      "type": "malware_realtime"
    },
    {
      "severity": "warning",
      "source": null,
      "source_ip": null,
      "time": "2026-10-16T10:30:00Z",
      "type": "integrity_change"
    },
    {
      "severity": "critical",
      "source": "modsecurity",
      "source_ip": "198.51.100.23",
      "time": "2026-10-16T10:00:00Z",
      "type": "sql_injection"
    },
    {
      "severity": "warning",
      "source": "watcher",
      "source_ip": "203.0.113.7",
      "time": "2026-10-16T09:00:00Z",
      "type": "ssh_brute_force"
    }
  ],
  "ok": true
}
```
<!-- /example:events -->

| Field | Type | Values | Always | Meaning |
|---|---|---|---|---|
| `ok` | boolean | `true` | yes | |
| `agent_running` | boolean | `true` | yes | |
| `events` | array | | yes | Empty array when there are none. |
| `events[].type` | string | open set, e.g. `ssh_brute_force`, `sql_injection`, `xss_attempt`, `rce_attempt`, `port_scan`, `integrity_change`, `malware_realtime`, `quarantine_completed`, `egress_threat_match`, `dns_threat_answer`, `panel_unban`, `panel_allow`, `panel_disallow`, `panel_scan` | yes | Show unknown types as they are. |
| `events[].severity` | string | `info`, `warning`, `critical` (malware findings: `critical`, `high`, `medium`, `low`) | yes | |
| `events[].source_ip` | string \| null | | yes | The remote address, when the event has one. |
| `events[].source` | string \| null | e.g. `watcher`, `webwatcher`, `modsecurity`, `panel` | yes | Which part of the agent reported it, when known. |
| `events[].time` | string | timestamp | yes | |

### `coexistence`

`infrafence-agent panel coexistence --json`. Read-only detection; also answers without a running agent.

<!-- example:coexistence -->
```json
{
  "agent_running": true,
  "mode": "coexist",
  "ok": true,
  "tools": [
    {
      "action": "InfraFence keeps its own chain and never edits csf.conf, csf.allow or csf.deny. After csf -r it restores only its own jump. CSF ports change only when you ask from the dashboard.",
      "action_id": "coexist_csf",
      "active": true,
      "id": "csf",
      "kind": "firewall",
      "manages_firewall": true,
      "name": "CSF (ConfigServer Firewall)",
      "rulesets": [],
      "version": "14.20"
    },
    {
      "action": "Both read the same logs and block on their own; lfd blocks stay in CSF, InfraFence bans stay in its own set.",
      "action_id": "coexist_lfd",
      "active": true,
      "id": "lfd",
      "kind": "brute_force",
      "manages_firewall": false,
      "name": "lfd (Login Failure Daemon)",
      "rulesets": [],
      "version": null
    },
    {
      "action": "InfraFence leaves Imunify360's firewall, ipsets and WAF alone and keeps to its own chain; both block independently.",
      "action_id": "coexist_imunify",
      "active": true,
      "id": "imunify",
      "kind": "firewall",
      "manages_firewall": true,
      "name": "Imunify360",
      "rulesets": [],
      "version": null
    },
    {
      "action": "cPHulk blocks panel and service logins; InfraFence reads the same logs and bans at the firewall. cPHulk is not changed.",
      "action_id": "coexist_cphulk",
      "active": true,
      "id": "cphulk",
      "kind": "brute_force",
      "manages_firewall": false,
      "name": "cPHulk",
      "rulesets": [],
      "version": null
    },
    {
      "action": "InfraFence reads the ModSecurity audit log for detections. Under a hosting panel it adds no ModSecurity rules: the panel owns the web server configuration.",
      "action_id": "coexist_modsecurity",
      "active": true,
      "id": "modsecurity",
      "kind": "waf",
      "manages_firewall": false,
      "name": "ModSecurity",
      "rulesets": [
        "Imunify360 WAF",
        "OWASP CRS"
      ],
      "version": null
    }
  ]
}
```
<!-- /example:coexistence -->

| Field | Type | Values | Always | Meaning |
|---|---|---|---|---|
| `ok` | boolean | `true` | yes | |
| `agent_running` | boolean | | yes | |
| `mode` | string | `coexist`, `primary` | yes | `coexist`: another active tool writes firewall rules; InfraFence keeps to its own chains and never edits theirs. `primary`: InfraFence is the only one. |
| `tools` | array | | yes | Empty array when no other tool is found. |
| `tools[].id` | string | `csf`, `lfd`, `imunify`, `imunifyav`, `cphulk`, `fail2ban`, `crowdsec`, `plesk_firewall`, `bitninja`, `monarx`, `firewalld`, `ufw`, `modsecurity` | yes | |
| `tools[].name` | string | | yes | Display name (product names, not translated). |
| `tools[].kind` | string | `firewall`, `brute_force`, `waf`, `malware` | yes | |
| `tools[].active` | boolean | | yes | Running (or, for CSF, not in testing mode). |
| `tools[].manages_firewall` | boolean | | yes | The tool writes its own iptables/nftables rules. |
| `tools[].version` | string \| null | | yes | Known for CSF only. |
| `tools[].rulesets` | array of string | `OWASP CRS`, `Comodo WAF`, `Imunify360 WAF`, `Atomicorp`, or the vendor's own id | yes | ModSecurity vendors and rule sets in use; empty array for other tools. |
| `tools[].action_id` | string | `coexist_<id>` | yes | Key for translating `action` in the plugin. |
| `tools[].action` | string | | yes | What InfraFence does about this tool, in English. |

### `sites`

`infrafence-agent panel sites --json`. Read-only (cPanel userdata, the Plesk database, DirectAdmin's domain
lists); also answers without a running agent. With no hosting panel, `sites` is an empty array.

<!-- example:sites -->
```json
{
  "agent_running": true,
  "control_panel": "cpanel",
  "malware_scan_enabled": true,
  "ok": true,
  "sites": [
    {
      "account": "alice",
      "document_root": "/home/alice/public_html",
      "domain": "alice.example",
      "kind": "main",
      "scan_covered": true,
      "scannable": true
    },
    {
      "account": "alice",
      "document_root": "/home/alice/public_html",
      "domain": "alice.example.net",
      "kind": "parked",
      "scan_covered": true,
      "scannable": true
    },
    {
      "account": "alice",
      "document_root": "/home/alice/public_html/blog",
      "domain": "blog.alice.example",
      "kind": "sub",
      "scan_covered": true,
      "scannable": true
    },
    {
      "account": "bob",
      "document_root": "/home/bob/public_html",
      "domain": "bob.example",
      "kind": "main",
      "scan_covered": false,
      "scannable": true
    }
  ]
}
```
<!-- /example:sites -->

| Field | Type | Values | Always | Meaning |
|---|---|---|---|---|
| `ok` | boolean | `true` | yes | |
| `agent_running` | boolean | | yes | |
| `control_panel` | string \| null | as in `status` | yes | |
| `malware_scan_enabled` | boolean \| null | | yes | Scheduled malware scanning is on in the dashboard. `null` when unknown (agent not running, or not sent yet). |
| `sites` | array | | yes | |
| `sites[].account` | string \| null | | yes | cPanel user, Plesk system user, DirectAdmin user. |
| `sites[].domain` | string | | yes | |
| `sites[].kind` | string | cPanel: `main`, `addon`, `sub`, `parked`; Plesk and DirectAdmin: `site` | yes | |
| `sites[].document_root` | string \| null | absolute path | yes | `null` when the panel doesn't say. |
| `sites[].scan_covered` | boolean | | yes | The document root is inside a directory the scheduled malware scan covers. |
| `sites[].scannable` | boolean | | yes | `scan` accepts this document root: it belongs to the account (see `scan`). Show the scan action only when `true`. |

### `scan`

`infrafence-agent panel scan <document root> --actor <panel user> --json`. Queues a malware scan of one
site's document root (`sites[].document_root`; nothing else is accepted). The document root must belong to
the site's account. After resolving symlinks it must sit inside the account's home directory (on Plesk, also
inside `/var/www/vhosts/<domain>`), never be that directory itself or a system directory, and be owned by the
account's uid. Otherwise the reply is `not_scannable` (`sites[].scannable` says so in advance). The directory
is opened once and checked again just before the scan starts.

The scan reads only the files under it, never through a symlink (symlinked files and directories are
skipped; YARA runs with `-N`). It does not run the server-wide checks, and it doesn't change the server's
security score.

<!-- example:scan -->
```json
{
  "agent_running": true,
  "ok": true,
  "path": "/home/alice/public_html",
  "queued": true,
  "reported": true
}
```
<!-- /example:scan -->

| Field | Type | Values | Always | Meaning |
|---|---|---|---|---|
| `ok` | boolean | `true` | yes | |
| `agent_running` | boolean | `true` | yes | |
| `path` | string | | yes | The directory that will be scanned, symlinks resolved. |
| `queued` | boolean | `true` | yes | The scan started in the background. Results arrive as `findings` and in the dashboard. |
| `reported` | boolean | | yes | As for `unban`. |

Errors: `not_a_document_root`, `not_scannable`, `scan_running` (one scan at a time per server),
`invalid_path`, `invalid_actor`.

## Errors

Every error is `ok: false` with a code and an English message (log it; translate by `error`). The exit
status is 1.

From the agent (`agent_running: true`):

<!-- example:error -->
```json
{
  "agent_running": true,
  "error": "not_banned",
  "message": "203.0.113.99 is not banned by InfraFence on this server",
  "ok": false
}
```
<!-- /example:error -->

When the agent is not running, for commands that need it (`agent_running: false`):

<!-- example:error_agent_not_running -->
```json
{
  "agent_running": false,
  "error": "agent_not_running",
  "message": "the InfraFence agent is not running",
  "ok": false
}
```
<!-- /example:error_agent_not_running -->

Arguments the command refuses before asking the agent: no `agent_running` key.

<!-- example:error_invalid_ip -->
```json
{
  "error": "invalid_ip",
  "message": "not a single IPv4 or IPv6 address",
  "ok": false
}
```
<!-- /example:error_invalid_ip -->

| Field | Type | Values | Always | Meaning |
|---|---|---|---|---|
| `ok` | boolean | `false` | yes | |
| `error` | string | see below | yes | |
| `message` | string | | yes | English, for logs. |
| `agent_running` | boolean | | no | Absent only when the arguments were refused before asking the agent (`bad_request`, `unknown_command`, `invalid_ip`, `invalid_path`, `invalid_actor`) or the command didn't run as root (`not_root`). |

Error codes:

| `error` | When |
|---|---|
| `bad_request` | Unknown option, missing or extra argument, invalid `--limit`, `--since` or `--note`, full allow list. |
| `unknown_command` | Not one of the eleven commands. |
| `invalid_ip` | Not exactly one IPv4 or IPv6 address (ranges, ports, zones, `0.0.0.0`, `::`, broadcast and multicast are refused). |
| `invalid_path` | Not a clean absolute path. |
| `invalid_actor` | `--actor` missing on a command that changes something, or not 1–64 of `A–Z a–z 0–9 . _ @ - +`. |
| `not_root` | The command was not run as root. |
| `agent_not_running` | The agent is not running (all commands except `status`, `coexistence`, `sites`). |
| `loopback_address` | `allow`: a loopback address (`127.0.0.0/8`, `::1`); it is never banned and is refused. |
| `not_banned` | `unban`: the address is not banned on this server (or was already lifted). |
| `not_in_allowlist` | `disallow`: the address is not on the allow list. |
| `managed_by_dashboard` | `disallow`: the entry belongs to the organization's allow list in the dashboard. |
| `not_a_document_root` | `scan`: missing, or not the document root of any site. |
| `not_scannable` | `scan`: the site's document root doesn't belong to its account: outside its home, not owned by its uid, a system directory, or the site has no account. |
| `scan_running` | `scan`: a malware scan is already running. |
| `internal_error` | The agent did not answer in time, or could not save the change (nothing was changed). |
