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

## Paid plans only

The plugins are included in the **Basic, Pro and AutoMode** plans (a comped plan counts as its plan). `status`
always answers and says whether the organization is entitled (`entitled`, `entitlement`). Every other command
answers only an error when it is not, with no data at all, and changes nothing (an unban, allow, disallow or scan
is refused):

| `entitlement` | When | Error of the other commands |
|---|---|---|
| `ok` | The plan is `basic`, `pro` or `automode`, and protection is not switched off. | (none: they answer) |
| `plan_required` | Another plan, such as Starter. Show "included in Basic, Pro and AutoMode" and a link to upgrade. | `plan_required` |
| `unpaid` | Protection is switched off (`protection: disabled`): the dashboard has refused the agent for 24 hours, e.g. the subscription is not active. Show the billing message. | `unpaid` |
| `unknown` | No plan known yet: the agent has never synced since it was installed or upgraded, or the dashboard doesn't send the plan. Show "waiting for the InfraFence dashboard", not "upgrade". | `unknown` |

The plan is the one of the last successful sync. The agent keeps it in
`/var/lib/infrafence/protection-state.json` across restarts and uses it while the dashboard is unreachable, so an
outage doesn't blank the plugin; a refusal (`protection: refused`) keeps it too, until protection is switched off.
Without a running agent, `status`, `coexistence` and `sites` use the same saved state. The gate is on the replies
only: it never changes the server's protection. Agents up to 1.0.33 don't gate: there the plugin decides from
`plan` and `protection` (entitled = plan `basic`, `pro` or `automode`, and protection not `disabled`).

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
  `status`, `coexistence` and `sites` then still answer `ok`, the last two only when
  [entitled](#paid-plans-only)). It is absent only from replies to arguments
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
  "disabled_at": null,
  "entitled": true,
  "entitlement": "ok",
  "last_heartbeat": "2026-10-16T11:59:20Z",
  "last_sync": "2026-10-16T12:00:00Z",
  "monitor_mode": false,
  "ok": true,
  "plan": "pro",
  "plugin_installed": "1.0.2",
  "plugin_latest": "1.0.3",
  "protection": "active",
  "refused_since": null,
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
  "disabled_at": null,
  "entitled": false,
  "entitlement": "unknown",
  "last_heartbeat": null,
  "last_sync": null,
  "monitor_mode": null,
  "ok": true,
  "plan": null,
  "plugin_installed": null,
  "plugin_latest": null,
  "protection": null,
  "refused_since": null,
  "suspended": null,
  "version": "1.0.23"
}
```
<!-- /example:status_agent_not_running -->

An organization on a plan without the plugins (Starter): `entitled` is `false` and every other command answers
`plan_required`.

<!-- example:status_plan_required -->
```json
{
  "agent_id": 42,
  "agent_running": true,
  "automode": null,
  "connected": true,
  "control_panel": "cpanel",
  "dashboard_url": "https://app.infrafence.com/servers/42",
  "disabled_at": null,
  "entitled": false,
  "entitlement": "plan_required",
  "last_heartbeat": "2026-10-16T11:59:20Z",
  "last_sync": "2026-10-16T12:00:00Z",
  "monitor_mode": false,
  "ok": true,
  "plan": "starter",
  "plugin_installed": "1.0.2",
  "plugin_latest": "1.0.3",
  "protection": "active",
  "refused_since": null,
  "suspended": false,
  "version": "1.0.23"
}
```
<!-- /example:status_plan_required -->

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
| `plan` | string \| null | e.g. `starter`, `basic`, `pro`, `automode` | yes | The organization's plan, as the dashboard sent it in the last successful sync (kept across restarts and while the dashboard is unreachable; without a running agent, the saved one). `null` when it is not known or the dashboard doesn't send it. |
| `entitled` | boolean | | yes | `true` when the plugin may show data: `entitlement` is `ok`. See [Paid plans only](#paid-plans-only). |
| `entitlement` | string | `ok`, `plan_required`, `unpaid`, `unknown` | yes | Why the plugin may or may not show data; the other commands answer the same code as their error. |
| `automode` | object \| null | | yes | AutoMode state, read only: the object the dashboard sends, passed through unchanged. `null` when the dashboard doesn't send it (today's dashboards). |
| `monitor_mode` | boolean \| null | | yes | `true`: detections are reported but nothing is banned. |
| `suspended` | boolean \| null | | yes | `true`: the organization exceeded its plan's server limit; protection is off. |
| `protection` | string \| null | `active`, `refused`, `disabled` | yes | `active`: InfraFence protects the server. `refused`: the dashboard refuses the agent (401, or 403 such as an organization suspended) but protection is still in force; it is switched off after 24 hours of refusal. `disabled`: protection is switched off after 24 hours of refusal (InfraFence's firewall chains, ipsets, ModSecurity rules and user-agent blocking removed, nothing banned) until the dashboard accepts the agent again — show a red banner. A dashboard that is only unreachable never leads to `refused` or `disabled`. Without a running agent: `disabled` when it was switched off, `null` otherwise. |
| `refused_since` | string \| null | timestamp | yes | When the dashboard started refusing the agent (no accepted request since); `null` when it is not refusing. |
| `disabled_at` | string \| null | timestamp | yes | When protection was switched off; `null` while it is on. |
| `control_panel` | string \| null | `cpanel`, `plesk`, `directadmin`, `cyberpanel`, `hestiacp`, `vestacp`, `ispconfig`, `cloudpanel`, `cwp`, `aapanel`, `keyhelp`, `froxlor`, `enhance`, `virtualmin`, `webmin`, `coolify`, `dokploy`, `easypanel`, `caprover`, `runcloud`, `gridpane`, `forge`, `ploi`, `bitnami` | yes | Hosting panel detected on the server. |
| `plugin_installed` | string \| null | e.g. `1.0.2` | yes | Version of the InfraFence plugin installed in the panel, read by the agent (WHM: `/usr/local/share/infrafence-whm/VERSION`, else the `infrafence-whm` rpm or deb package). Agent 1.0.35+. `null` when no plugin is found, and on Plesk for now. The plugin is updated from the dashboard (Panel plugins), not with the agent: `version` is the agent's, this is the plugin's. |
| `plugin_latest` | string \| null | e.g. `1.0.3` | yes | Latest release of this panel's plugin, as the dashboard sent it in the last sync (`panel_plugin_latest`). Agent 1.0.35+. `null` when the dashboard doesn't send it, on Plesk for now, and without a running agent. When it is newer than the plugin's own version (compare as versions, not as text), the plugin can say that an update is available from Dashboard › Panel plugins. Older agents leave both fields out: show nothing. |

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
      "resolved_at": null,
      "resolved_how": null,
      "severity": "high",
      "state": "open",
      "status": "detected",
      "subject": "malware:/home/bob/public_html/wp-includes/class-wp-cache.php"
    },
    {
      "detected": "2026-10-16T11:00:00Z",
      "kind": "malware",
      "last_seen": "2026-10-16T11:00:00Z",
      "name": "PHP webshell (generic)",
      "path": "/home/alice/public_html/wp-content/uploads/x.php",
      "resolved_at": "2026-10-16T11:10:00Z",
      "resolved_how": "quarantined",
      "severity": "critical",
      "state": "resolved",
      "status": "quarantined",
      "subject": "malware:/home/alice/public_html/wp-content/uploads/x.php"
    },
    {
      "detected": "2026-10-16T10:30:00Z",
      "kind": "integrity",
      "last_seen": "2026-10-16T10:30:00Z",
      "name": null,
      "path": "/etc/passwd",
      "resolved_at": "2026-10-16T11:40:00Z",
      "resolved_how": "marked_expected",
      "severity": "warning",
      "state": "resolved",
      "status": "detected",
      "subject": "file:/etc/passwd"
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
| `findings[].subject` | string | `malware:<path>`, `file:<path>` | yes | What the finding is about (see [Problems and resolution](#problems-and-resolution)). |
| `findings[].state` | string | `open`, `resolved` | yes | `resolved`: resolved after `last_seen` (quarantined, marked as resolved in the dashboard...). |
| `findings[].resolved_at` | string \| null | timestamp | yes | When it was resolved; `null` while open. |
| `findings[].resolved_how` | string \| null | see [Problems and resolution](#problems-and-resolution) | yes | How it was resolved; `null` while open. |
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
      "resolved_at": null,
      "resolved_how": null,
      "severity": "warning",
      "source": null,
      "source_ip": null,
      "state": "open",
      "subject": "php:PHP_DISPLAY_ERRORS@ea-php82",
      "time": "2026-10-16T11:50:00Z",
      "type": "php_config_risk"
    },
    {
      "resolved_at": null,
      "resolved_how": null,
      "severity": "info",
      "source": null,
      "source_ip": null,
      "state": null,
      "subject": "malware:/home/alice/public_html/wp-content/uploads/x.php",
      "time": "2026-10-16T11:10:00Z",
      "type": "quarantine_completed"
    },
    {
      "resolved_at": "2026-10-16T11:10:00Z",
      "resolved_how": "quarantined",
      "severity": "critical",
      "source": null,
      "source_ip": null,
      "state": "resolved",
      "subject": "malware:/home/alice/public_html/wp-content/uploads/x.php",
      "time": "2026-10-16T11:00:00Z",
      "type": "malware_realtime"
    },
    {
      "resolved_at": null,
      "resolved_how": null,
      "severity": "info",
      "source": null,
      "source_ip": null,
      "state": null,
      "subject": "port:tcp/3306",
      "time": "2026-10-16T10:50:00Z",
      "type": "firewall_action_done"
    },
    {
      "resolved_at": "2026-10-16T10:50:00Z",
      "resolved_how": "port_closed",
      "severity": "critical",
      "source": null,
      "source_ip": null,
      "state": "resolved",
      "subject": "port:tcp/3306",
      "time": "2026-10-16T10:40:00Z",
      "type": "db_exposed"
    },
    {
      "resolved_at": "2026-10-16T11:40:00Z",
      "resolved_how": "marked_expected",
      "severity": "warning",
      "source": null,
      "source_ip": null,
      "state": "resolved",
      "subject": "file:/etc/passwd",
      "time": "2026-10-16T10:30:00Z",
      "type": "integrity_change"
    },
    {
      "resolved_at": null,
      "resolved_how": null,
      "severity": "critical",
      "source": "modsecurity",
      "source_ip": "198.51.100.23",
      "state": null,
      "subject": null,
      "time": "2026-10-16T10:00:00Z",
      "type": "sql_injection"
    },
    {
      "resolved_at": null,
      "resolved_how": null,
      "severity": "warning",
      "source": "watcher",
      "source_ip": "203.0.113.7",
      "state": null,
      "subject": null,
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
| `events[].subject` | string \| null | e.g. `port:tcp/3306`, `file:/etc/passwd` | yes | What the event is about (see [Problems and resolution](#problems-and-resolution)): problem events, and the results of the actions taken on them (`firewall_action_done`, `quarantine_completed`...). `null` for the others (attacks, scans, progress). |
| `events[].state` | string \| null | `open`, `resolved` | yes | Problem events only (`null` for every other event, and for a problem event without a subject). `resolved`: its subject was resolved at or after `time`. Count and highlight only `open` ones. Agents before 1.0.34 don't send `state`: treat every event as open. |
| `events[].resolved_at` | string \| null | timestamp | yes | When it was resolved; `null` unless `state` is `resolved`. |
| `events[].resolved_how` | string \| null | see [Problems and resolution](#problems-and-resolution) | yes | How it was resolved; `null` unless `state` is `resolved`. |

#### Problems and resolution

A **problem event** reports a condition that can still be true on the server; once it is dealt with, it is
**resolved**. Each one has a `subject`, a stable key of what it is about, the same in the agent's events
(`details.subject`) and in the dashboard:

| Event type | Subject | Problem (has a `state`) |
|---|---|---|
| `db_exposed` | `port:tcp/<port>` | yes |
| `integrity_change`, `php_dropin_changed` | `file:<path>` | yes |
| `php_config_risk` | `php:<check_id>` (e.g. `php:PHP_DISPLAY_ERRORS@ea-php82`) | yes |
| `malware_realtime` | `malware:<path>` | yes |
| `virtual_patch_failed` | `cve:<id>` | yes (when applying) |
| `hardening_fix_failed`, `hardening_fix_rolled_back` | `php:<check_id>` for PHP checks, `hardening:<check_id>` otherwise | yes (unless reverting) |
| `package_update_failed` | `package:<name>` (one package per request only) | yes |
| `firewall_action_done`, `firewall_action_failed`, `firewall_action_rolled_back` (`close_port`, `open_port`) | `port:<proto>/<port>` | no: the result of an action |
| `quarantine_completed`, `quarantine_failed`, `quarantine_restored`, `quarantine_restore_failed` | `malware:<path>` | no |
| `hardening_fix_applied` | `php:<check_id>` or `hardening:<check_id>` | no |
| `virtual_patch_done` | `cve:<id>` | no |
| `package_update_started`, `package_update_done` | `package:<name>` (one package per request only) | no |

Findings are all problems: `malware:<path>` for `malware`, `file:<path>` for `integrity`.

A subject is resolved from a point in time on. The dashboard sends what it resolved (a port closed, a fix
applied, a file quarantined, a package updated, "Mark as resolved" or "Mark as expected"), and the agent records
what it fixed itself: a port its firewall closed (not when it is still reachable over IPv6), a fix applied and
verified, a file quarantined, a package updated. The agent keeps its own resolutions for 30 days across
restarts. An event or finding at or before the resolution is `resolved`; a newer one is `open` again (the
problem came back). `resolved_how`: `port_closed`, `fix_applied`, `rescan_clean`, `quarantined`,
`marked_expected`, `marked_resolved`, `package_updated`, `superseded`, or another word from a newer
dashboard (show it as it is).

A database port the agent's firewall closes is no longer reported as `db_exposed` when the agent starts,
even though the database still listens on all addresses.

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
      "action": "InfraFence keeps its own chain and never edits csf.conf, csf.allow or csf.deny. After csf -r it restores only its own chains, jumps and sets, within seconds and never while csf is restarting. CSF ports change only when you ask from the dashboard.",
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

### `map`

`infrafence-agent panel map [--hours 24|168] --json` (default 24: the last 24 hours; 168: the last 7 days).
Where this server's attacks came from, as the dashboard counts them for its maps: inbound attacks only, by
country and by category, with no addresses. The running agent asks the dashboard
(`GET /api/v1/agent/map`) **at most once every 5 minutes for each range**, whether it answered or not, and
gives every request in between the answer it has. Ask as often as you like (on every page view); nothing
reaches the dashboard more often. Requests arriving while one is in flight wait for it (at most 10 seconds).

<!-- example:map -->
```json
{
  "agent_running": true,
  "categories": [
    {
      "attacks": 30,
      "cat": "ssh"
    },
    {
      "attacks": 21,
      "cat": "web"
    },
    {
      "attacks": 6,
      "cat": "scans"
    }
  ],
  "connected": true,
  "countries": [
    {
      "attacks": 40,
      "code": "CN"
    },
    {
      "attacks": 12,
      "code": "US"
    },
    {
      "attacks": 3,
      "code": "BR"
    }
  ],
  "generated_at": "2026-10-16T11:58:00Z",
  "hours": 24,
  "ok": true,
  "stale": false,
  "total": {
    "attacks": 57
  }
}
```
<!-- /example:map -->

When the dashboard did not answer the latest request (unreachable, or an error), the last answer is given
again with `stale: true`; show `generated_at` as "last updated". An answer the dashboard computed more than an
hour ago is `stale` too, even when it was just received. The agent refuses an answer whose `generated_at` is
more than 5 minutes in the future. With no answer at all since the agent
started, the reply is the error `not_connected` (see [Errors](#errors)): show an empty state.

<!-- example:map_stale -->
```json
{
  "agent_running": true,
  "categories": [
    {
      "attacks": 30,
      "cat": "ssh"
    },
    {
      "attacks": 21,
      "cat": "web"
    },
    {
      "attacks": 6,
      "cat": "scans"
    }
  ],
  "connected": true,
  "countries": [
    {
      "attacks": 40,
      "code": "CN"
    },
    {
      "attacks": 12,
      "code": "US"
    },
    {
      "attacks": 3,
      "code": "BR"
    }
  ],
  "generated_at": "2026-10-16T11:58:00Z",
  "hours": 24,
  "ok": true,
  "stale": true,
  "total": {
    "attacks": 57
  }
}
```
<!-- /example:map_stale -->

| Field | Type | Values | Always | Meaning |
|---|---|---|---|---|
| `ok` | boolean | `true` | yes | |
| `agent_running` | boolean | `true` | yes | |
| `connected` | boolean | | yes | As in `status`: the last heartbeat the dashboard accepted is less than 3 minutes old. |
| `stale` | boolean | | yes | `true`: the dashboard did not answer the latest request, so this is an earlier answer, or `generated_at` is more than an hour old. |
| `hours` | integer | `24`, `168` | yes | The range asked for. |
| `generated_at` | string | timestamp | yes | When the dashboard computed it. |
| `total` | object | | yes | |
| `total.attacks` | integer | | yes | Attacks in the range, including those from an unknown country. No "blocked" figure. |
| `countries` | array | | yes | Most attacks first, at most 250. Empty array when there are none. |
| `countries[].code` | string | ISO 3166-1 alpha-2, upper case | yes | Countries the dashboard cannot place are left out (they count in `total`). |
| `countries[].attacks` | integer | | yes | |
| `categories` | array | | yes | Most attacks first. Empty array when there are none. |
| `categories[].cat` | string | `ssh`, `web`, `bots`, `scans`, `other` (open set) | yes | As on the dashboard's maps. Show an unknown category as `other`. |
| `categories[].attacks` | integer | | yes | |

Errors: `not_connected`, `bad_request` (`--hours` other than 24 or 168).

### `score`

`infrafence-agent panel score --json`. This server's security score as the dashboard computes it, what takes
points off it, and its daily scores of the last 30 days. Fetched like `map`: the running agent asks the
dashboard (`GET /api/v1/agent/score`) **at most once every 15 minutes**, with the same `stale` and
`not_connected` rules. As everywhere in this reference, **HTML-escape every field you display**, also those the
agent has checked.

<!-- example:score -->
```json
{
  "agent_running": true,
  "connected": true,
  "generated_at": "2026-10-16T11:58:00Z",
  "grade": "C",
  "items": [
    {
      "detail": {
        "ports": [
          3306,
          6379
        ]
      },
      "key": "exposed_ports",
      "points": 16
    },
    {
      "detail": {
        "failed": 22,
        "total": 43
      },
      "key": "hardening",
      "points": 12
    }
  ],
  "ok": true,
  "score": 72,
  "stale": false,
  "trend": [
    {
      "day": "2026-10-14",
      "score": 65
    },
    {
      "day": "2026-10-15",
      "score": 70
    },
    {
      "day": "2026-10-16",
      "score": 72
    }
  ]
}
```
<!-- /example:score -->

| Field | Type | Values | Always | Meaning |
|---|---|---|---|---|
| `ok` | boolean | `true` | yes | |
| `agent_running` | boolean | `true` | yes | |
| `connected` | boolean | | yes | As for `map`. |
| `stale` | boolean | | yes | As for `map`. |
| `generated_at` | string | timestamp | yes | When the dashboard computed it. |
| `score` | integer | 0–100 | yes | |
| `grade` | string | `A`–`F` | yes | As the dashboard shows it. |
| `items` | array | | yes | What takes points off, most points first. Empty array for a perfect score. |
| `items[].key` | string | open set, e.g. `hardening`, `no_hardening_scan`, `exploited_cves`, `vulnerable_packages`, `no_software_audit`, `exposed_ports`, `malware`, `monitor_mode`, `agent_outdated`, `no_2fa` | yes | Word it by key; show a generic line for an unknown key. |
| `items[].points` | integer | 0–100 | yes | Points it takes off 100. |
| `items[].detail` | object | | yes | The counts to word it with, by key (e.g. `hardening`: `failed`, `total`; `exposed_ports`: `ports`; `agent_outdated`: `version`, `latest`). Values are numbers, booleans, `null`, text or lists of numbers and text; `{}` when there is nothing to add. Text is at most 64 characters of letters, digits, space and `. _ : / @ + , ( ) -` (the agent refuses an answer with anything else), but HTML-escape it like every other field. |
| `items[].detail.failed` | integer | | no | `hardening`: checks failed. |
| `items[].detail.total` | integer | | no | `hardening`: checks run. |
| `items[].detail.ports` | array of integer | | no | `exposed_ports`: the ports open to the internet. |
| `trend` | array | | yes | Daily scores, oldest first. Empty array when there are none yet. |
| `trend[].day` | string | `YYYY-MM-DD` (UTC) | yes | |
| `trend[].score` | integer | 0–100 | yes | |

Errors: `not_connected`.

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

`map` and `score` when the dashboard has not answered since the agent started (unreachable, or a dashboard
that doesn't offer them yet). An agent older than these commands answers `unknown_command` or
`bad_request`: treat every error the same way, as "no data".

<!-- example:error_not_connected -->
```json
{
  "agent_running": true,
  "error": "not_connected",
  "message": "the InfraFence dashboard has not sent this server's attack map (not reachable, or it does not offer it yet)",
  "ok": false
}
```
<!-- /example:error_not_connected -->

Not entitled to the plugins (see [Paid plans only](#paid-plans-only)): every command but `status`, with no data.
The code says why: `plan_required`, `unpaid` or `unknown`.

<!-- example:error_plan_required -->
```json
{
  "agent_running": true,
  "error": "plan_required",
  "message": "the InfraFence plugin is included in the Basic, Pro and AutoMode plans",
  "ok": false
}
```
<!-- /example:error_plan_required -->

<!-- example:error_unpaid -->
```json
{
  "agent_running": true,
  "error": "unpaid",
  "message": "InfraFence protection is switched off for this server (the dashboard has refused it for 24 hours, e.g. the subscription is not active): the plugin shows no data until it is accepted again",
  "ok": false
}
```
<!-- /example:error_unpaid -->

<!-- example:error_unknown -->
```json
{
  "agent_running": true,
  "error": "unknown",
  "message": "waiting for the InfraFence dashboard: this server's plan is not known yet",
  "ok": false
}
```
<!-- /example:error_unknown -->

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
| `bad_request` | Unknown option, missing or extra argument, invalid `--limit`, `--since`, `--note` or `--hours`, full allow list. |
| `unknown_command` | Not one of the thirteen commands. |
| `plan_required` | Every command but `status`: the organization's plan doesn't include the plugins (e.g. Starter). No data. |
| `unpaid` | Every command but `status`: protection is switched off (refused for 24 hours, e.g. unpaid). No data. |
| `unknown` | Every command but `status`: the plan is not known yet (never synced, or the dashboard doesn't send it). No data. |
| `invalid_ip` | Not exactly one IPv4 or IPv6 address (ranges, ports, zones, `0.0.0.0`, `::`, broadcast and multicast are refused). |
| `invalid_path` | Not a clean absolute path. |
| `invalid_actor` | `--actor` missing on a command that changes something, or not 1–64 of `A–Z a–z 0–9 . _ @ - +`. |
| `not_root` | The command was not run as root. |
| `agent_not_running` | The agent is not running (all commands except `status`, `coexistence`, `sites`; those two answer the entitlement error instead when not entitled). |
| `loopback_address` | `allow`: a loopback address (`127.0.0.0/8`, `::1`); it is never banned and is refused. |
| `not_banned` | `unban`: the address is not banned on this server (or was already lifted). |
| `not_in_allowlist` | `disallow`: the address is not on the allow list. |
| `managed_by_dashboard` | `disallow`: the entry belongs to the organization's allow list in the dashboard. |
| `not_a_document_root` | `scan`: missing, or not the document root of any site. |
| `not_scannable` | `scan`: the site's document root doesn't belong to its account: outside its home, not owned by its uid, a system directory, or the site has no account. |
| `scan_running` | `scan`: a malware scan is already running. |
| `not_connected` | `map`, `score`: the dashboard has not answered since the agent started. |
| `internal_error` | The agent did not answer in time, or could not save the change (nothing was changed). |
