# InfraFence for OPNsense

Two packages:

| Package | Contents |
|---|---|
| `infrafence-agent` | `/usr/local/sbin/infrafence-agent`, the FreeBSD build of the agent. On FreeBSD, `start` runs the appliance loop in `cmd/infrafence-agent/appliance.go`, which uses pf tables, the OPNsense logs and read-only checks. |
| `os-infrafence` | The GUI plugin in `plugin/`, laid out as `security/infrafence` in `opnsense/plugins`. It adds the Services › InfraFence page, configd actions, the rc.d service, the External aliases and the block-only rules. It depends on `infrafence-agent`. |

**Hidden until launch.** Nothing here is published:
- there is no release job
- `.github/workflows/opnsense.yml` only builds and tests, on pull requests and by hand

## What the plugin changes on the firewall

- **Install** creates three aliases of type *External (advanced)*: `infrafence_bans`, `infrafence_threat` and `infrafence_geo`.
  - OPNsense declares their pf tables and never fills or flushes them. A filter reload keeps their contents.
  - This is the only change written to `config.xml`, apart from the plugin's own settings under `OPNsense/infrafence`.
- **Enabled**:
  - The `infrafence_firewall()` hook registers `block in quick from <table>` rules, per table and address family, on the chosen interfaces (WAN by default). They are registered with priority 1, ahead of user rules.
  - The optional *Block LAN to banned* setting adds `block in quick on lan to <infrafence_bans|threat>`.
  - These rules are automatic rules: they are not written to `config.xml` and they go away with the plugin.
  - **No pass rule is ever added.**
- **The agent** writes only the contents of its three tables, through `pfctl -t infrafence_* -T replace|add|delete`.
  - `pf.Ctl` refuses any other table name.
  - The agent never edits `config.xml`, the rules or any other table. AutoMode on the dashboard can only add or remove bans.
  - If the tables are missing (plugin removed, filter not loaded) or pf is disabled, the agent switches to **detect-only** and reports it.
- **Never blocked**, enforced by the agent and written into every table as negated `!addr` entries:
  - private, loopback and reserved ranges
  - the firewall's own addresses and its internal interface networks
  - gateways, DNS servers and VPN peers
  - the dashboard
  - addresses administrators logged in from in the last 30 days
  - the allow list
- **Uninstall** stops the agent, empties the three tables, removes the aliases and reloads the filter.
  - The agent identity in `/usr/local/etc/infrafence/config.json` and the state in `/var/db/infrafence` are kept, so a reinstall keeps the same agent.
  - To remove them too: `rm -r /usr/local/etc/infrafence /var/db/infrafence`.

The install token is used once:
1. The GUI controller writes it to a root-only spool file (`/var/db/infrafence/register.token`, mode 0600).
2. `configd` runs `register.php`, which removes the file and passes the token to `infrafence-agent register --token-stdin`.
3. The token never appears in `config.xml`, in configd parameters or in `argv`.

`config.xml` must stay free of it because it goes into backups, config exports and HA (XMLRPC) sync. That would clone one agent identity onto two firewalls.

## Build

`build-pkgs.sh` needs `pkg(8)`, so run it on FreeBSD or OPNsense. CI runs it in a FreeBSD 14 VM.

```sh
CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.version=1.0.44" \
    -o infrafence-agent ./cmd/infrafence-agent
# on FreeBSD:
sh packaging/opnsense/build-pkgs.sh -b ./infrafence-agent -v 1.0.44 -a amd64 -o ./pkgs
```

- For arm64, use `GOARCH=arm64` and `-a aarch64`.
- The agent package's ABI is `FreeBSD:*:<arch>`, because the binary is static. The plugin's ABI is `FreeBSD:*:*`. The same files therefore serve OPNsense 26.1 (FreeBSD 14) and 26.7 (FreeBSD 15.1; verified in the VM test).
- The plugin's package scripts are generated the way `Mk/plugins.mk` generates them:
  - restart configd
  - run the model migrations
  - `rc.configure_plugins`
  - reload the template
  - the plugin's `.pre` and `.post` parts
- It also installs `/usr/local/opnsense/version/infrafence` and the annotations, so the plugin shows in System › Firmware › Plugins.

## Signed repository

```sh
openssl genrsa -out infrafence-repo.key 4096          # once; keep it as a CI secret (like the cosign key)
openssl rsa -in infrafence-repo.key -pubout -out infrafence-repo.pub
sh packaging/opnsense/make-repo.sh -k infrafence-repo.key -r ./repo -a amd64 pkgs/*.pkg
sh packaging/opnsense/make-repo.sh -k infrafence-repo.key -r ./repo -a aarch64 pkgs-arm64/*.pkg
```

Layout on `https://pkg.infrafence.com` (published by the release workflow, `deploy/README.md`):

```
/opnsense/FreeBSD:14:amd64/latest/{meta.conf,packagesite.pkg,data.pkg,All/*.pkg}
/opnsense/FreeBSD:14:aarch64/latest/...
/opnsense/FreeBSD:15:amd64/latest/...
/opnsense/FreeBSD:15:aarch64/latest/...
/keys/infrafence-repo.pub
/opnsense-install.sh
```

The customer side is `opnsense-install.sh`. It:
1. downloads `infrafence-repo.pub` into `/usr/local/etc/pkg/keys/`
2. writes `/usr/local/etc/pkg/repos/InfraFence.conf` with `signature_type: "pubkey"`
3. runs `pkg update` and `pkg install os-infrafence`

Plugin updates then arrive through System › Firmware like any plugin.

## Publishing at launch

Wired in `release.yml` (job `edge-opnsense`), off until the repository variable `EDGE_PUBLISH` is `true`; see `deploy/README.md`:
1. `deploy/pkg-keygen.sh` creates the key, commits `infrafence-repo.pub` here and sets `KEY_SHA256` in `opnsense-install.sh` (the script refuses to run until then). The private key is the secret `OPNSENSE_REPO_KEY` of the `release` environment.
2. On a tag, the job builds `infrafence-agent-freebsd-{amd64,arm64}`, the packages and the signed repository in a FreeBSD VM, and publishes `opnsense/` to `pkg.infrafence.com`; `edge-site` publishes the key and `opnsense-install.sh`, `edge-assets` attaches the installer to the release.
3. Turn on the dashboard's "Add server → OPNsense" tab (see the dashboard contract).
4. Both `FreeBSD:14:*` (26.1) and `FreeBSD:15:*` (26.7) are published; `make-repo.sh` writes both majors. Watch the roadmap for FreeBSD 16.
5. The plugin version (`build-pkgs.sh -p`, default 0.1) must go up when the plugin changes, or firewalls will not upgrade it.

## Tests

- **Unit tests**:
  - `go test ./internal/pf/... ./internal/opnsense/... ./internal/platform/...`
  - `go test -run 'Appliance|RegisterArgs|RegisterJSON' ./cmd/infrafence-agent/`
- **pf on FreeBSD**: `test/opnsense/pf-freebsd.sh`, run by CI in a disposable VM.
- **OPNsense VM end to end**: `test/opnsense/run.sh`, or `docker-run.sh` on macOS. It:
  - boots the official nano image
  - builds and signs the repository inside it, then installs from it
  - registers against the mock dashboard
  - checks bans, brute force, port scan, IDS, Learning, filter reload, reboot and uninstall

  In CI it runs on demand: Actions › OPNsense › Run workflow › opnsense_vm.

## Licence

The plugin (`packaging/opnsense/plugin/`) is licensed under the BSD 2-Clause License, see
`packaging/opnsense/plugin/LICENSE`, as OPNsense's community plugins require. The InfraFence agent it
installs and runs stays under the repository's licence (BSL 1.1, `LICENSE` at the root).

## Soak test on a shared host

`test/opnsense/soak-remote.sh` runs OPNsense 26.7 with the plugin for days on a Docker host reached over SSH, emulated by QEMU. No KVM is needed. It writes a health line every 10 minutes.

```sh
test/opnsense/soak-remote.sh root@HOST start 7    # build here, upload, start a 7-day soak
test/opnsense/soak-remote.sh root@HOST status     # container, last soak.log and health.log lines
test/opnsense/soak-remote.sh root@HOST stop       # stop (the VM shuts down cleanly); data kept, `start` resumes
test/opnsense/soak-remote.sh root@HOST cleanup    # remove container, image and /srv/opnsense-soak
```

**What it may touch on the host.** Nothing but the container `infrafence-opnsense-soak`, the image `infrafence-opnsense-soak:1` (both labelled `org.infrafence.soak`) and `SOAK_DIR` (default `/srv/opnsense-soak`). That directory is marked with `.infrafence-opnsense-soak`, and `cleanup` refuses to remove a directory without the marker. The host builds and downloads nothing:
- the image, agent, mock dashboard, OPNsense image (SHA-256 pinned) and ET Open rules are prepared on the operator's machine
- they are uploaded with `rsync`, and the image is loaded with `docker load`
- the SSH user must be root or have passwordless sudo

**Isolation and limits.**
- Network: `--network none`. The VM's two NICs use QEMU's user-mode networking. They reach only a mock dashboard (`test/distro/mockapi`) and a file server on the container's own loopback (10.0.2.2 from the VM). There is no Internet access, no host network, no published port, no Docker network and no iptables rule. The production InfraFence cannot be reached even by mistake.
- Limits: `--cpus=3 --memory=6g --memory-swap=6g` (no swap), `--oom-score-adj 1000` (the OOM killer picks it first), `--pids-limit 512`.
- Hardening: read-only root, all capabilities dropped, `no-new-privileges`, and QEMU under `nice 19` with the idle I/O class.
- Restarts: `--restart unless-stopped`. After a host reboot the soak resumes on its persistent disk (`disk.img`), and the end date stays the same.

**What runs in the VM.**
- `os-infrafence` is installed from a locally signed repository built in the VM, and registered against the mock in Full protection. It blocks on WAN.
- Suricata runs in IDS mode on WAN with the uploaded ET Open rules, installed offline.
- Every tick:
  - 6 SSH failures from a new public address, which becomes a ban
  - a port scan in the filter log
  - a WAN fetch that ET Open sid 2100498 alerts on
- A filter reload every 6 h and a VM reboot every 24 h.

**Files in `SOAK_DIR`.**
- `health.log`: one JSON line per tick with three blocks:
  - `vm`: agent alive/pid/RSS/CPU, agent starts and panics, pf tables referenced and their entry counts, protection, Suricata running, eve alerts, VM free memory and load
  - `dashboard`: heartbeats, syncs, bans reported, events by type, agent RSS reported
  - `container`: memory, QEMU alive
- Lines with `"event"` mark QEMU crashes and planned reboots.
- `logs/soak.log` and `run/console.log` (the serial console).

**Settings.** `SOAK_DIR`, `SOAK_CPUS` (3), `SOAK_MEMORY` (6g), `SOAK_VM_MEM` (4096), `SOAK_TICK_SECONDS` (600), `SOAK_REBOOT_HOURS` (24), `SOAK_RELOAD_HOURS` (6). For a short local test:

```sh
SOAK_DIR=$HOME/soak SOAK_MEMORY=3g SOAK_VM_MEM=2304 SOAK_MINUTES=45 SOAK_TICK_SECONDS=120 SOAK_REBOOT_MINUTES=20 \
    test/opnsense/soak-remote.sh local start
```
