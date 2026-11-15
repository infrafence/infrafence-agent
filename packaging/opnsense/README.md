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

Layout, served as static files:

```
repo/FreeBSD:14:amd64/latest/{meta.conf,meta.txz,packagesite.pkg,data.pkg,All/*.pkg}
repo/FreeBSD:14:aarch64/latest/...
repo/FreeBSD:15:amd64/latest/...
repo/FreeBSD:15:aarch64/latest/...
```

The customer side is `opnsense-install.sh`. It:
1. downloads `infrafence-repo.pub` into `/usr/local/etc/pkg/keys/`
2. writes `/usr/local/etc/pkg/repos/InfraFence.conf` with `signature_type: "pubkey"`
3. runs `pkg update` and `pkg install os-infrafence`

Plugin updates then arrive through System › Firmware like any plugin.

## Publishing at launch (not done)

1. Generate the repository key as above. Store the private key as the GitHub secret `OPNSENSE_REPO_KEY`, commit `infrafence-repo.pub` here, and put its SHA-256 into `KEY_SHA256` in `opnsense-install.sh` (the script refuses to run until then).
2. Add a `freebsd` job to `release.yml`. On the tag, it:
   - builds `infrafence-agent-freebsd-{amd64,arm64}`
   - adds both to `checksums.txt` and cosign-signs them like the Linux binaries
   - builds the packages in the FreeBSD VM (as in `opnsense.yml`)
   - runs `make-repo.sh` with the secret
   - uploads `repo/` to the static host
3. Host `pkg.infrafence.com` over HTTPS with:
   - `repo/`
   - `infrafence-repo.pub`
   - `opnsense-install.sh`, served from the tagged commit
4. Turn on the dashboard's "Add server → OPNsense" tab (see the dashboard contract).
5. Publish both `FreeBSD:14:*` (26.1) and `FreeBSD:15:*` (26.7) directories; `make-repo.sh` writes both majors. Watch the roadmap for FreeBSD 16.

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
