# OpenWrt / GL.iNet packages of the router agent

`cmd/infrafence-router` ships as OpenWrt packages from a signed InfraFence feed. Nothing here is published yet: the router agent launches together with the home network check, and until then the release jobs that publish the feed and the installer stay off (`EDGE_PUBLISH`, see `deploy/README.md`).

## Packages

| Package | Contents |
|---|---|
| `infrafence-router` (per arch) | `/usr/sbin/infrafence-router`, procd init `/etc/init.d/infrafence`, UCI `/etc/config/infrafence` (conffile), `/lib/upgrade/keep.d/infrafence` (config and registration survive `sysupgrade`), firewall include `/usr/share/infrafence/firewall.include`. Depends: `ca-bundle`. |
| `luci-app-infrafence` (all) | LuCI page *Services → InfraFence*: enrol with the install token, status, local settings. |
| `infrafence-keyring` (all) | The feed's public keys: `/etc/opkg/keys/<fingerprint>` (usign) and `/etc/apk/keys/infrafence-feed.pem`. |

The agent token is in `/etc/infrafence/config.json` (0600), never in UCI (readable through rpcd). `postinst` adds the firewall include section `firewall.infrafence`, enables and (re)starts the service; `prerm` stops it and removes the firewall table and the DNS list; `postrm` removes the include. `/etc/infrafence` (registration and device-key secret) is **kept on removal**, so a reinstall (after a firmware upgrade, for example) keeps the same agent in the dashboard and the same device keys. To forget the router completely: `rm -rf /etc/infrafence` after removing the package, and delete it in the dashboard. Note that a sysupgrade backup includes `/etc/infrafence` (`keep.d`): restoring it on another router gives that router the same identity.

## Building

```bash
packaging/openwrt/build-binaries.sh build/bin 1.1.0          # mips, mipsle (softfloat), arm (v7), arm64, amd64
USIGN_SEC=... USIGN_PUB=... APK_SEC=... APK_PUB=... \
  packaging/openwrt/build-packages.sh build/bin 1.1.0 build/feed
```

`build-packages.sh` needs Go and Docker (apk-tools 3 from `alpine:3.23` for the `.apk` files and `packages.adb`); the `.ipk` files, the `Packages` index and its usign signature are made by `owrtpkg` (Go, no OpenWrt SDK). `ARCHES="x86_64 mipsel_24kc"` limits the architectures.

Architectures: `mips_24kc mips_mips32` (mips softfloat), `mipsel_24kc mipsel_74kc mipsel_mips32` (mipsle softfloat), `arm_cortex-a7 arm_cortex-a7_neon-vfpv4 arm_cortex-a7_vfpv4 arm_cortex-a8_vfpv3 arm_cortex-a9_neon arm_cortex-a9_vfpv3-d16 arm_cortex-a15_neon-vfpv4` (GOARM=7), `aarch64_cortex-a53 aarch64_cortex-a72 aarch64_cortex-a76 aarch64_generic`, `x86_64`.

## Feed layout

```
https://pkg.infrafence.com/openwrt/
  keys/usign.pub                      usign public key (opkg)
  keys/apk.pem                        EC P-256 public key (apk)
  24.10/<arch>/Packages{,.gz,.sig}    opkg feed: OpenWrt 24.10 and older, GL.iNet 4.x (fw3 or fw4)
  24.10/<arch>/*.ipk
  25.12/<arch>/packages.adb           apk v3 feed: OpenWrt 25.12+
  25.12/<arch>/*.apk
https://pkg.infrafence.com/router-install.sh
```

The "24.10" feed serves every opkg release (21.02–24.10): the agent is one static binary and the packages only depend on `ca-bundle`.

## Keys and publishing

Two signing keys, `OPENWRT_USIGN_KEY` (usign, signs `Packages`) and `OPENWRT_APK_KEY` (EC P-256, signs `.apk` and `packages.adb`), secrets of the `release` environment. `deploy/pkg-keygen.sh` creates them, commits the public halves as `packaging/openwrt/keys/usign.pub` and `packaging/openwrt/keys/apk.pem` (they go into `infrafence-keyring` and to `keys/` on the feed) and pins them in `router-install.sh` (`USIGN_FP`, `APK_KEY_SHA256`). A key rotation ships a new `infrafence-keyring` with both public keys first, then switches the signing key.

The release workflow's `edge-openwrt` job builds and signs the feed on every tag and publishes it to `pkg.infrafence.com` (`deploy/README.md`); `edge-site` publishes the installer and the keys, `edge-assets` attaches the installer to the GitHub release. All of it is off until the repository variable `EDGE_PUBLISH` is `true`.

## Launch

1. Keys (above), secrets and server: `deploy/README.md`.
2. Dashboard: the router contract (`agents.kind`, router sync, domain list endpoint, device endpoint, events, "Add router" page) live first — the dashboard is released before the agent, as in RELEASING.md.
3. Docs, in the launch pull request only (not before: the product is hidden until launch): the `CHANGELOG.md` entry, the READMEs (5 languages) and the site: requirements (16 MB flash with 4 MB free, 128 MB RAM), the one-liner, LuCI, GL.iNet *Applications → Plug-ins* (the installer adds the feed to `customfeeds.conf`), "after a firmware upgrade, run the one-liner again".
4. Set `EDGE_PUBLISH=true` and tag the release.
5. GL.iNet: ask for a listing in their plug-in catalogue once the feed is stable.

Until then `router.yml` builds packages with throwaway keys on pull requests and manual runs, and uploads them as workflow artifacts only.

## Installer

`router-install.sh` (published as `https://pkg.infrafence.com/router-install.sh`): checks OpenWrt, opkg/apk, the architecture, ≥ 4 MB free flash and ≥ 100 MB RAM, fw4/fw3 (installs `ipset kmod-ipt-ipset` on fw3), adds the feed key and the feed (`/etc/opkg/customfeeds.conf` or `/etc/apk/repositories.d/infrafence.list`), installs the packages and enrols with `--token`. `--feed URL` points it at another feed (the QEMU test uses the mock dashboard's); the default feed's keys are pinned, another feed's key is trusted as served over HTTPS (plain HTTP is refused unless `INFRAFENCE_ALLOW_HTTP_FEED=1`, for the test).
