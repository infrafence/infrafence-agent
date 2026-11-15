# Edge package publishing (pkg.infrafence.com)

The router agent (OpenWrt, GL.iNet) and the OPNsense plugin are installed from signed package repositories on `https://pkg.infrafence.com`, our production server: Traefik (the Coolify proxy) terminates TLS with Let's Encrypt and forwards to the container `infrafence-pkg` (`nginx:1.27-alpine`, read-only), which serves `/srv/infrafence-pkg` from a read-only bind mount. The release workflow builds and signs the packages and sends them there over SSH.

**Off until the edge launch.** The four `edge-*` jobs in `.github/workflows/release.yml` run only when the repository variable `EDGE_PUBLISH` is `true` (and on plain `vX.Y.Z` tags). Until the owner sets it, a release is exactly what it was before.

## What is served

```
https://pkg.infrafence.com/
  index.html                          keys, fingerprints, the one-liners
  keys/usign.pub                      OpenWrt opkg feed key (usign, Ed25519)
  keys/apk.pem                        OpenWrt apk feed key (EC P-256)
  keys/infrafence-repo.pub            OPNsense pkg repository key (RSA 4096)
  router-install.sh                   OpenWrt / GL.iNet installer
  opnsense-install.sh                 OPNsense installer
  openwrt/keys/{usign.pub,apk.pem}
  openwrt/24.10/<arch>/               opkg feed: Packages, Packages.gz, Packages.sig, *.ipk
  openwrt/25.12/<arch>/               apk v3 feed: packages.adb, *.apk
  opnsense/FreeBSD:{14,15}:{amd64,aarch64}/latest/   pkg repository: meta.conf, packagesite.pkg, data.pkg, All/*.pkg
```

The "channel" of the OpenWrt feed is the package manager generation: `24.10` serves every opkg release (21.02 to 24.10, GL.iNet 4.x), `25.12` the apk releases. pkg(8) names the 64-bit ARM ABI `aarch64` (`FreeBSD:14:aarch64`), not `arm64`.

## The release jobs

| Job | Does | Publishes |
|---|---|---|
| `edge-openwrt` | `packaging/openwrt/build-binaries.sh`, `build-packages.sh` with the release keys (checked against the committed public keys first) | product `openwrt` |
| `edge-opnsense` | FreeBSD binaries, `packaging/opnsense/build-pkgs.sh` and `make-repo.sh` in a FreeBSD 14.3 VM | product `opnsense` |
| `edge-site` | `deploy/pkg-site.sh`: index page, public keys, installers | product `site` |
| `edge-assets` | `router-install.sh` and `opnsense-install.sh` with `.sha256` and cosign `.sig`, attached to the GitHub release | - |

Each product goes up as one tarball: `deploy/pkg-upload.sh` packs `<product>/` and pipes it to `ssh <user>@<host> "infrafence-deploy pkg-publish <product> <version>"`, with the server's host key pinned (`StrictHostKeyChecking=yes`). `edge-opnsense` also checks that `packaging/opnsense/infrafence-repo.pub` is committed (`deploy/pkg-keygen.sh`) and fails with a clear error until then.

## Secrets and variables

Repository **variables** (Settings → Secrets and variables → Actions → Variables):

| Variable | Value |
|---|---|
| `EDGE_PUBLISH` | `true` to turn publishing on. A repository variable, not an environment one: the jobs' `if:` is evaluated before the environment applies. |
| `PKG_DEPLOY_HOST` | the server's SSH address (`pkg.infrafence.com` or its IP) |
| `PKG_DEPLOY_USER` | `pkgpub` |
| `PKG_DEPLOY_KNOWN_HOSTS` | the server's host key line, `pkg.infrafence.com ssh-ed25519 AAAA...` (public, checked against the server's own `/etc/ssh/ssh_host_ed25519_key.pub`) |

**Secrets** of the environment `release` (Settings → Environments → release). Add required reviewers and allow only `v*` tags (deployment branches and tags): otherwise anyone who can push a branch could run a modified workflow with these secrets.

| Secret | What | Created by |
|---|---|---|
| `OPENWRT_USIGN_KEY` | usign secret key, signs the opkg `Packages` | `deploy/pkg-keygen.sh` (`openwrt-usign.sec`) |
| `OPENWRT_APK_KEY` | EC P-256 private key (PEM), signs the `.apk` and `packages.adb` | `deploy/pkg-keygen.sh` (`openwrt-apk.sec`) |
| `OPNSENSE_REPO_KEY` | RSA 4096 private key (PEM), signs the pkg repository | `deploy/pkg-keygen.sh` (`opnsense-repo.key`) |
| `PKG_DEPLOY_SSH_KEY` | private SSH key of `pkgpub` on the server (ed25519, no passphrase) | `ssh-keygen -t ed25519 -N '' -C github-actions-pkg-publish -f pkg_deploy` |

`edge-assets` uses the existing repository secrets `COSIGN_PRIVATE_KEY` and `COSIGN_PASSWORD`.

## Keys

`deploy/pkg-keygen.sh OUTDIR` (OUTDIR outside the repository, new) creates the three key pairs once:
- writes the private keys to OUTDIR only (0600) and prints the `gh secret set ... < file` commands; nothing secret is printed;
- copies the public keys to `packaging/openwrt/keys/usign.pub`, `packaging/openwrt/keys/apk.pem` and `packaging/opnsense/infrafence-repo.pub`;
- pins them in the installers: `USIGN_FP` and `APK_KEY_SHA256` in `router-install.sh`, `KEY_SHA256` in `opnsense-install.sh`.

Commit the public keys and the pins in the launch pull request, store the secrets, copy the three public files to the server's `/etc/infrafence/pkg-keys/`, then delete OUTDIR (an offline backup is optional: losing a key means a rotation, not an outage). The installers refuse the default feed until the pins are set; `router-install.sh --feed URL` (tests, mirrors) trusts the key that feed serves.

Rotation: ship the new public key next to the old one first (`infrafence-keyring`, the server's pinned keys, the installers' pins), then switch the secret.

## Server side: `pkg-publish.sh`

`deploy/pkg-publish.sh` is the `pkg-publish` subcommand of the forced command `/usr/local/bin/infrafence-deploy`. On every upload it:
1. reads the upload within 15 minutes before taking the lock, and caps it (300 MiB), its unpacked size (1 GiB, decompressed once) and the entries (20000);
2. checks the tar listing before writing anything: no absolute path, no `..` or `.` component, no backslash or control character, only regular files and directories (no symlink, hard link, device or FIFO), and only the paths and file names the product may contain;
3. extracts into a staging directory and checks it again on disk;
4. checks the content against what is pinned on the server (`/etc/infrafence/pkg-keys/`):
   - OpenWrt: `Packages.sig` verified with OpenSSL (Ed25519) against the pinned usign key, `Packages.gz` equal to `Packages`, every listed `.ipk` present with the size and SHA-256 the signed index gives, the version matching, `packages.adb` and `.apk` present, the shipped public keys equal to the pinned ones;
   - OPNsense: `meta.conf`, `packagesite`, `os-infrafence` and `infrafence-agent-<version>.pkg` in every ABI (the repository signature is checked by pkg(8) on the firewalls, against the key pinned by `opnsense-install.sh`; apk checks `packages.adb` the same way);
   - site: the keys equal to the pinned ones, and `index.html` and the installers equal to the SHA-256 sums in `site.sha256`. The installers run as root on customer devices and carry the key pins, so the CI deploy key alone cannot change them: when an installer changes, the reviewed sums (printed by `deploy/pkg-site.sh`, `build/pkgroot/site.sha256` in the job log) are copied to the server by hand;
5. refuses a release older than the published one (old signed releases are public and could be replayed; `PKG_ALLOW_DOWNGRADE=1` to allow) and one that drops a channel, architecture or ABI the current one has (`PKG_ALLOW_REMOVAL=1`);
6. links the current release's package files into the new one (not into its indexes), so a router or firewall that read the old index a moment ago still finds them;
7. switches `www/<product>` to the new release with an atomic `rename(2)` of a symlink, keeps the last 3 releases and removes older ones.

```
/srv/infrafence-pkg-releases/<product>/<UTC stamp>-<version>/<product>/...   releases (last 3), not served
/srv/infrafence-pkg-releases/{.lock,.work.*,<product>/.staging-*}           publish in progress
/srv/infrafence-pkg/<product> -> /srv/infrafence-pkg-releases/<product>/<id>/<product>
/srv/infrafence-pkg/{index.html,keys,router-install.sh,opnsense-install.sh} -> site/...
```

The web root (`PKG_WWW`, the container's `/usr/share/nginx/html`) only holds symlinks, replaced with `rename(2)`: nginx follows them on every request, so a new release or a rollback is served on the next request without restarting or reloading the container, and a request never sees a half-written release (`deploy/test/pkg-serve-test.sh` checks this against a read-only `nginx:1.27-alpine`).

Because the links point outside the web root, the container must see the releases directory **at the same path**: one more read-only bind mount, `/srv/infrafence-pkg-releases:/srv/infrafence-pkg-releases:ro`. Without it every product URL is a 404 (also checked by the test). If the container cannot get a second mount, set `PKG_RELEASES=/srv/infrafence-pkg/.releases`: the links become relative, the one existing mount is enough, and the dotfile rule keeps `/.releases/` unreachable (also tested).

By hand on the server, as `pkgpub`:

```
/usr/local/lib/infrafence/pkg-publish.sh status
/usr/local/lib/infrafence/pkg-publish.sh rollback openwrt     # back to the previous release
```

Needs bash, GNU tar, gzip, coreutils, `flock` and OpenSSL 3 (Debian/Ubuntu have them). Settings by environment: `PKG_WWW` (`/srv/infrafence-pkg`), `PKG_RELEASES` (`/srv/infrafence-pkg-releases`), `PKG_KEYS_DIR` (`/etc/infrafence/pkg-keys`), `PKG_MAX_BYTES`, `PKG_MAX_UNPACKED`, `PKG_MAX_ENTRIES`, `PKG_KEEP`, `PKG_READ_TIMEOUT`.

The CI key must only reach this command: in `~pkgpub/.ssh/authorized_keys`, `restrict,command="/usr/local/bin/infrafence-deploy" ssh-ed25519 AAAA... github-actions-pkg-publish` (or `command="/usr/local/lib/infrafence/pkg-publish.sh"`, which reads `SSH_ORIGINAL_COMMAND` itself and accepts only `[infrafence-deploy] pkg-publish <product> <version>`). Without `command=` the key is a shell.

`nginx-pkg-additions.conf` holds the rules to add to the container's `/srv/infrafence-pkg-conf/default.conf`, **after** its dotfile rule: GET/HEAD only; `application/octet-stream` for indexes and packages (nginx's `mime.types` would send `.apk` as an Android package); `text/plain` for installers and keys; indexes, signatures, installers and keys `no-cache`; packages cached a day. TLS, certificates and HSTS stay with Traefik.

## Tests

```
deploy/test/pkg-publish-test.sh   # good and malicious tarballs against pkg-publish.sh (in a Debian container on macOS)
deploy/test/pkg-serve-test.sh     # publish, new release and rollback served by a read-only nginx:1.27-alpine like the live one
deploy/test/edge-dry-run.sh       # the workflow: actionlint, guards, and the real run: blocks of edge-openwrt and edge-site
                                  # with throwaway keys, published into a temporary server tree
shellcheck deploy/*.sh deploy/test/*.sh
```
