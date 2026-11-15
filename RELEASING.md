# Releasing the InfraFence Agent

One release a month, plus security fixes as soon as they are ready. Every change reaches `main` through a pull request.

## Monthly release

1. **Dependencies.** At the start of the month Dependabot opens one grouped pull request per ecosystem (Go modules, GitHub Actions, Docker). The distribution matrix runs on the Go and Docker ones; for an Actions update, read the release notes of each new major version (runtime, removed inputs) before merging.
2. **Changes.** Every feature or fix pull request passes the distribution matrix on all 15 distributions (`test/distro/run.sh`) and adds its entry under `## Unreleased` in `CHANGELOG.md`, with the docs (READMEs, site docs) in the same pull request.
3. **Dashboard first.** When the release needs a dashboard change (a new field, endpoint or migration), the dashboard is released before the agent. Old dashboards must keep working with the new agent, and old agents with the new dashboard.
4. **Release pull request.** Rename `## Unreleased` to `## vX.Y.Z` in `CHANGELOG.md`. If `main` changed since the last full matrix run, run the Distro matrix workflow on `main` (Actions → Distro matrix → Run workflow) and link the run.
5. **Tag.** After the merge, tag the merge commit and push the tag:

   ```
   git fetch origin
   git tag vX.Y.Z origin/main
   git push origin vX.Y.Z
   ```

   The Release workflow builds the binaries and the image, signs them with cosign and publishes the GitHub release.
6. **Verify.** Download the assets and check `checksums.txt` and the signatures:

   ```
   sha256sum -c checksums.txt
   cosign verify-blob --key cosign.pub --signature checksums.txt.sig --insecure-ignore-tlog=true checksums.txt
   ```

   (and the same for each binary).
7. **Roll out.** Update the internal servers first, then customers update from the dashboard or by automatic updates.

## Edge launch

Once, for the first release that publishes the router agent (OpenWrt, GL.iNet) and the OPNsense firewall agent and plugin to `https://pkg.infrafence.com`. Until step 5 a release is exactly a Linux release. Details: `deploy/README.md`, `packaging/openwrt/README.md`, `packaging/opnsense/README.md`.

1. **Dashboard first.** The router and firewall contract is live (`agents.kind`, router sync, domain list and device endpoints, events) with the "Add server → Router (OpenWrt / GL.iNet)" and "Add server → OPNsense" tabs still hidden; the site's router and OPNsense docs pages are ready to go public.
2. **Keys.** On a trusted machine, from an up-to-date checkout of `main`: `deploy/pkg-keygen.sh OUTDIR` (OUTDIR new, outside the repository). It writes the three private keys to OUTDIR only, copies the public keys to `packaging/openwrt/keys/usign.pub`, `packaging/openwrt/keys/apk.pem` and `packaging/opnsense/infrafence-repo.pub`, and sets the pins in the installers (`USIGN_FP`, `APK_KEY_SHA256` in `router-install.sh`, `KEY_SHA256` in `opnsense-install.sh`). Commit the public keys and the pins in the launch pull request, with the `CHANGELOG.md` entry, the READMEs and the site docs.
3. **Secrets and variables.** Run the `gh secret set ... --env release` lines `pkg-keygen.sh` prints (`OPENWRT_USIGN_KEY`, `OPENWRT_APK_KEY`, `OPNSENSE_REPO_KEY`), then `ssh-keygen -t ed25519 -N '' -C github-actions-pkg-publish -f pkg_deploy` and store `pkg_deploy` as `PKG_DEPLOY_SSH_KEY` in the same environment. The `release` environment has required reviewers and allows only `v*` tags. Repository variables: `PKG_DEPLOY_HOST`, `PKG_DEPLOY_USER` (`pkgpub`), `PKG_DEPLOY_KNOWN_HOSTS` (the server's ed25519 host key line, checked against its `/etc/ssh/ssh_host_ed25519_key.pub`). Leave `EDGE_PUBLISH` unset for now.
4. **Server.** On `pkg.infrafence.com`:
   - user `pkgpub`; `pkg_deploy.pub` in `~pkgpub/.ssh/authorized_keys` as `restrict,command="/usr/local/bin/infrafence-deploy" ssh-ed25519 AAAA... github-actions-pkg-publish` (never without `command=`);
   - `deploy/pkg-publish.sh` installed as `/usr/local/lib/infrafence/pkg-publish.sh`, reached through the `pkg-publish` subcommand of `/usr/local/bin/infrafence-deploy`;
   - the three public keys (`usign.pub`, `apk.pem`, `infrafence-repo.pub`) in `/etc/infrafence/pkg-keys/`, and `site.sha256` there too: run `deploy/pkg-site.sh OUTDIR vX.Y.Z` on the merged launch commit, review the installers, copy `OUTDIR/site.sha256`. Then delete the keygen OUTDIR;
   - the `infrafence-pkg` container (`nginx:1.27-alpine`, read-only) behind Traefik for `pkg.infrafence.com`, with `/srv/infrafence-pkg` and `/srv/infrafence-pkg-releases` bind-mounted read-only at the same paths, and the rules of `deploy/nginx-pkg-additions.conf` after the dotfile rule.
   - Check: `/usr/local/lib/infrafence/pkg-publish.sh status` as `pkgpub`, and `deploy/test/edge-dry-run.sh` locally.
5. **Turn it on.** Set the repository variable `EDGE_PUBLISH` to `true`.
6. **First tag.** Release as in the monthly release (steps 4 and 5): the plain `vX.Y.Z` tag runs `edge-openwrt`, `edge-opnsense`, `edge-site` and `edge-assets` next to the usual jobs (pre-release tags never publish). Approve the `release` environment when asked.
7. **Verify.**
   - The usual checks of the GitHub release, plus `router-install.sh` and `opnsense-install.sh` against their `.sha256` and cosign `.sig`.
   - `https://pkg.infrafence.com/` shows the keys with the same SHA-256 as the committed public keys; `pkg-publish.sh status` lists `openwrt`, `opnsense` and `site` at the new version.
   - A real install of each: an OpenWrt 24.10 router (opkg), an OpenWrt 25.12 router (apk), a GL.iNet router (*Applications → Plug-ins* after the one-liner), an OPNsense 26.1 and a 26.7 firewall (the plugin then shows in *System → Firmware → Plugins*). Each one enrols, appears in the dashboard within a minute in Learning, and reports a test event.
   - Then publish the dashboard tabs and the site pages.
8. **Rollback.**
   - A bad edge release: on the server, as `pkgpub`, `/usr/local/lib/infrafence/pkg-publish.sh rollback <openwrt|opnsense|site>` serves the previous release on the next request (the last 3 are kept). The fix is a new, higher version: the server refuses to publish an older one.
   - Stop publishing: set `EDGE_PUBLISH` back to `false`; Linux releases go on unchanged. Routers and firewalls already installed keep the packages they have.
   - A leaked signing key: rotate as in `deploy/README.md` (new public key next to the old one first, in `infrafence-keyring`, on the server and in the installers' pins, then switch the secret).
9. **After launch.** Ask GL.iNet for a listing in their plug-in catalogue once the feed is stable. Raise the plugin version (`build-pkgs.sh -p`) whenever the plugin changes, or firewalls will not upgrade it. Watch the OPNsense roadmap for FreeBSD 16.

## Security fixes

Dependabot alerts and security updates are on for this repository: a vulnerable dependency gets its own pull request as soon as an advisory is published, outside the monthly schedule. Same steps, without waiting for the end of the month: a pull request with the fix and its test, the matrix on all distributions, a patch release.
