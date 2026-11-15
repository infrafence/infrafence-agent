#!/usr/bin/env bash
# Sends one product tree to pkg.infrafence.com (release workflow side):
# packs DIR/<product> into a tar.gz and pipes it over SSH to the forced
# command "infrafence-deploy pkg-publish <product> <version>"
# (deploy/pkg-publish.sh on the server).
#
#   deploy/pkg-upload.sh <product> <version> <dir containing product/>
#
# Environment (GitHub secrets/variables, see deploy/README.md):
#   PKG_DEPLOY_HOST, PKG_DEPLOY_USER       where to connect (variables)
#   PKG_DEPLOY_SSH_KEY                     private key of the deploy user (secret)
#   PKG_DEPLOY_KNOWN_HOSTS                 the server's host key line(s) (secret or variable)
#   DRY_RUN=1                              pack and check, print the command, send nothing
#   PKG_PUBLISH_CMD                        tests only (ignored on GitHub Actions): a local
#                                          command that reads the tarball on stdin instead of ssh
set -euo pipefail
product=${1:?product}
version=${2:?version}
dir=${3:?directory}
case $product in openwrt | opnsense | site) ;; *) echo "unknown product $product" >&2; exit 1 ;; esac
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$ ]] || { echo "bad version $version" >&2; exit 1; }
[ -d "$dir/$product" ] || { echo "$dir/$product is not a directory" >&2; exit 1; }
if [ -n "$(find "$dir/$product" \( ! -type f ! -type d \) -print -quit)" ]; then
  echo "$dir/$product contains links or special files" >&2; exit 1
fi

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
tb="$work/$product-$version.tar.gz"
# Deterministic, root-owned, no ./ prefix: the server accepts exactly
# "<product>/..." paths.
tar -C "$dir" --sort=name --owner=0 --group=0 --numeric-owner --mtime=@"${SOURCE_DATE_EPOCH:-0}" \
  -cf - "$product" | gzip -9n >"$tb"
echo "pkg-upload: $product $version: $(du -h "$tb" | cut -f1), $(tar -tzf "$tb" | wc -l) entries, sha256 $(sha256sum "$tb" | cut -d' ' -f1)"

remote="infrafence-deploy pkg-publish $product $version"
if [ -n "${PKG_PUBLISH_CMD:-}" ] && [ -z "${GITHUB_ACTIONS:-}" ]; then
  # shellcheck disable=SC2086 # a test command line
  $PKG_PUBLISH_CMD publish "$product" "$version" <"$tb"
  exit
fi
: "${PKG_DEPLOY_HOST:?}" "${PKG_DEPLOY_USER:?}"
if [ "${DRY_RUN:-}" = 1 ]; then
  echo "pkg-upload: dry run: ssh $PKG_DEPLOY_USER@$PKG_DEPLOY_HOST '$remote' < $(basename "$tb")"
  exit 0
fi
: "${PKG_DEPLOY_SSH_KEY:?}" "${PKG_DEPLOY_KNOWN_HOSTS:?}"
umask 077
printf '%s\n' "$PKG_DEPLOY_SSH_KEY" >"$work/id"
printf '%s\n' "$PKG_DEPLOY_KNOWN_HOSTS" >"$work/known_hosts"
ssh -i "$work/id" -o IdentitiesOnly=yes -o BatchMode=yes \
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$work/known_hosts" -o GlobalKnownHostsFile=/dev/null \
  -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o ForwardAgent=no \
  -o ConnectTimeout=30 -o ServerAliveInterval=15 \
  "$PKG_DEPLOY_USER@$PKG_DEPLOY_HOST" "$remote" <"$tb"
