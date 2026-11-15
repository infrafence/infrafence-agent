#!/usr/bin/env bash
# Publishes one edge package release on pkg.infrafence.com (the server side
# of the release workflow's "publish" jobs).
#
#   pkg-publish.sh publish <product> <version>  < release.tar.gz
#   pkg-publish.sh rollback <product>           back to the previous release
#   pkg-publish.sh status [<product>]
#
# Products and what their tarball must contain (one top directory, named
# after the product):
#   openwrt   openwrt/{24.10,25.12}/<arch>/...  opkg feed (Packages, .gz, .sig
#             signed with usign) and apk v3 feed (packages.adb), plus
#             openwrt/keys/{usign.pub,apk.pem}
#   opnsense  opnsense/FreeBSD:<major>:<amd64|aarch64>/latest/...  signed pkg
#             repository (meta.conf, packagesite.pkg, All/*.pkg)
#   site      site/index.html, site/keys/*, site/{router,opnsense}-install.sh
#
# Called through the SSH forced command (infrafence-deploy pkg-publish ...),
# or directly with SSH_ORIGINAL_COMMAND set and no arguments. It never
# trusts the tarball: size caps, a strict listing check before anything is
# written (no absolute paths, no "..", no links or devices, only the
# expected directories and file names), extraction into a staging
# directory, checks of the indexes and signatures against the public keys
# pinned on this server (and, for the site, its pinned SHA-256 sums), no
# downgrade, then an atomic switch of the product's symlink.
# The previous releases stay on disk for "rollback".
#
# Layout:
#   PKG_RELEASES (default /srv/infrafence-pkg-releases, not served)
#     <product>/<UTC stamp>-<version>/<product>/...   the releases
#     .lock, .work.*, <product>/.staging-*            publish in progress
#   PKG_WWW (default /srv/infrafence-pkg, the web root, served read-only)
#     <product> -> PKG_RELEASES/<product>/<id>/<product>
#     {index.html,keys,router-install.sh,opnsense-install.sh} -> site/...
# The product entries are symlinks replaced with rename(2): the web server
# sees the new release on the next request, and never a half-written one.
# Outside PKG_WWW the links are absolute, so the web server must see
# PKG_RELEASES at the same path (an extra read-only bind mount of the same
# directory); with PKG_RELEASES inside PKG_WWW (a dot directory such as
# PKG_WWW/.releases, hidden by the dotfile rule) they are relative and the
# one bind mount of PKG_WWW is enough.
#
# Needs bash, GNU tar, gzip, coreutils, flock and OpenSSL 3.
set -euo pipefail
umask 022
export LC_ALL=C

PKG_WWW=${PKG_WWW:-/srv/infrafence-pkg}
PKG_RELEASES=${PKG_RELEASES:-/srv/infrafence-pkg-releases}
PKG_KEYS_DIR=${PKG_KEYS_DIR:-/etc/infrafence/pkg-keys}
PKG_MAX_BYTES=${PKG_MAX_BYTES:-314572800}        # 300 MiB compressed
PKG_MAX_UNPACKED=${PKG_MAX_UNPACKED:-1073741824} # 1 GiB unpacked
PKG_MAX_ENTRIES=${PKG_MAX_ENTRIES:-20000}
PKG_KEEP=${PKG_KEEP:-3}                          # releases kept per product
PKG_ALLOW_REMOVAL=${PKG_ALLOW_REMOVAL:-0}        # 1: a release may drop a channel/arch/ABI
PKG_ALLOW_DOWNGRADE=${PKG_ALLOW_DOWNGRADE:-0}    # 1: a release may be older than the current one
PKG_READ_TIMEOUT=${PKG_READ_TIMEOUT:-900}        # seconds to receive the upload

work="" stage="" # globals: the EXIT trap removes them
cleanup() { rm -rf -- ${work:+"$work"} ${stage:+"$stage"}; }
die() { echo "pkg-publish: error: $*" >&2; exit 1; }
say() { echo "pkg-publish: $*"; }

valid_product() { case $1 in openwrt | opnsense | site) return 0 ;; *) return 1 ;; esac; }
valid_version() { [ ${#1} -le 40 ] && [[ $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$ ]]; }
valid_id() { [[ $1 =~ ^[0-9]{8}T[0-9]{6}Z(-[0-9]+)?-[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$ ]]; }

# The allowed paths of each product. A directory entry may end with "/".
NAME_CHARS='[A-Za-z0-9._+-]+'
name_ok() { # product path
  local p=${2%/}
  case $1 in
  openwrt)
    [[ $p =~ ^openwrt(/keys(/(usign\.pub|apk\.pem))?)?$ ]] ||
      [[ $p =~ ^openwrt/24\.10(/[a-z0-9_-]+(/(Packages|Packages\.gz|Packages\.sig|${NAME_CHARS}\.ipk))?)?$ ]] ||
      [[ $p =~ ^openwrt/25\.12(/[a-z0-9_-]+(/(packages\.adb|${NAME_CHARS}\.apk))?)?$ ]]
    ;;
  opnsense)
    [[ $p =~ ^opnsense(/FreeBSD:1[0-9]:(amd64|aarch64)(/latest(/All(/${NAME_CHARS}\.pkg)?|/(meta\.conf|meta|meta\.txz|meta\.pkg|packagesite\.pkg|packagesite\.txz|packagesite\.tzst|data\.pkg|data\.txz|data\.tzst|filesite\.pkg|filesite\.txz|digests\.pkg|digests\.txz))?)?)?$ ]]
    ;;
  site)
    [[ $p =~ ^site(/(index\.html|router-install\.sh|opnsense-install\.sh|keys(/(usign\.pub|apk\.pem|infrafence-repo\.pub))?))?$ ]]
    ;;
  esac
}

# The usign signature of an opkg index, checked with OpenSSL (Ed25519):
#   public key "Ed" | keynum[8] | key[32], signature "Ed" | keynum[8] | sig[64]
b64line_hex() { sed -n 2p "$1" | base64 -d 2>/dev/null | od -An -tx1 -v | tr -d ' \n'; }
hex_to_file() { printf '%b' "$(printf '%s' "$1" | sed 's/../\\x&/g')" >"$2"; }
usign_verify() { # pub msg (msg.sig next to it)
  local p s
  p=$(b64line_hex "$1") || return 1
  s=$(b64line_hex "$2.sig") || return 1
  [ ${#p} -eq 84 ] && [ ${#s} -eq 148 ] || return 1
  [ "${p:0:4}" = 4564 ] && [ "${s:0:4}" = 4564 ] || return 1 # "Ed"
  [ "${p:4:16}" = "${s:4:16}" ] || return 1                  # same key number
  hex_to_file "302a300506032b6570032100${p:20}" "$work/ed25519.der"
  hex_to_file "${s:20}" "$work/ed25519.sig"
  openssl pkeyutl -verify -pubin -keyform DER -inkey "$work/ed25519.der" -rawin \
    -in "$2" -sigfile "$work/ed25519.sig" >/dev/null 2>&1
}

pinned() { # name: the pinned public key on this server, or die
  [ -s "$PKG_KEYS_DIR/$1" ] || die "no pinned key $PKG_KEYS_DIR/$1 on this server (install the public keys first)"
  echo "$PKG_KEYS_DIR/$1"
}

current_target() { # product: the release directory www/<product> points to (or empty)
  local l="$PKG_WWW/$1"
  [ -L "$l" ] || return 0
  readlink -f "$l"
}

# The channel/arch (openwrt) or ABI (opnsense) directories of a tree.
subdirs() { # product tree
  case $1 in
  openwrt) (cd "$2" && find 24.10 25.12 -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort) ;;
  opnsense) (cd "$2" && find . -mindepth 1 -maxdepth 1 -type d -name 'FreeBSD:*' 2>/dev/null | sed 's#^\./##' | sort) ;;
  site) : ;;
  esac
}

verify_openwrt() { # tree version
  local t=$1 v=$2 usign apk d f n=0
  usign=$(pinned usign.pub); apk=$(pinned apk.pem)
  cmp -s "$t/keys/usign.pub" "$usign" || die "openwrt/keys/usign.pub is not the pinned usign key"
  cmp -s "$t/keys/apk.pem" "$apk" || die "openwrt/keys/apk.pem is not the pinned apk key"
  for d in "$t"/24.10/*/; do
    [ -d "$d" ] || continue
    d=${d%/}
    for f in Packages Packages.gz Packages.sig; do [ -s "$d/$f" ] || die "${d#"$t"/}: $f missing"; done
    usign_verify "$usign" "$d/Packages" || die "${d#"$t"/}/Packages: bad usign signature"
    gzip -dc "$d/Packages.gz" | cmp -s - "$d/Packages" || die "${d#"$t"/}: Packages.gz differs from Packages"
    grep -q '^Filename: ' "$d/Packages" || die "${d#"$t"/}/Packages lists no package"
    # Every package the signed index lists, with its size and SHA-256.
    local fsize fsum
    while read -r f fsize fsum; do
      [[ $f =~ ^${NAME_CHARS}\.ipk$ ]] && [ -s "$d/$f" ] || die "${d#"$t"/}: $f is in Packages but missing"
      [ "$(stat -c %s "$d/$f")" = "$fsize" ] || die "${d#"$t"/}/$f: size differs from Packages"
      [ "$(sha256sum "$d/$f" | cut -d' ' -f1)" = "$fsum" ] || die "${d#"$t"/}/$f: SHA-256 differs from Packages"
    done < <(awk '/^Filename: /{f=$2} /^Size: /{z=$2} /^SHA256sum: /{h=$2} /^$/{if(f!="")print f, z, h; f=z=h=""} END{if(f!="")print f, z, h}' "$d/Packages")
    if [[ $v =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      grep -qx "Version: $v-r1" "$d/Packages" || die "${d#"$t"/}: no package with version $v-r1"
    fi
    n=$((n + 1))
  done
  [ "$n" -gt 0 ] || die "openwrt: no opkg feed (24.10/<arch>)"
  n=0
  for d in "$t"/25.12/*/; do
    [ -d "$d" ] || continue
    d=${d%/}
    [ -s "$d/packages.adb" ] || die "${d#"$t"/}: packages.adb missing"
    compgen -G "$d/*.apk" >/dev/null || die "${d#"$t"/}: no .apk"
    n=$((n + 1))
  done
  [ "$n" -gt 0 ] || die "openwrt: no apk feed (25.12/<arch>)"
}

verify_opnsense() { # tree version
  local t=$1 v=$2 d n=0
  for d in "$t"/FreeBSD:*/; do
    [ -d "$d" ] || continue
    d=${d%/}/latest
    [ -s "$d/meta.conf" ] || die "${d#"$t"/}: meta.conf missing"
    [ -s "$d/packagesite.pkg" ] || [ -s "$d/packagesite.txz" ] || [ -s "$d/packagesite.tzst" ] ||
      die "${d#"$t"/}: packagesite missing"
    compgen -G "$d/All/*.pkg" >/dev/null || die "${d#"$t"/}: no package in All/"
    compgen -G "$d/All/os-infrafence-*.pkg" >/dev/null || die "${d#"$t"/}: os-infrafence missing"
    if [[ $v =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      [ -s "$d/All/infrafence-agent-$v.pkg" ] || die "${d#"$t"/}: infrafence-agent-$v.pkg missing"
    fi
    n=$((n + 1))
  done
  [ "$n" -gt 0 ] || die "opnsense: no repository (FreeBSD:<major>:<arch>/latest)"
}

# The site's index page and installers run as root on customer devices
# (wget | sh) and carry the key pins: they must match the SHA-256 sums
# pinned on this server (PKG_KEYS_DIR/site.sha256, sha256sum format, set by
# hand from the reviewed release), so the CI deploy key alone cannot change
# them.
verify_site() { # tree
  local t=$1 f n want got pins
  [ -s "$t/index.html" ] || die "site/index.html missing"
  pins=$(pinned site.sha256)
  for f in "$t"/index.html "$t"/*.sh; do
    [ -e "$f" ] || continue
    n=${f##*/}
    want=$(awk -v n="$n" '$2 == n || $2 == "*" n {print $1}' "$pins")
    got=$(sha256sum "$f" | cut -d' ' -f1)
    [ -n "$want" ] || die "site/$n is not pinned in $pins"
    [ "$want" = "$got" ] || die "site/$n ($got) does not match its pinned SHA-256 in $pins"
  done
  [ -d "$t/keys" ] || die "site/keys missing"
  compgen -G "$t/keys/*" >/dev/null || die "site/keys is empty"
  for f in "$t"/keys/*; do
    cmp -s "$f" "$(pinned "$(basename "$f")")" || die "site/keys/$(basename "$f") is not the pinned key"
  done
}

# Package files of the current release are linked into the new one (not
# into its indexes): a router or firewall that read the old index a moment
# ago still finds the files it lists. Only the current release's own files
# are carried, one release back.
carry_over() { # product cur_tree new_tree new_list
  local f
  case $1 in
  openwrt) (cd "$2" && find 24.10 25.12 -mindepth 2 -maxdepth 2 -type f \( -name '*.ipk' -o -name '*.apk' \) 2>/dev/null) ;;
  opnsense) (cd "$2" && find . -mindepth 4 -maxdepth 4 -type f -path './FreeBSD:*/latest/All/*.pkg' | sed 's#^\./##') ;;
  *) return 0 ;;
  esac | sort >"$work/cur-files"
  [ -s "$work/cur-files" ] || return 0
  local carried="${2%/*}.carried"
  if [ -f "$carried" ]; then
    sort "$carried" | comm -23 "$work/cur-files" - >"$work/own"
  else
    cp "$work/cur-files" "$work/own"
  fi
  : >"$4"
  while IFS= read -r f; do
    [ -e "$3/$f" ] && continue
    [ -d "$3/$(dirname "$f")" ] || continue
    ln "$2/$f" "$3/$f" 2>/dev/null || cp -p "$2/$f" "$3/$f"
    echo "$f" >>"$4"
  done <"$work/own"
}

# The symlink target of a release, as the web server must resolve it.
link_target() { # product id
  local abs="$PKG_RELEASES/$1/$2/$1"
  case $PKG_RELEASES/ in
  "$PKG_WWW"/*) echo "${abs#"$PKG_WWW"/}" ;;
  *) echo "$abs" ;;
  esac
}

switch_to() { # product id
  local l="$PKG_WWW/$1" target
  [ ! -e "$l" ] || [ -L "$l" ] || die "$l exists and is not a symlink: move it away first"
  target=$(link_target "$1" "$2")
  rm -f -- "$PKG_WWW/.$1.new"
  ln -s "$target" "$PKG_WWW/.$1.new"
  mv -Tf "$PKG_WWW/.$1.new" "$l"
  if [ "$1" = site ]; then
    local n
    for n in index.html keys router-install.sh opnsense-install.sh; do
      if [ -L "$PKG_WWW/$n" ]; then continue; fi
      if [ -e "$PKG_WWW/$n" ]; then say "warning: $PKG_WWW/$n is not a link to site/$n: the published one is not served"; continue; fi
      ln -s "site/$n" "$PKG_WWW/$n"
    done
  fi
}

releases_of() { # product: release ids, oldest first
  local d="$PKG_RELEASES/$1" e
  [ -d "$d" ] || return 0
  for e in "$d"/*/; do
    e=${e%/}; e=${e##*/}
    valid_id "$e" && echo "$e"
  done | sort
}

prune() { # product
  local cur id ids n keep=$PKG_KEEP
  [ "$keep" -ge 2 ] || keep=2
  cur=$(current_target "$1"); cur=${cur%/*}; cur=${cur##*/}
  mapfile -t ids < <(releases_of "$1")
  n=${#ids[@]}
  for id in "${ids[@]}"; do
    [ "$n" -gt "$keep" ] || break
    [ "$id" = "$cur" ] && continue
    valid_id "$id" || continue
    rm -rf -- "${PKG_RELEASES:?}/$1/$id"
    rm -f -- "${PKG_RELEASES:?}/$1/$id.carried"
    say "removed old release $1/$id"
    n=$((n - 1))
  done
}

lock() {
  [ -d "$PKG_WWW" ] || die "web root $PKG_WWW missing"
  exec 9>"$PKG_RELEASES/.lock"
  flock -w 300 9 || die "another publish is running"
}

cmd_publish() { # product version (tarball on stdin)
  local product=$1 version=$2
  valid_product "$product" || die "unknown product"
  valid_version "$version" || die "bad version"
  case $(tar --version 2>/dev/null | head -n 1) in *'GNU tar'*) ;; *) die "GNU tar is needed" ;; esac
  # The upload is read before taking the lock (a stalled client cannot
  # block other publishes) and decompressed once, with both size caps.
  [ -d "$PKG_RELEASES" ] || die "releases directory $PKG_RELEASES missing"
  work=$(mktemp -d "$PKG_RELEASES/.work.XXXXXX")
  trap cleanup EXIT
  local tb="$work/in.tar.gz" tarf="$work/in.tar" size n line name rc
  set +e
  timeout "$PKG_READ_TIMEOUT" head -c "$((PKG_MAX_BYTES + 1))" >"$tb"
  rc=$?
  set -e
  [ "$rc" -ne 124 ] || die "upload not received within $PKG_READ_TIMEOUT s"
  [ "$rc" -eq 0 ] || die "upload read failed"
  size=$(stat -c %s "$tb")
  [ "$size" -gt 0 ] || die "empty upload"
  [ "$size" -le "$PKG_MAX_BYTES" ] || die "upload larger than $PKG_MAX_BYTES bytes"
  [ "$(od -An -tx1 -N2 "$tb" | tr -d ' ')" = 1f8b ] || die "not a gzip file"
  set +e +o pipefail
  gzip -dc "$tb" 2>/dev/null | head -c "$((PKG_MAX_UNPACKED + 1))" >"$tarf"
  rc=${PIPESTATUS[0]}
  set -e -o pipefail
  [ "$(stat -c %s "$tarf")" -le "$PKG_MAX_UNPACKED" ] || die "archive unpacks to more than $PKG_MAX_UNPACKED bytes"
  [ "$rc" -eq 0 ] || die "corrupt gzip"
  rm -f -- "$tb"
  lock

  # Listing checks, before anything is extracted.
  tar -tf "$tarf" >"$work/names" 2>/dev/null || die "not a tar archive"
  tar -tvf "$tarf" >"$work/long" 2>/dev/null || die "not a tar archive"
  n=$(wc -l <"$work/names")
  [ "$n" -gt 0 ] || die "empty archive"
  [ "$n" -le "$PKG_MAX_ENTRIES" ] || die "more than $PKG_MAX_ENTRIES entries"
  [ "$(wc -l <"$work/long")" -eq "$n" ] || die "inconsistent listing"
  while IFS= read -r name; do
    case $name in /* | *\\* | *//* | *[[:cntrl:]]*) die "bad path in archive: $(printf %q "$name")" ;; esac
    case /$name/ in */../* | */./*) die "bad path in archive: $(printf %q "$name")" ;; esac
    name_ok "$product" "$name" || die "unexpected path in archive: $(printf %q "$name")"
  done <"$work/names"
  while IFS= read -r line; do
    case $line in
    -* | d*) ;;
    *) die "archive member is not a file or directory: $(printf %q "$line")" ;;
    esac
    case $line in *' -> '* | *' link to '*) die "link in archive: $(printf %q "$line")" ;; esac
  done <"$work/long"

  # Extraction into a staging directory, then the same checks on disk.
  local id tree rel cur
  id="$(date -u +%Y%m%dT%H%M%SZ)-$version"
  [ -e "$PKG_RELEASES/$product/$id" ] && id="$(date -u +%Y%m%dT%H%M%SZ)-$$-$version"
  rel="$PKG_RELEASES/$product"
  mkdir -p "$rel"
  stage="$rel/.staging-$id"
  mkdir "$stage"
  tar -xf "$tarf" -C "$stage" --no-same-owner --no-same-permissions --no-overwrite-dir 2>/dev/null ||
    die "extraction failed"
  [ -z "$(find "$stage" -mindepth 1 \( ! -type f ! -type d \) -print -quit)" ] || die "non-regular file after extraction"
  [ -z "$(find "$stage" -type f -links +1 -print -quit)" ] || die "hard link after extraction"
  [ "$(find "$stage" -mindepth 1 -maxdepth 1 | wc -l)" -eq 1 ] && [ -d "$stage/$product" ] ||
    die "the archive must hold exactly one top directory, $product/"
  chmod -R u=rwX,go=rX "$stage"
  tree="$stage/$product"
  case $product in
  openwrt) verify_openwrt "$tree" "$version" ;;
  opnsense) verify_opnsense "$tree" "$version" ;;
  site) verify_site "$tree" ;;
  esac

  # A release may not silently drop a channel, architecture or ABI that
  # routers and firewalls already use.
  cur=$(current_target "$product")
  if [ -n "$cur" ] && [ -d "$cur" ]; then
    # No downgrade: old signed releases are public and could be replayed.
    local curid=${cur%/*}
    curid=${curid##*/}
    if [[ $curid =~ ^[0-9]{8}T[0-9]{6}Z(-[0-9]+)?-(.+)$ ]] && [ "$PKG_ALLOW_DOWNGRADE" != 1 ]; then
      local curver=${BASH_REMATCH[2]}
      [ "$(printf '%s\n%s\n' "$curver" "$version" | sort -V | tail -n 1)" = "$version" ] ||
        die "$version is older than the published $curver (PKG_ALLOW_DOWNGRADE=1 to allow)"
    fi
    subdirs "$product" "$cur" >"$work/old-dirs"
    subdirs "$product" "$tree" >"$work/new-dirs"
    if [ "$PKG_ALLOW_REMOVAL" != 1 ]; then
      local missing
      missing=$(comm -23 "$work/old-dirs" "$work/new-dirs" | tr '\n' ' ')
      [ -z "$missing" ] || die "the new release drops: $missing(PKG_ALLOW_REMOVAL=1 to allow)"
    fi
    carry_over "$product" "$cur" "$tree" "$work/carried"
  fi

  mv -T "$stage" "$rel/$id"
  stage=""
  if [ -s "$work/carried" ]; then cp "$work/carried" "$rel/$id.carried"; fi
  switch_to "$product" "$id"
  say "published $product $version as $id${cur:+ (previous: $(basename "$(dirname "$cur")"))}"
  if [ -s "$work/carried" ]; then say "kept $(wc -l <"$work/carried") package files of the previous release"; fi
  prune "$product"
}

cmd_rollback() { # product
  local product=$1 cur prev="" id
  valid_product "$product" || die "unknown product"
  lock
  cur=$(current_target "$product")
  [ -n "$cur" ] || die "$product is not published"
  cur=${cur%/*}; cur=${cur##*/}
  for id in $(releases_of "$product"); do
    [ "$id" = "$cur" ] && break
    prev=$id
  done
  [ -n "$prev" ] || die "no release before $cur"
  switch_to "$product" "$prev"
  say "$product rolled back from $cur to $prev"
}

cmd_status() {
  local p cur
  local -a ps=("$@")
  [ ${#ps[@]} -gt 0 ] || ps=(openwrt opnsense site)
  for p in "${ps[@]}"; do
    valid_product "$p" || die "unknown product"
    cur=$(current_target "$p")
    if [ -n "$cur" ]; then cur=${cur%/*}; cur=${cur##*/}; else cur=none; fi
    echo "$p: current $cur"
    releases_of "$p" | sed 's/^/  /'
  done
}

main() {
  if [ $# -eq 0 ] && [ -n "${SSH_ORIGINAL_COMMAND:-}" ]; then
    # Forced command: only "[infrafence-deploy] pkg-publish <product> <version>".
    local -a w
    read -r -a w <<<"$SSH_ORIGINAL_COMMAND"
    [ "${w[0]:-}" = infrafence-deploy ] && w=("${w[@]:1}")
    [ ${#w[@]} -eq 3 ] && [ "${w[0]}" = pkg-publish ] || die "only 'pkg-publish <product> <version>' is allowed"
    set -- publish "${w[1]}" "${w[2]}"
  fi
  case ${1:-} in
  publish | pkg-publish) [ $# -eq 3 ] || die "usage: $0 publish <product> <version> < tarball"; cmd_publish "$2" "$3" ;;
  rollback) [ $# -eq 2 ] || die "usage: $0 rollback <product>"; cmd_rollback "$2" ;;
  status) shift; cmd_status "$@" ;;
  *) die "usage: $0 publish <product> <version> < tarball | rollback <product> | status [<product>]" ;;
  esac
}

main "$@"
