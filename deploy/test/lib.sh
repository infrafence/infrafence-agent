# Shared by the pkg-publish tests: throwaway keys (usign framing made with
# OpenSSL) and fixture trees. Expects $work and $PKG_KEYS_DIR.
# shellcheck shell=bash disable=SC2154
# ---- keys: usign (Ed25519 in usign framing, made with OpenSSL) ------------
usign_keygen() { # dir name
  openssl genpkey -algorithm ed25519 -out "$1/$2.key" 2>/dev/null
  local raw kn
  raw=$(openssl pkey -in "$1/$2.key" -pubout -outform DER | tail -c 32 | od -An -tx1 -v | tr -d ' \n')
  kn=$(openssl rand -hex 8)
  echo "$kn" >"$1/$2.kn"
  { echo "untrusted comment: test key $kn"; printf '%b' "$(printf '4564%s%s' "$kn" "$raw" | sed 's/../\\x&/g')" | base64 -w0; echo; } >"$1/$2.pub"
}
usign_sign() { # keydir name file -> file.sig
  local sig
  sig=$(openssl pkeyutl -sign -inkey "$1/$2.key" -rawin -in "$3" | od -An -tx1 -v | tr -d ' \n')
  { echo "untrusted comment: signed"; printf '%b' "$(printf '4564%s%s' "$(cat "$1/$2.kn")" "$sig" | sed 's/../\\x&/g')" | base64 -w0; echo; } >"$3.sig"
}
make_keys() { # the pinned keys in $PKG_KEYS_DIR, the secret halves in $work
  usign_keygen "$work" good
  usign_keygen "$work" evil
  cp "$work/good.pub" "$PKG_KEYS_DIR/usign.pub"
  openssl ecparam -name prime256v1 -genkey -noout -out "$work/apk.sec" 2>/dev/null
  openssl ec -in "$work/apk.sec" -pubout -out "$PKG_KEYS_DIR/apk.pem" 2>/dev/null
  openssl genrsa -out "$work/repo.key" 2048 2>/dev/null
  openssl rsa -in "$work/repo.key" -pubout -out "$PKG_KEYS_DIR/infrafence-repo.pub" 2>/dev/null
}

# ---- fixtures --------------------------------------------------------------
openwrt_tree() { # dir version arches... (signed with key "good")
  local d=$1 v=$2 a; shift 2
  mkdir -p "$d/openwrt/keys"
  cp "$PKG_KEYS_DIR/usign.pub" "$d/openwrt/keys/usign.pub"
  cp "$PKG_KEYS_DIR/apk.pem" "$d/openwrt/keys/apk.pem"
  for a in "$@"; do
    local o="$d/openwrt/24.10/$a" p="$d/openwrt/25.12/$a"
    mkdir -p "$o" "$p"
    echo "ipk $v $a" >"$o/infrafence-router_${v}-r1_$a.ipk"
    local ipk="infrafence-router_${v}-r1_$a.ipk"
    printf 'Package: infrafence-router\nVersion: %s-r1\nFilename: %s\nSize: %s\nSHA256sum: %s\n\n' \
      "$v" "$ipk" "$(stat -c %s "$o/$ipk")" "$(sha256sum "$o/$ipk" | cut -d' ' -f1)" >"$o/Packages"
    gzip -9nc "$o/Packages" >"$o/Packages.gz"
    usign_sign "$work" good "$o/Packages"
    echo "apk $v" >"$p/infrafence-router-$v-r1.apk"
    echo "ADB index" >"$p/packages.adb"
  done
}
opnsense_tree() { # dir version
  local abi d
  for abi in FreeBSD:14:amd64 FreeBSD:15:amd64 FreeBSD:14:aarch64 FreeBSD:15:aarch64; do
    d="$1/opnsense/$abi/latest"
    mkdir -p "$d/All"
    echo "packing_format = tzst" >"$d/meta.conf"
    echo site >"$d/packagesite.pkg"
    echo data >"$d/data.pkg"
    echo pkg >"$d/All/infrafence-agent-$2.pkg"
    echo pkg >"$d/All/os-infrafence-0.1.pkg"
  done
}
site_tree() { # dir
  mkdir -p "$1/site/keys"
  echo '<!doctype html><title>t</title>' >"$1/site/index.html"
  cp "$PKG_KEYS_DIR"/usign.pub "$PKG_KEYS_DIR"/apk.pem "$PKG_KEYS_DIR"/infrafence-repo.pub "$1/site/keys/"
  echo '#!/bin/sh' >"$1/site/router-install.sh"
}
pack() { # dir top out
  tar -C "$1" --owner=0 --group=0 --numeric-owner -czf "$3" "$2"
}
# Malicious archives, written member by member with python's tarfile.
