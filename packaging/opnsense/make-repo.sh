#!/bin/sh
# Lays out and signs the InfraFence pkg repository (run on FreeBSD):
#   REPO/FreeBSD:14:amd64/latest/All/*.pkg  + meta.conf, packagesite.pkg, ...
#   REPO/FreeBSD:14:aarch64/latest/...       (and FreeBSD:15:* when published)
# The packages are ABI-independent across FreeBSD majors (static binary,
# PHP plugin), so the same files go under every ABI directory.
#
# usage: make-repo.sh -k KEY.pem -r REPO_DIR -a amd64|aarch64 PKG...
# KEY.pem is the RSA signing key (a CI secret, like the cosign key); its
# public half is packaging/opnsense/infrafence-repo.pub once generated.
set -eu
key= repo= arch=
while getopts k:r:a: opt; do
	case $opt in
	k) key=$OPTARG ;;
	r) repo=$OPTARG ;;
	a) arch=$OPTARG ;;
	*) exit 2 ;;
	esac
done
shift $((OPTIND - 1))
[ -n "$key" ] && [ -n "$repo" ] && [ -n "$arch" ] && [ $# -gt 0 ] || { echo "usage: $0 -k KEY.pem -r REPO_DIR -a ARCH PKG..." >&2; exit 2; }
for major in 14 15; do
	d="$repo/FreeBSD:$major:$arch/latest"
	mkdir -p "$d/All"
	cp "$@" "$d/All/"
	pkg repo "$d" "$key"
done
find "$repo" -maxdepth 3 -type d
