#!/bin/sh
# Builds the two packages of the OPNsense product with pkg(8) (run it on
# FreeBSD or OPNsense):
#   infrafence-agent-<version>.pkg  the agent binary (FreeBSD build)
#   os-infrafence-<plugin>.pkg       the GUI plugin (packaging/opnsense/plugin)
# The plugin's package scripts are generated the way the opnsense/plugins
# tree (Mk/plugins.mk) generates them, so it installs like any plugin.
#
# usage: build-pkgs.sh -b BINARY -v AGENT_VERSION -a amd64|aarch64 -o OUTDIR [-p PLUGIN_VERSION]
set -eu

here=$(cd "$(dirname "$0")" && pwd)
bin= ver= arch= out= pver=0.1
while getopts b:v:a:o:p: opt; do
	case $opt in
	b) bin=$OPTARG ;;
	v) ver=$OPTARG ;;
	a) arch=$OPTARG ;;
	o) out=$OPTARG ;;
	p) pver=$OPTARG ;;
	*) exit 2 ;;
	esac
done
[ -n "$bin" ] && [ -n "$ver" ] && [ -n "$arch" ] && [ -n "$out" ] || {
	echo "usage: $0 -b BINARY -v AGENT_VERSION -a amd64|aarch64 -o OUTDIR [-p PLUGIN_VERSION]" >&2
	exit 2
}
case $arch in amd64|aarch64) ;; *) echo "arch must be amd64 or aarch64" >&2; exit 2 ;; esac
case $ver in *[!0-9.]*|"") echo "bad agent version $ver" >&2; exit 2 ;; esac
case $pver in *[!0-9.]*|"") echo "bad plugin version $pver" >&2; exit 2 ;; esac
command -v pkg > /dev/null || { echo "pkg(8) is needed: run this on FreeBSD/OPNsense" >&2; exit 1; }

work=$(mktemp -d -t infrafence-pkg)
trap 'rm -rf "$work"' EXIT
mkdir -p "$out"

# ---- infrafence-agent -------------------------------------------------
A=$work/agent
mkdir -p "$A/root/usr/local/sbin"
install -m 0755 "$bin" "$A/root/usr/local/sbin/infrafence-agent"
# Owned by root whoever builds (@(owner,group,mode) keeps the file mode).
cat > "$A/plist" <<PLIST
@(root,wheel,) /usr/local/sbin/infrafence-agent
PLIST
cat > "$A/+MANIFEST" <<MANIFEST
name: infrafence-agent
version: "$ver"
origin: security/infrafence-agent
comment: "InfraFence security agent (firewall appliance build)"
desc: "The InfraFence agent for OPNsense: pf table bans, log and IDS event reporting. Installed with os-infrafence."
maintainer: "support@infrafence.com"
www: "https://infrafence.com"
prefix: "/usr/local"
abi: "FreeBSD:*:$arch"
arch: "freebsd:*:$( [ "$arch" = amd64 ] && echo x86:64 || echo aarch64:64 )"
licenselogic: "single"
licenses: [ "BSL" ]
categories: [ "security" ]
scripts: {
  post-install: <<EOD
install -d -m 0750 /var/db/infrafence /usr/local/etc/infrafence
# An upgrade restarts a running agent on the new binary.
if [ -s /usr/local/etc/infrafence/config.json ] && /usr/sbin/service infrafence enabled 2> /dev/null; then
	/usr/sbin/service infrafence restart > /dev/null 2>&1 || true
fi
EOD
}
MANIFEST
pkg create -M "$A/+MANIFEST" -p "$A/plist" -r "$A/root" -o "$out"

# ---- os-infrafence ----------------------------------------------------
P=$work/plugin
src=$here/plugin
mkdir -p "$P/root/usr/local"
(cd "$src/src" && find . -type f | sort) > "$P/files"
(cd "$src/src" && tar -cf - .) | (cd "$P/root/usr/local" && tar -xpf -)
mkdir -p "$P/root/usr/local/opnsense/version"
cat > "$P/root/usr/local/opnsense/version/infrafence" <<VERSION
{
    "product_abi": "",
    "product_arch": "",
    "product_conflicts": "",
    "product_email": "support@infrafence.com",
    "product_hash": "",
    "product_id": "os-infrafence",
    "product_name": "infrafence",
    "product_tier": "3",
    "product_version": "$pver",
    "product_website": "https://infrafence.com"
}
VERSION
{
	sed 's#^\./#/usr/local/#' "$P/files"
	echo /usr/local/opnsense/version/infrafence
} | sort | sed 's#^#@(root,wheel,) #' > "$P/plist"

# Scripts as Mk/plugins.mk writes them: .pre, the automatic hooks, .post.
post_install=$work/post-install
pre_deinstall=$work/pre-deinstall
post_deinstall=$work/post-deinstall
: > "$post_install"; : > "$pre_deinstall"; : > "$post_deinstall"
[ -f "$src/+POST_INSTALL.pre" ] && cat "$src/+POST_INSTALL.pre" >> "$post_install"
[ -f "$src/+PRE_DEINSTALL.pre" ] && cat "$src/+PRE_DEINSTALL.pre" >> "$pre_deinstall"
[ -f "$src/+POST_DEINSTALL.pre" ] && cat "$src/+POST_DEINSTALL.pre" >> "$post_deinstall"
cat >> "$post_install" <<'AUTO'
if [ -f /usr/local/etc/rc.d/configd ]; then /usr/local/etc/rc.d/configd restart; fi
if [ -f /usr/local/opnsense/mvc/script/run_migrations.php ]; then /usr/local/opnsense/mvc/script/run_migrations.php OPNsense/InfraFence; fi
if [ -f /usr/local/etc/rc.configure_plugins ]; then echo "Reloading plugin configuration"; /usr/local/etc/rc.configure_plugins POST_INSTALL; fi
AUTO
# One template reload per template directory the plugin ships (depth 2).
for t in $(cd "$src/src/opnsense/service/templates" && find -s . -depth 2 -type d | sed 's#^\./##'); do
	echo "if [ -f /usr/local/sbin/configctl ]; then echo -n \"Reloading template $t: \"; /usr/local/sbin/configctl template reload $t; fi" >> "$post_install"
done
cat >> "$post_deinstall" <<'AUTO'
if [ -f /usr/local/etc/rc.configure_plugins ]; then echo "Reloading plugin configuration"; /usr/local/etc/rc.configure_plugins POST_DEINSTALL; fi
AUTO
[ -f "$src/+POST_INSTALL.post" ] && cat "$src/+POST_INSTALL.post" >> "$post_install"
[ -f "$src/+PRE_DEINSTALL.post" ] && cat "$src/+PRE_DEINSTALL.post" >> "$pre_deinstall"
[ -f "$src/+POST_DEINSTALL.post" ] && cat "$src/+POST_DEINSTALL.post" >> "$post_deinstall"

annotations=$(tr -d '\n' < "$P/root/usr/local/opnsense/version/infrafence")
{
	cat <<MANIFEST
name: os-infrafence
version: "$pver"
origin: opnsense/os-infrafence
comment: "InfraFence: network-wide bans, IDS and login attack reporting"
maintainer: "support@infrafence.com"
www: "https://infrafence.com"
prefix: "/usr/local"
abi: "FreeBSD:*:*"
arch: "freebsd:*:*"
licenselogic: "single"
licenses: [ "BSL" ]
categories: [ "security" ]
deps: {
  infrafence-agent: { version: "$ver", origin: "security/infrafence-agent" }
}
annotations $annotations
MANIFEST
	echo "desc: <<EOD"
	cat "$src/pkg-descr"
	echo "EOD"
	echo "scripts: {"
	for s in post-install pre-deinstall post-deinstall; do
		f=$work/$s
		[ -s "$f" ] || continue
		echo "  $s: <<EOD"
		cat "$f"
		echo "EOD"
	done
	echo "}"
} > "$P/+MANIFEST"
pkg create -M "$P/+MANIFEST" -p "$P/plist" -r "$P/root" -o "$out"
ls -l "$out"
