#!/usr/bin/env bash
# Builds the "site" product of pkg.infrafence.com: the index page, the
# public keys and the installers, from the repository.
#
#   deploy/pkg-site.sh OUTDIR VERSION     -> OUTDIR/site/..., OUTDIR/site.sha256
#
# OUTDIR/site/
#   index.html             what the host serves, the keys and their fingerprints
#   keys/usign.pub         OpenWrt opkg feed key          (packaging/openwrt/keys/)
#   keys/apk.pem           OpenWrt apk feed key           (packaging/openwrt/keys/)
#   keys/infrafence-repo.pub  OPNsense pkg repository key (packaging/opnsense/)
#   router-install.sh, opnsense-install.sh
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
out=${1:?output directory}
version=${2:?version}
site="$out/site"
mkdir -p "$site/keys"
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

rows=""
add_key() { # source name what
  [ -s "$1" ] || return 0
  cp "$1" "$site/keys/$2"
  rows="$rows<tr><td><a href=\"/keys/$2\">keys/$2</a></td><td>$3</td><td><code>$(sha256 "$1")</code></td></tr>"
}
# KEYS_FROM (tests): a directory with usign.pub, apk.pem, infrafence-repo.pub.
kf=${KEYS_FROM:-}
add_key "${kf:-$repo/packaging/openwrt/keys}/usign.pub" usign.pub "OpenWrt opkg feed (usign)"
add_key "${kf:-$repo/packaging/openwrt/keys}/apk.pem" apk.pem "OpenWrt apk feed (EC P-256)"
add_key "${kf:-$repo/packaging/opnsense}/infrafence-repo.pub" infrafence-repo.pub "OPNsense pkg repository (RSA)"
[ -n "$rows" ] || { echo "no public key in packaging/: run deploy/pkg-keygen.sh first" >&2; exit 1; }

cp "$repo/packaging/openwrt/router-install.sh" "$site/router-install.sh"
[ -f "$repo/packaging/opnsense/opnsense-install.sh" ] && cp "$repo/packaging/opnsense/opnsense-install.sh" "$site/opnsense-install.sh"
chmod 0644 "$site"/*.sh "$site/keys"/*

cat >"$site/index.html" <<EOF
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>InfraFence packages</title>
<style>
body{font:15px/1.5 system-ui,sans-serif;max-width:52rem;margin:2rem auto;padding:0 1rem;color:#1b1f24;background:#fff}
code,pre{font-family:ui-monospace,monospace;font-size:13px}pre{background:#f3f4f6;padding:.75rem;overflow-x:auto}
table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:.35rem .5rem;border-bottom:1px solid #e5e7eb;vertical-align:top}
td code{word-break:break-all}
@media (prefers-color-scheme:dark){body{color:#e6e6e6;background:#111418}pre{background:#1d2127}td,th{border-color:#2a2f36}a{color:#7cb4ff}}
</style>
</head>
<body>
<h1>InfraFence packages</h1>
<p>Signed package feeds of the InfraFence agent for routers and firewalls . Install from the InfraFence dashboard, which gives you the one-line command with your install token.</p>
<h2>OpenWrt and GL.iNet</h2>
<pre>wget -qO- https://pkg.infrafence.com/router-install.sh | sh -s -- --token &lt;install token&gt;</pre>
<p><code>/openwrt/24.10/&lt;arch&gt;/</code> opkg feed (OpenWrt 21.02 to 24.10, GL.iNet 4.x), <code>/openwrt/25.12/&lt;arch&gt;/</code> apk feed (OpenWrt 25.12 and later).</p>
<h2>OPNsense</h2>
<pre>fetch -o - https://pkg.infrafence.com/opnsense-install.sh | sh</pre>
<p><code>/opnsense/FreeBSD:&lt;major&gt;:&lt;arch&gt;/latest/</code> pkg repository (OPNsense 26.1 on FreeBSD 14, 26.7 on FreeBSD 15).</p>
<h2>Signing keys</h2>
<table><tr><th>File</th><th>Signs</th><th>SHA-256</th></tr>$rows</table>
<p>The installers pin these keys and refuse a feed signed with any other. Source: <a href="https://github.com/infrafence/infrafence-agent">github.com/infrafence/infrafence-agent</a>.</p>
</body>
</html>
EOF
# The SHA-256 sums the server pins for the site (PKG_KEYS_DIR/site.sha256 in
# deploy/README.md): the page does not change from release to release, the
# installers only when they are edited.
for f in "$site"/index.html "$site"/*.sh; do echo "$(sha256 "$f")  ${f##*/}"; done >"$out/site.sha256"
echo "site for $version -> $site; pins for the server:"
cat "$out/site.sha256"
