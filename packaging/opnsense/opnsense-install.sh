#!/bin/sh
# Adds the InfraFence package repository to an OPNsense firewall and
# installs the plugin. After this, os-infrafence also shows (and updates)
# in System › Firmware › Plugins. Run as root on the firewall:
#   fetch -o - https://pkg.infrafence.com/opnsense-install.sh | sh
# (published at the edge launch: see deploy/README.md)
set -eu
REPO_URL=${INFRAFENCE_PKG_URL:-https://pkg.infrafence.com}
# SHA-256 of infrafence-repo.pub, pinned in this script (deploy/pkg-keygen.sh
# sets it at launch): the key is not trusted just because the server sent it.
KEY_SHA256="SET-AT-LAUNCH"
[ -f /usr/local/opnsense/version/core ] || { echo "This is not an OPNsense firewall." >&2; exit 1; }
case $REPO_URL in https://*) ;; *) echo "The repository URL must be https://" >&2; exit 1 ;; esac
case $KEY_SHA256 in *[!0-9a-f]*|"") echo "This script has no repository key fingerprint yet." >&2; exit 1 ;; esac
install -d -m 0755 /usr/local/etc/pkg/repos /usr/local/etc/pkg/keys
tmp=$(mktemp)
fetch -q -o "$tmp" "$REPO_URL/keys/infrafence-repo.pub"
if [ "$(sha256 -q "$tmp")" != "$KEY_SHA256" ]; then
	rm -f "$tmp"
	echo "The repository key does not match the fingerprint in this script: not installed." >&2
	exit 1
fi
mv "$tmp" /usr/local/etc/pkg/keys/infrafence.pub
chmod 0644 /usr/local/etc/pkg/keys/infrafence.pub
cat > /usr/local/etc/pkg/repos/InfraFence.conf <<CONF
InfraFence: {
  url: "$REPO_URL/opnsense/\${ABI}/latest",
  signature_type: "pubkey",
  pubkey: "/usr/local/etc/pkg/keys/infrafence.pub",
  mirror_type: "none",
  enabled: yes
}
CONF
pkg update -r InfraFence
pkg install -y -r InfraFence os-infrafence
echo "Done: open Services › InfraFence in the GUI and paste the install token."
