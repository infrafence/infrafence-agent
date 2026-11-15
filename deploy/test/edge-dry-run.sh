#!/usr/bin/env bash
# Dry run of the edge jobs of .github/workflows/release.yml, on this machine:
#   1. the workflow: actionlint, the jobs before the edge jobs unchanged
#      (release.yml on origin/main is a prefix of this one), every edge job
#      guarded by vars.EDGE_PUBLISH == 'true' and needing "build";
#   2. the real "run:" blocks of edge-openwrt and edge-site, extracted from
#      release.yml and executed with throwaway keys (placed where the
#      committed public keys will be, removed afterwards), ARCHES limited to
#      two architectures, the upload piped into deploy/pkg-publish.sh in a
#      Linux container instead of ssh;
#   3. a secret that does not match the committed public key is refused;
#   4. pkg-upload.sh DRY_RUN=1 prints the ssh command it would run.
# The OPNsense job needs a FreeBSD VM and is not run here.
#   deploy/test/edge-dry-run.sh [VERSION]      (needs Go, Docker, python3)
set -euo pipefail
repo=$(cd "$(dirname "$0")/../.." && pwd)
cd "$repo"
version=${1:-1.0.99}
wf=.github/workflows/release.yml
img=infrafence-pkg-publish-test
for d in build/bin build/pkgroot packaging/openwrt/keys packaging/opnsense/infrafence-repo.pub; do
  [ ! -e "$d" ] || { echo "$d exists: run this on a clean checkout" >&2; exit 1; }
done
work=$(mktemp -d); work=$(cd "$work" && pwd -P)
cleanup() {
  rm -rf -- "$work" "$repo/build/bin" "$repo/build/pkgroot" "$repo/packaging/openwrt/keys"
  rm -f -- "$repo/packaging/opnsense/infrafence-repo.pub"
}
trap cleanup EXIT
pass=0
ok() { pass=$((pass + 1)); echo "ok   $*"; }
die() { echo "FAIL $*" >&2; exit 1; }

# ---- 1. workflow structure ---------------------------------------------------
if command -v actionlint >/dev/null; then
  # The build job's existing "cat *.sha256" info (SC2035) is not ours.
  out=$(actionlint -ignore 'SC2035' "$wf" 2>&1) || die "actionlint: $out"
  ok "actionlint"
else
  echo "skip actionlint (not installed)"
fi
if git cat-file -e origin/main:"$wf" 2>/dev/null; then
  git show origin/main:"$wf" >"$work/main.yml"
  head -c "$(wc -c <"$work/main.yml")" "$wf" | cmp -s - "$work/main.yml" || die "the existing jobs of $wf changed"
  ok "existing release jobs unchanged (origin/main's release.yml is a prefix)"
fi
python3 - "$wf" <<'PY' || die "edge job guards"
import re, sys
text = open(sys.argv[1]).read()
jobs = re.split(r"(?m)^  (?=[a-z][a-z0-9-]*:\s*$)", text.split("\njobs:\n", 1)[1])
edge = [j for j in jobs if j.startswith("edge-")]
assert len(edge) == 4, f"expected 4 edge jobs, found {len(edge)}"
for j in edge:
    name = j.split(":", 1)[0]
    assert re.search(r"(?m)^    if: vars\.EDGE_PUBLISH == 'true' && !contains\(github\.ref_name, '-'\)$", j), f"{name}: no EDGE_PUBLISH guard"
    assert re.search(r"(?m)^    needs: build$", j), f"{name}: does not need build"
    assert "secrets." not in "".join(l for l in j.splitlines() if "echo" in l), f"{name}: echoes a secret"
others = [j.split(":", 1)[0] for j in jobs if j.strip() and not j.startswith("edge-")]
print("edge jobs:", ", ".join(j.split(":", 1)[0] for j in edge), "| others:", ", ".join(others))
PY
ok "every edge job guarded by vars.EDGE_PUBLISH and needs build"

# The run: block of a step, as in release.yml.
run_block() { # job step-name
  python3 - "$wf" "$1" "$2" <<'PY'
import re, sys
text, job, step = open(sys.argv[1]).read(), sys.argv[2], sys.argv[3]
body = re.search(r"(?ms)^  " + re.escape(job) + r":\s*\n(.*?)(?=^  [a-z][a-z0-9-]*:\s*$|\Z)", text).group(1)
s = re.search(r"(?ms)^      - name: " + re.escape(step) + r"\s*\n(.*?)(?=^      - |\Z)", body).group(1)
m = re.search(r"(?m)^        run: (.*)$", s)
if m.group(1).strip() != "|":
    print(m.group(1)); sys.exit()
lines = s[m.end():].split("\n")[1:]
for l in lines:
    if l.strip() and not l.startswith("          "):
        break
    print(l[10:])
PY
}

# ---- 2. throwaway keys where the committed public keys will be --------------
mkdir -p "$work/keys" packaging/openwrt/keys
go run ./packaging/openwrt/owrtpkg keygen -sec "$work/keys/usign.sec" -pub packaging/openwrt/keys/usign.pub -c "InfraFence dry run"
openssl ecparam -name prime256v1 -genkey -noout -out "$work/keys/apk.sec" 2>/dev/null
openssl ec -in "$work/keys/apk.sec" -pubout -out packaging/openwrt/keys/apk.pem 2>/dev/null
go run ./packaging/openwrt/owrtpkg keygen -sec "$work/keys/other.sec" -pub "$work/keys/other.pub" -c other
export VERSION=$version ARCHES="x86_64 mipsel_24kc"

echo "--- edge-openwrt: Binaries"
bash -e -c "$(run_block edge-openwrt Binaries)" >/dev/null
ok "Binaries"

echo "--- edge-openwrt: Packages and signed feeds (mismatched secret)"
if OPENWRT_USIGN_KEY=$(cat "$work/keys/other.sec") OPENWRT_APK_KEY=$(cat "$work/keys/apk.sec") \
  bash -e -c "$(run_block edge-openwrt 'Packages and signed feeds')" >"$work/mismatch.log" 2>&1; then
  die "a usign secret that does not match the committed key was accepted"
fi
grep -q 'does not match packaging/openwrt/keys/usign.pub' "$work/mismatch.log" || die "mismatch: $(tail -3 "$work/mismatch.log")"
ok "mismatched OPENWRT_USIGN_KEY refused"
rm -rf "$repo/build/pkgroot"

echo "--- edge-openwrt: Packages and signed feeds"
OPENWRT_USIGN_KEY=$(cat "$work/keys/usign.sec") OPENWRT_APK_KEY=$(cat "$work/keys/apk.sec") \
  bash -e -c "$(run_block edge-openwrt 'Packages and signed feeds')" | tail -1
for a in x86_64 mipsel_24kc; do
  go run ./packaging/openwrt/owrtpkg verify -pub packaging/openwrt/keys/usign.pub -m "build/pkgroot/openwrt/24.10/$a/Packages" >/dev/null
  [ -s "build/pkgroot/openwrt/25.12/$a/packages.adb" ] || die "no packages.adb for $a"
done
ok "feeds built and signed (owrtpkg verify)"

echo "--- edge-site: Build and publish (site part)"
site_cmd=$(run_block edge-site 'Build and publish' | grep 'pkg-site.sh')
bash -e -c "$site_cmd" >/dev/null
[ -s build/pkgroot/site/index.html ] && [ -s build/pkgroot/site/keys/usign.pub ] || die "site not built"
ok "site built"

# ---- the upload, piped into pkg-publish.sh in a Linux container -------------
docker build -q -t "$img" - >/dev/null <<'EOF'
FROM python:3.13-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssl && rm -rf /var/lib/apt/lists/*
EOF
mkdir -p "$work/pinned"
cp packaging/openwrt/keys/usign.pub packaging/openwrt/keys/apk.pem "$work/pinned/"
cp build/pkgroot/site.sha256 "$work/pinned/site.sha256"   # what the coordinator pins on the server
openwrt_publish=$(run_block edge-openwrt 'Publish to pkg.infrafence.com')
site_publish=$(run_block edge-site 'Build and publish' | grep 'pkg-upload.sh')
# $work at the same path in the container: the release links are absolute.
docker run --rm -v "$repo:/repo" -v "$work:$work" -w /repo -e VERSION="$VERSION" \
  -e PKG_WWW="$work/srv/infrafence-pkg" -e PKG_RELEASES="$work/srv/infrafence-pkg-releases" -e PKG_KEYS_DIR="$work/pinned" \
  -e PKG_PUBLISH_CMD="bash deploy/pkg-publish.sh" -e OW="$openwrt_publish" -e SITE="$site_publish" "$img" bash -euc '
    mkdir -p "$PKG_WWW" "$PKG_RELEASES"
    bash -e -c "$OW"
    bash -e -c "VERSION=$VERSION; $SITE"
    bash deploy/pkg-publish.sh status'
[ -s "$work/srv/infrafence-pkg/openwrt/24.10/x86_64/Packages.sig" ] && [ -s "$work/srv/infrafence-pkg/keys/usign.pub" ] &&
  [ -s "$work/srv/infrafence-pkg/router-install.sh" ] || die "not served after publish"
go run ./packaging/openwrt/owrtpkg verify -pub "$work/srv/infrafence-pkg/keys/usign.pub" -m "$work/srv/infrafence-pkg/openwrt/24.10/x86_64/Packages" >/dev/null
ok "openwrt feed and site accepted by pkg-publish.sh (real usign signature verified server side)"

# ---- 4. the ssh command ------------------------------------------------------
docker run --rm -v "$repo:/repo:ro" -v "$work:/work" -w /repo "$img" bash -c \
  'mkdir -p /work/up && cp -R build/pkgroot/site /work/up/ && DRY_RUN=1 PKG_DEPLOY_HOST=pkg.example.invalid PKG_DEPLOY_USER=pkgpub deploy/pkg-upload.sh site 1.0.99 /work/up' |
  tee "$work/dry.log"
grep -q "ssh pkgpub@pkg.example.invalid 'infrafence-deploy pkg-publish site 1.0.99'" "$work/dry.log" || die "dry run command"
ok "pkg-upload.sh DRY_RUN prints the forced-command invocation"

echo
echo "dry run passed ($pass checks); not run: edge-opnsense (FreeBSD VM), edge-assets (cosign, gh release)"
