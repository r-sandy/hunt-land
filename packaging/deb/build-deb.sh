#!/usr/bin/env bash
# build-deb.sh — build hunt-land_<version>_all.deb with plain dpkg-deb.
# Output lands in dist/ at the repo root. Needs only dpkg-deb (any Debian/Ubuntu).
set -euo pipefail

REPO=$(cd "$(dirname "$0")/../.." && pwd)
VERSION=$(sed -n 's/^HUNT_VERSION="\(.*\)"/\1/p' "$REPO/tools/lib/hunt-common.sh")
TOOLS="hunt-land hunt-procs hunt-net hunt-persist hunt-lolbin hunt-memory hunt-intel"

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
PKG="$STAGE/hunt-land_${VERSION}_all"

mkdir -p "$PKG/DEBIAN" "$PKG/usr/bin" "$PKG/usr/lib/hunt-land" \
         "$PKG/usr/share/doc/hunt-land"

for t in $TOOLS; do
    install -m 0755 "$REPO/tools/bin/$t" "$PKG/usr/bin/$t"
done
install -m 0644 "$REPO/tools/lib/hunt-common.sh" "$PKG/usr/lib/hunt-land/hunt-common.sh"
install -m 0644 "$REPO/README.md" "$PKG/usr/share/doc/hunt-land/README.md"

cat > "$PKG/DEBIAN/control" <<EOF
Package: hunt-land
Version: $VERSION
Section: admin
Priority: optional
Architecture: all
Depends: bash
Maintainer: r-sandy <symlir.diglm@gmail.com>
Homepage: https://github.com/r-sandy/hunt-land
Description: Living-off-the-Land forensic hunter for Blue Team defenders
 Read-only compromise-assessment toolkit for hosts where AV/EDR shows no
 file-based alerts but native tooling (bash, cron, systemd, curl, LOLBins)
 is suspected of being abused. Runs a six-phase hunt pipeline and emits a
 ranked Compromise Assessment Report mapped to MITRE ATT&CK.
EOF

mkdir -p "$REPO/dist"
dpkg-deb --build --root-owner-group "$PKG" "$REPO/dist/"
echo "Built: $(ls "$REPO"/dist/hunt-land_${VERSION}_all.deb)"
