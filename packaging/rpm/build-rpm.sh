#!/usr/bin/env bash
# build-rpm.sh — build hunt-land-<version>.noarch.rpm with rpmbuild.
# Output lands in dist/ at the repo root. Needs rpmbuild
# (Fedora/RHEL: dnf install rpm-build; Debian/Ubuntu: apt install rpm).
set -euo pipefail

REPO=$(cd "$(dirname "$0")/../.." && pwd)
VERSION=$(sed -n 's/^HUNT_VERSION="\(.*\)"/\1/p' "$REPO/tools/lib/hunt-common.sh")

TOP=$(mktemp -d)
trap 'rm -rf "$TOP"' EXIT

# --build-in-place uses the cwd as the build dir; %doc README.md needs it
cd "$REPO"
rpmbuild -bb "$REPO/packaging/rpm/hunt-land.spec" \
    --define "_topdir $TOP" \
    --define "hunt_version $VERSION" \
    --define "repo_root $REPO" \
    --build-in-place

mkdir -p "$REPO/dist"
cp "$TOP"/RPMS/noarch/hunt-land-*.rpm "$REPO/dist/"
echo "Built: $(ls "$REPO"/dist/hunt-land-${VERSION}*.rpm)"
