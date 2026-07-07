#!/usr/bin/env bash
# install.sh — install the hunt-land toolkit into a bin on PATH (Linux + macOS)
# No dependencies beyond a POSIX shell + coreutils already on the host.
# Read-only hunters; nothing here modifies the system it inspects.
set -e

SRC=$(cd "$(dirname "$0")" && pwd)
TOOLS="hunt-land hunt-procs hunt-net hunt-persist hunt-lolbin hunt-memory hunt-intel"

# Choose a prefix: honor $PREFIX, else /usr/local if writable, else ~/.local
if [ -n "${PREFIX:-}" ]; then
    :
elif [ -w /usr/local/bin ] || [ "$(id -u)" -eq 0 ]; then
    PREFIX=/usr/local
else
    PREFIX="$HOME/.local"
fi
BINDIR="$PREFIX/bin"
LIBDIR="$PREFIX/lib/hunt-land"

echo "Installing hunt-land toolkit"
echo "  from: $SRC"
echo "  bin : $BINDIR"
echo "  lib : $LIBDIR"

mkdir -p "$BINDIR" "$LIBDIR"
cp "$SRC/lib/hunt-common.sh" "$LIBDIR/hunt-common.sh"

for t in $TOOLS; do
    cp "$SRC/bin/$t" "$BINDIR/$t"
    chmod +x "$BINDIR/$t"
    echo "  + $BINDIR/$t"
done

echo
if ! printf '%s' ":$PATH:" | grep -q ":$BINDIR:"; then
    echo "NOTE: $BINDIR is not on your PATH. Add this to your shell rc:"
    echo "  export PATH=\"$BINDIR:\$PATH\""
fi
echo "Done. Try:  hunt-land --help"
echo "Uninstall:  rm -f $BINDIR/{$(echo $TOOLS | tr ' ' ',')} && rm -rf $LIBDIR"
