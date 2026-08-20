#!/usr/bin/env bash
# Build `arkd-light`: a single arkd binary that runs its own wallet
# in-process on top of an Esplora API (no NBXplorer, no bitcoind), meant
# for light mode (in-memory live store, sqlite db, badger event db).
#
#   scripts/live/arkd/build.sh [output]   (default: target/arkd-light)
#
# Needs git and go. Overridable: ARKD_REPO, ARKD_REV, ARKD_SRC (an
# existing checkout to build from instead of cloning), and the usual
# GOMODCACHE/GOCACHE.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
workspace="$(cd "$here/../../.." && pwd)"
out="$(realpath -m "${1:-$workspace/target/arkd-light}")"
repo="${ARKD_REPO:-https://github.com/arkade-os/arkd}"
rev="${ARKD_REV:-f863e484719344edbe4a8d10cf5fe994b123f2c0}"
src="${ARKD_SRC:-$workspace/target/arkd-src}"

if [ ! -d "$src/.git" ]; then
  git clone --quiet "$repo" "$src"
fi
if [ -z "${ARKD_SRC:-}" ]; then
  git -C "$src" fetch --quiet origin "$rev" 2>/dev/null || true
  git -C "$src" checkout --quiet --force "$rev"
fi

# arkd's main plus our files, in a package inside the arkd module so
# it may import arkd's internal packages.
cmd="$src/cmd/arkd-light"
rm -rf "$cmd"
mkdir -p "$cmd"
cp "$src"/cmd/arkd/*.go "$here"/esplora.go "$here"/wallet.go "$cmd"/
grep -q 'cfg, err := config.LoadConfig()' "$cmd/main.go" || {
  echo "arkd's startAction changed; update the patch in $0" >&2
  exit 1
}
sed -i 's|\tcfg, err := config.LoadConfig()|\tif err := startEmbeddedWallet(); err != nil {\n\t\treturn fmt.Errorf("embedded wallet: %s", err)\n\t}\n\tcfg, err := config.LoadConfig()|' "$cmd/main.go"

cd "$src"
# Fall back to a module cache of our own when Go's is not writable.
modcache="$(go env GOMODCACHE)"
mkdir -p "$modcache" 2>/dev/null || true
if [ ! -w "$modcache" ]; then
  export GOMODCACHE="$workspace/target/go/mod"
fi
version="$(git describe --tags --always 2>/dev/null || echo "$rev")-light"
go build -ldflags="-s -w -X 'main.Version=$version'" -o "$out" ./cmd/arkd-light
echo "built $out ($version)"
