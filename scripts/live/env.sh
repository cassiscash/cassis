# Shared settings of the live-test scripts; source it.
#
# Everything they create lives under $LIVE (default <workspace>/tmp/live),
# which is git-ignored: node homes, LND and bitcoind data, binaries.
LIVE_SCRIPTS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(cd "$LIVE_SCRIPTS/../.." && pwd)"
LIVE="${LIVE:-$WORKSPACE/tmp/live}"
BIN="$LIVE/bin"
mkdir -p "$BIN"
export PATH="$BIN:$PATH"

# Public mutinynet ledgers.
MUTINYNET_ESPLORA="https://mutinynet.com/api"
MUTINYNET_FEDIMINT="fedimint::fed11qgqzc2nhwden5te0vejkg6tdd9h8gepwvejkg6tdd9h8garhduhx6at5d9h8jmn9wshxxmmd9uqqzgxg6s3evnr6m9zdxr6hxkdkukexpcs3mn7mj3g5pc5dfh63l4tj6g9zk4er"
MUTINYNET_CASHU="cashu::cashu.mutinynet.com"
MUTINYNET_ARKADE="arkade::mutinynet"

# Mutinynet is a custom signet with 30s blocks, which stock bitcoind
# cannot follow: these settings go with benthecarman's fork.
MUTINYNET_SIGNETCHALLENGE="512102f7561d208dd9ae99bf497273e16f389bdbd6c4742ddb8e6b216e64fa2928ad8f51ae"
MUTINYNET_PEER="45.79.52.207:38333"
BITCOIND_RPC_PORT=38332
BITCOIND_RPC_USER=cassis
BITCOIND_RPC_PASS=cassis

# Private relay for route announcements (scripts/live/relay.sh).
RELAY_PORT=10547
RELAY="ws://localhost:$RELAY_PORT"

# `cassis-cli` built from this workspace.
if [ -z "${CASSIS_CLI:-}" ]; then
  CASSIS_CLI="$(cd "$WORKSPACE" && cargo metadata --format-version 1 --no-deps |
    sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')/debug/cassis-cli"
fi

# cassis-cli against the node home `$LIVE/nodes/<name>`.
cassis() {
  local name="$1"
  shift
  "$CASSIS_CLI" --home "$LIVE/nodes/$name" "$@"
}
