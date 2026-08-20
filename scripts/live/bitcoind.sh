#!/usr/bin/env bash
# A pruned mutinynet bitcoind, the chain backend of the live LND nodes.
#
#   scripts/live/bitcoind.sh start | stop | status | cli <args...>
#
# Downloads benthecarman's mutinynet fork of Bitcoin Core (30s blocks;
# stock bitcoind rejects the chain's difficulty retargets) into
# $LIVE/bin on first use. The initial sync takes a while.
set -euo pipefail
source "$(dirname "$0")/env.sh"

VERSION=2fda7bfc027e
URL="https://github.com/benthecarman/bitcoin/releases/download/mutinynet-inq-template-hash/bitcoin-$VERSION-x86_64-linux-gnu.tar.gz"
DATA="$LIVE/bitcoind"

install() {
  [ -x "$BIN/bitcoind-mutinynet" ] && return
  local tmp
  tmp="$(mktemp -d)"
  curl -sSL "$URL" -o "$tmp/bitcoin.tar.gz"
  tar -xzf "$tmp/bitcoin.tar.gz" -C "$tmp"
  cp "$tmp/bitcoin-$VERSION/bin/bitcoind" "$BIN/bitcoind-mutinynet"
  cp "$tmp/bitcoin-$VERSION/bin/bitcoin-cli" "$BIN/bitcoin-cli-mutinynet"
  rm -rf "$tmp"
}

cli() {
  bitcoin-cli-mutinynet -signet -datadir="$DATA" "$@"
}

case "${1:-}" in
  start)
    install
    mkdir -p "$DATA"
    cat > "$DATA/bitcoin.conf" <<CONF
signet=1
server=1
prune=2000
dbcache=1000
[signet]
signetchallenge=$MUTINYNET_SIGNETCHALLENGE
signetblocktime=30
addnode=$MUTINYNET_PEER
dnsseed=0
listen=0
rpcport=$BITCOIND_RPC_PORT
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
rpcuser=$BITCOIND_RPC_USER
rpcpassword=$BITCOIND_RPC_PASS
zmqpubrawblock=tcp://127.0.0.1:28332
zmqpubrawtx=tcp://127.0.0.1:28333
fallbackfee=0.0002
CONF
    bitcoind-mutinynet -datadir="$DATA" -daemon
    echo "bitcoind starting; log at $DATA/signet/debug.log"
    ;;
  stop) cli stop ;;
  status) cli getblockchaininfo | grep -E '"(blocks|headers|verificationprogress|initialblockdownload)"' ;;
  cli) shift; cli "$@" ;;
  *) echo "usage: $0 start | stop | status | cli <args...>" >&2; exit 1 ;;
esac
