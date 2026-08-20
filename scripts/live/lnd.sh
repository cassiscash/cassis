#!/usr/bin/env bash
# Mutinynet LND nodes on the local bitcoind (scripts/live/bitcoind.sh).
#
#   scripts/live/lnd.sh start <n>          start node n (1, 2, ...)
#   scripts/live/lnd.sh stop <n>
#   scripts/live/lnd.sh cli <n> <args...>  lncli against node n
#   scripts/live/lnd.sh enable <n> <node>  point cassis node <node> at it
#   scripts/live/lnd.sh channel <a> <b> <sats>   open a channel a -> b
#
# Node n listens on p2p 9735+n, gRPC 10009+n, REST 8080+n, and keeps
# its data in $LIVE/lnd<n>. Wallets are created without a seed backup
# and unlock on start: test money only. Downloads the LND release into
# $LIVE/bin on first use.
set -euo pipefail
source "$(dirname "$0")/env.sh"

VERSION=v0.21.6-beta
URL="https://github.com/lightningnetwork/lnd/releases/download/$VERSION/lnd-linux-amd64-$VERSION.tar.gz"

install() {
  [ -x "$BIN/lnd" ] && return
  local tmp
  tmp="$(mktemp -d)"
  curl -sSL "$URL" -o "$tmp/lnd.tar.gz"
  tar -xzf "$tmp/lnd.tar.gz" -C "$tmp"
  cp "$tmp/lnd-linux-amd64-$VERSION/lnd" "$tmp/lnd-linux-amd64-$VERSION/lncli" "$BIN/"
  rm -rf "$tmp"
}

dir() { echo "$LIVE/lnd$1"; }
rest_port() { echo $((8080 + $1)); }

cli() {
  local n="$1"
  shift
  lncli --lnddir="$(dir "$n")" --network=signet --rpcserver="localhost:$((10009 + n))" "$@"
}

case "${1:-}" in
  start)
    install
    n="$2"
    mkdir -p "$(dir "$n")"
    cat > "$(dir "$n")/lnd.conf" <<CONF
[Application Options]
alias=cassis-live-$n
listen=127.0.0.1:$((9735 + n))
rpclisten=127.0.0.1:$((10009 + n))
restlisten=127.0.0.1:$(rest_port "$n")
noseedbackup=true
accept-keysend=true
debuglevel=info

[Bitcoin]
bitcoin.signet=true
bitcoin.signetchallenge=$MUTINYNET_SIGNETCHALLENGE
bitcoin.node=bitcoind
bitcoin.defaultchanconfs=1

[Bitcoind]
bitcoind.rpchost=127.0.0.1:$BITCOIND_RPC_PORT
bitcoind.rpcuser=$BITCOIND_RPC_USER
bitcoind.rpcpass=$BITCOIND_RPC_PASS
bitcoind.zmqpubrawblock=tcp://127.0.0.1:28332
bitcoind.zmqpubrawtx=tcp://127.0.0.1:28333

[protocol]
protocol.wumbo-channels=true
CONF
    nohup lnd --lnddir="$(dir "$n")" > "$(dir "$n")/lnd.out" 2>&1 &
    echo $! > "$(dir "$n")/lnd.pid"
    until cli "$n" getinfo > /dev/null 2>&1; do sleep 1; done
    echo "lnd$n up: $(cli "$n" getinfo | grep -m1 identity_pubkey)"
    ;;
  stop) cli "$2" stop ;;
  cli) n="$2"; shift 2; cli "$n" "$@" ;;
  enable)
    n="$2"
    cassis "$3" enable lightning \
      --lnd-rest-url "https://127.0.0.1:$(rest_port "$n")" \
      --lnd-tls-cert "$(dir "$n")/tls.cert" \
      --lnd-macaroon "$(dir "$n")/data/chain/bitcoin/signet/admin.macaroon"
    ;;
  channel)
    a="$2" b="$3" sats="$4"
    pubkey="$(cli "$b" getinfo | sed -n 's/.*"identity_pubkey": "\([^"]*\)".*/\1/p')"
    cli "$a" connect "$pubkey@127.0.0.1:$((9735 + b))" || true
    cli "$a" openchannel --node_key "$pubkey" --local_amt "$sats"
    ;;
  *) echo "usage: $0 start|stop <n> | cli <n> <args...> | enable <n> <node> | channel <a> <b> <sats>" >&2; exit 1 ;;
esac
