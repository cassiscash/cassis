#!/usr/bin/env bash
# Our own arkade operator on mutinynet: `arkd-light` (arkd with its
# wallet in-process on the mutinynet esplora, light mode), the network
# `arkade::127.0.0.1:7070`.
#
#   scripts/live/arkd.sh start            start it, creating its wallet
#   scripts/live/arkd.sh stop
#   scripts/live/arkd.sh fund <sats>      fund the operator's on-chain
#                                         wallet (it finances batches)
#   scripts/live/arkd.sh balance          operator's on-chain balance
#   scripts/live/arkd.sh note <sats>      issue an arknote
#   scripts/live/arkd.sh give <node> <sats>
#       issue an arknote and redeem it into <node>'s wallet; <node> may
#       be a running daemon, reached through its admin interface
#
# Batches last `$ARKD_VTXO_TREE_EXPIRY` seconds (a multiple of 512),
# 4h by default: longer than the HTLCs of the live routes, which must
# be over before their VTXOs' batch expires. arkd keeps the settings it
# first started with in its database, so `start` writes it there too
# (needs sqlite3).
#
# Uses `$CASSIS_ARKD` or <workspace>/target/arkd-light, building it with
# scripts/live/arkd/build.sh (needs go) when missing.
set -euo pipefail
source "$(dirname "$0")/env.sh"

ARKD="${CASSIS_ARKD:-$WORKSPACE/target/arkd-light}"
DATA="$LIVE/arkd"
PORT=7070
ADMIN="http://127.0.0.1:7071/v1/admin"
NETWORK="arkade::127.0.0.1:$PORT"
PASSWORD=password

admin() {
  local method="$1" path="$2"
  shift 2
  curl -sSf -X "$method" -H 'content-type: application/json' "$ADMIN$path" "$@"
}
json() { sed -n "s/.*\"$1\": *\"\\([^\"]*\\)\".*/\\1/p"; }

case "${1:-}" in
  start)
    [ -x "$ARKD" ] || "$LIVE_SCRIPTS/arkd/build.sh" "$ARKD"
    mkdir -p "$DATA"
    [ -f "$DATA/signer.key" ] || od -An -tx1 -N32 /dev/urandom | tr -d ' \n' > "$DATA/signer.key"
    TREE_EXPIRY="${ARKD_VTXO_TREE_EXPIRY:-14336}"
    [ -f "$DATA/db/sqlite.db" ] &&
      sqlite3 "$DATA/db/sqlite.db" "UPDATE settings SET vtxo_tree_expiry = $TREE_EXPIRY"
    ARKD_DATADIR="$DATA" \
    ARKD_PORT="$PORT" \
    ARKD_ADMIN_PORT=7071 \
    ARKD_NO_TLS=true \
    ARKD_NO_MACAROONS=true \
    ARKD_LOG_LEVEL=4 \
    ARKD_ESPLORA_URL="$MUTINYNET_ESPLORA" \
    ARKD_WALLET_NETWORK=mutinynet \
    ARKD_WALLET_SIGNER_KEY="$(cat "$DATA/signer.key")" \
    ARKD_LIVE_STORE_TYPE=inmemory \
    ARKD_DB_TYPE=sqlite \
    ARKD_EVENT_DB_TYPE=badger \
    ARKD_SESSION_DURATION=10 \
    ARKD_UNILATERAL_EXIT_DELAY=512 \
    ARKD_PUBLIC_UNILATERAL_EXIT_DELAY=512 \
    ARKD_CHECKPOINT_EXIT_DELAY=512 \
    ARKD_BOARDING_EXIT_DELAY=1024 \
    ARKD_VTXO_TREE_EXPIRY="$TREE_EXPIRY" \
      nohup "$ARKD" > "$DATA/arkd.log" 2>&1 &
    echo $! > "$DATA/arkd.pid"
    until admin GET /wallet/status > /dev/null 2>&1; do sleep 0.5; done
    if ! admin GET /wallet/status | grep -q '"initialized": *true'; then
      seed="$(admin GET /wallet/seed | json seed)"
      admin POST /wallet/create -d "{\"seed\":\"$seed\",\"password\":\"$PASSWORD\"}" > /dev/null
    fi
    admin POST /wallet/unlock -d "{\"password\":\"$PASSWORD\"}" > /dev/null || true
    until curl -sf "http://127.0.0.1:$PORT/v1/info" > /dev/null; do sleep 0.5; done
    echo "arkd up: $NETWORK"
    ;;
  stop) kill -INT "$(cat "$DATA/arkd.pid")" ;;
  fund) "$LIVE_SCRIPTS/funder.sh" send-btc "$(admin GET /wallet/address | json address)" "$2" ;;
  balance) admin GET /wallet/balance; echo ;;
  note) admin POST /note -d "{\"amount\":$2,\"quantity\":1}" | sed -n 's/.*"notes": *\[ *"\([^"]*\)".*/\1/p' ;;
  give)
    if daemon_up "$2"; then
      wallet_op "$2" "$NETWORK" redeem "\"token\":\"$("$0" note "$3")\""
    else
      cassis "$2" arkade --network "$NETWORK" redeem-note "$("$0" note "$3")"
    fi
    ;;
  *) echo "usage: $0 start | stop | fund <sats> | balance | note <sats> | give <node> <sats>" >&2; exit 1 ;;
esac
