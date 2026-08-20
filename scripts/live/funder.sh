#!/usr/bin/env bash
# The faucet of the live tests: a node holding mutinynet BTC and testnet
# RBTC that every other node and router is funded from.
#
#   scripts/live/funder.sh address          deposit addresses to fund it
#   scripts/live/funder.sh balance
#   scripts/live/funder.sh send-btc <address> <sats>
#   scripts/live/funder.sh send-rbtc <address> <sats>
set -euo pipefail
source "$(dirname "$0")/env.sh"

case "${1:-}" in
  address)
    echo "mutinynet:          $(cassis funder bitcoin --network bitcoin::mutinynet address)"
    echo "rootstock testnet:  $(cassis funder rootstock --network rootstock::testnet address)"
    ;;
  balance)
    echo "mutinynet:          $(cassis funder bitcoin --network bitcoin::mutinynet balance)"
    echo "rootstock testnet:  $(cassis funder rootstock --network rootstock::testnet balance)"
    ;;
  send-btc)
    cassis funder bitcoin --network bitcoin::mutinynet send --to "$2" --amount-msat "$(($3 * 1000))"
    ;;
  send-rbtc)
    cassis funder rootstock --network rootstock::testnet send --to "$2" --amount-msat "$(($3 * 1000))"
    ;;
  *) echo "usage: $0 address | balance | send-btc <address> <sats> | send-rbtc <address> <sats>" >&2; exit 1 ;;
esac
