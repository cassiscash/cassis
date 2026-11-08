#!/usr/bin/env bash
# Local cashu mints (`cdk-mintd`) with a fake Lightning backend: their
# mint quotes are paid by themselves, so ecash is free.
#
#   scripts/live/mint.sh start <n>        mint n on port 3337+n
#   scripts/live/mint.sh stop <n>
#   scripts/live/mint.sh fund <n> <node> <sats>
#       mint <sats> with cdk-cli and redeem them into <node>'s wallet
#   scripts/live/mint.sh fund-external <host> <node> <sats> [quote id]
#       the same on a real mint (cashu.mutinynet.com): without a quote
#       id it prints a bolt11 to pay (e.g. from faucet.mutinynet.com) and
#       its quote id; with one it waits for the payment and redeems it
#
# Mint n is the network `cashu::127.0.0.1:<3337+n>`. <node> may be a
# running daemon: the token then goes through its admin interface.
set -euo pipefail
source "$(dirname "$0")/env.sh"

port() { echo $((3337 + $1)); }
dir() { echo "$LIVE/mint$1"; }

# credit <node> <network> <token>
credit() {
  if daemon_up "$1"; then
    wallet_op "$1" "$2" redeem "\"token\":\"$3\""
  else
    cassis "$1" cashu --network "$2" receive --token "$3"
  fi
}

case "${1:-}" in
  start)
    n="$2"
    mkdir -p "$(dir "$n")"
    [ -f "$(dir "$n")/seed" ] || "$CASSIS_WALLET" --home "$(dir "$n")/seedgen" seed > "$(dir "$n")/seed" 2>/dev/null
    CDK_MINTD_LISTEN_HOST=127.0.0.1 \
    CDK_MINTD_LISTEN_PORT="$(port "$n")" \
    CDK_MINTD_URL="http://127.0.0.1:$(port "$n")" \
    CDK_MINTD_LN_BACKEND=fakewallet \
    CDK_MINTD_FAKE_WALLET_SUPPORTED_UNITS=sat \
    CDK_MINTD_FAKE_WALLET_FEE_PERCENT=0 \
    CDK_MINTD_FAKE_WALLET_RESERVE_FEE_MIN=0 \
      nohup cdk-mintd -w "$(dir "$n")" --seed-file "$(dir "$n")/seed" > "$(dir "$n")/mintd.log" 2>&1 &
    echo $! > "$(dir "$n")/mintd.pid"
    until curl -sf "http://127.0.0.1:$(port "$n")/v1/info" > /dev/null; do sleep 0.5; done
    echo "mint $n up: cashu::127.0.0.1:$(port "$n")"
    ;;
  stop) kill "$(cat "$(dir "$2")/mintd.pid")" ;;
  fund)
    n="$2" node="$3" sats="$4"
    url="http://127.0.0.1:$(port "$n")"
    cdk() { cdk-cli -w "$LIVE/cdk-cli" -n "$@"; }
    cdk mint "$url" "$sats" > /dev/null
    token="$(cdk send -a "$sats" --mint-url "$url" | grep -m1 -E '^cashu[AB]')"
    credit "$node" "cashu::127.0.0.1:$(port "$n")" "$token"
    ;;
  fund-external)
    host="$2" node="$3" sats="$4"
    cdk() { cdk-cli -w "$LIVE/cdk-cli" -n "$@"; }
    if [ -z "${5:-}" ]; then
      # Prints the quote and bolt11, then gives up waiting at once.
      cdk mint "https://$host" "$sats" --wait-duration 1 2>&1 |
        grep -E '^(Quote|Please pay)' || true
      echo "pay it, then: $0 fund-external $host $node $sats <quote id>"
      exit 0
    fi
    # cdk-cli's own wait polls fast enough to hit the mint's rate limit.
    until curl -sf "https://$host/v1/mint/quote/bolt11/$5" | grep -qE '"state": *"(PAID|ISSUED)"'; do sleep 30; done
    cdk mint "https://$host" "$sats" --quote-id "$5" > /dev/null
    # Real mints charge input fees: keep 1% for them.
    token="$(cdk send -a "$((sats * 99 / 100))" --mint-url "https://$host" | grep -m1 -E '^cashu[AB]')"
    credit "$node" "cashu::$host" "$token"
    ;;
  *) echo "usage: $0 start|stop <n> | fund <n> <node> <sats> | fund-external <host> <node> <sats> [quote]" >&2; exit 1 ;;
esac
