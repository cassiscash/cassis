#!/usr/bin/env bash
# Our own one-guardian mutinynet federation (mintv2, walletv2, lnv2,
# meta), its chain read from the mutinynet esplora.
#
#   scripts/live/fedimint.sh start     start it, running DKG the first time
#   scripts/live/fedimint.sh stop
#   scripts/live/fedimint.sh invite    its network id, fedimint::<invite>
#   scripts/live/fedimint.sh fund <node> <sats>
#       peg <sats> in from the funder into <node>'s wallet (needs the
#       peg-in's confirmations: a few minutes)
#
# fedimintd is `$CASSIS_FEDIMINTD`, or <workspace>/tmp/fedimintd-v0.12.1.
# It is a nix bundle running in a chroot: paths given to it must be
# absolute. Setup goes through the guardian UI's forms (no fedimint-cli).
set -euo pipefail
source "$(dirname "$0")/env.sh"

FEDIMINTD="${CASSIS_FEDIMINTD:-$WORKSPACE/tmp/fedimintd-v0.12.1}"
DATA="$LIVE/fedimint"
UI="http://127.0.0.1:18175"

invite() { echo "fedimint::$(tr -d '[:space:]' < "$DATA/invite-code")"; }

case "${1:-}" in
  start)
    mkdir -p "$DATA"
    FM_DATA_DIR="$DATA" \
    FM_BITCOIN_NETWORK=signet \
    FM_ESPLORA_URL="$MUTINYNET_ESPLORA" \
    FM_BIND_P2P=127.0.0.1:18173 \
    FM_BIND_API=127.0.0.1:18174 \
    FM_BIND_UI=127.0.0.1:18175 \
    FM_BIND_METRICS=127.0.0.1:18176 \
    FM_P2P_URL=fedimint://127.0.0.1:18173 \
    FM_API_URL=ws://127.0.0.1:18174 \
    FM_ENABLE_IROH=false \
      setsid nohup "$FEDIMINTD" >> "$DATA/fedimintd.log" 2>&1 &
    echo $! > "$DATA/fedimintd.pid"
    until curl -sf "$UI/" > /dev/null; do sleep 0.5; done
    if [ ! -f "$DATA/invite-code" ]; then
      cookies="$DATA/ui.cookies"
      curl -sf -c "$cookies" -b "$cookies" -X POST "$UI/" \
        -d "name=live&is_lead=true&federation_name=cassis-live&federation_size=1" \
        -d "enable_base_fees=true&enabled_modules=lnv2&enabled_modules=meta" \
        -d "enabled_modules=mintv2&enabled_modules=walletv2" > /dev/null
      curl -sf -c "$cookies" -b "$cookies" -X POST "$UI/start_dkg" > /dev/null
      until [ -f "$DATA/invite-code" ]; do sleep 1; done
    fi
    echo "federation up: $(invite)"
    ;;
  # The bundle runs fedimintd under wrapper processes: signal the group.
  stop) kill -INT -- "-$(cat "$DATA/fedimintd.pid")" ;;
  invite) invite ;;
  fund)
    node="$2" sats="$3"
    out="$LIVE/nodes/$node.pegin"
    cassis "$node" fedimint --network "$(invite)" deposit --wait > "$out" &
    waiting=$!
    until [ -s "$out" ]; do sleep 0.5; done
    address="$(head -1 "$out")"
    "$LIVE_SCRIPTS/funder.sh" send-btc "$address" "$sats"
    wait "$waiting"
    cassis "$node" fedimint --network "$(invite)" balance
    ;;
  *) echo "usage: $0 start | stop | invite | fund <node> <sats>" >&2; exit 1 ;;
esac
