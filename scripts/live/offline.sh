#!/usr/bin/env bash
# Receiving offline: a gateway and a preimage server, daemons with their
# homes at $LIVE/nodes/{gateway,preimage}, configured through their admin
# interfaces (see env.sh).
#
#   scripts/live/offline.sh start      run both, on $OFFLINE_NETWORKS (by
#                                      default both local mints); logs at
#                                      $LIVE/nodes/{gateway,preimage}.log
#   scripts/live/offline.sh stop
#   scripts/live/offline.sh endpoints  the flags of `cassis-wallet receive`
#                                      and `authorize` to go through them
#
# Fund the gateway with what it pays payees from, while it runs: it is a
# <node> to `mint.sh fund`, and `node.sh balance`. pay.sh with OFFLINE=1
# runs a payment through them.
set -euo pipefail
source "$(dirname "$0")/env.sh"

NETWORKS="${OFFLINE_NETWORKS:-$M1 $M2}"

# What a client needs to reach a daemon: its id and relay, one per line.
endpoint() {
  admin_text "$1" identity/key/value
  admin_text "$1" identity/relay/value
}

case "${1:-}" in
  start)
    start_daemon gateway "$CASSIS_GATEWAY" --home
    start_daemon preimage "$CASSIS_PREIMAGE_SERVER" --home
    for daemon in gateway preimage; do
      for network in $NETWORKS; do
        admin_act "$daemon" network.set "{\"id\":\"$network\"}"
      done
      for network in $NETWORKS; do
        network_open "$daemon" "$network"
      done
    done
    ;;
  stop)
    "$LIVE_SCRIPTS/node.sh" stop gateway
    "$LIVE_SCRIPTS/node.sh" stop preimage
    ;;
  endpoints)
    { read -r gateway; read -r gateway_relay; } <<< "$(endpoint gateway)"
    { read -r preimage; read -r preimage_relay; } <<< "$(endpoint preimage)"
    echo "--gateway $gateway --gateway-relay $gateway_relay --ps $preimage --ps-relay $preimage_relay"
    ;;
  *) echo "usage: $0 start | stop | endpoints" >&2; exit 1 ;;
esac
