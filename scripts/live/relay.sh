#!/usr/bin/env bash
# A private Nostr relay for route announcements, so live-test routers do
# not announce testnet routes on the public relays (`nak serve`, in
# memory: restart it and routers re-announce within their interval).
#
#   scripts/live/relay.sh start | stop
#
# Nodes use it through `--nostr-relay $RELAY` (see env.sh).
set -euo pipefail
source "$(dirname "$0")/env.sh"

PIDFILE="$LIVE/relay.pid"
case "${1:-}" in
  start)
    nohup nak serve --port "$RELAY_PORT" > "$LIVE/relay.log" 2>&1 &
    echo $! > "$PIDFILE"
    echo "relay on $RELAY"
    ;;
  stop) kill "$(cat "$PIDFILE")" && rm "$PIDFILE" ;;
  *) echo "usage: $0 start | stop" >&2; exit 1 ;;
esac
