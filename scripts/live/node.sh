#!/usr/bin/env bash
# Cassis nodes of the live tests, each a home under $LIVE/nodes/<name>.
#
#   scripts/live/node.sh <name> <cassis-wallet args...>   run a command
#   scripts/live/node.sh route <name> [run args...]
#       run it in the background as a router announcing on the private
#       relay; log at $LIVE/nodes/<name>.log
#   scripts/live/node.sh serve <name>    the same without routing, to
#                                        claim payments to its invoices
#   scripts/live/node.sh stop <name>
#   scripts/live/node.sh pay <name> <from network> <invoice json>
#   scripts/live/node.sh route-of <from> <to> <amount msat>
#       the route the relay's announcements give
set -euo pipefail
source "$(dirname "$0")/env.sh"

background() {
  local name="$1"
  shift
  mkdir -p "$LIVE/nodes"
  nohup "$CASSIS_WALLET" --home "$LIVE/nodes/$name" run "$@" > "$LIVE/nodes/$name.log" 2>&1 &
  echo $! > "$LIVE/nodes/$name.pid"
  echo "$name running (pid $!), log at $LIVE/nodes/$name.log"
}

case "${1:-}" in
  route)
    # TODO: routers moved to cassis-routerd, configured by a config.toml
    # in their data dir; these homes have no such config yet.
    echo "routers now run under cassis-routerd; node.sh does not set them up yet" >&2
    exit 1 ;;
  serve) background "$2" ;;
  stop) kill -INT "$(cat "$LIVE/nodes/$2.pid")" && rm "$LIVE/nodes/$2.pid" ;;
  pay) cassis "$2" pay --from "$3" --invoice "$4" --nostr-relay "$RELAY" ;;
  route-of) cassis funder route --from "$2" --to "$3" --amount-msat "$4" --nostr-relay "$RELAY" ;;
  "") echo "usage: see $0" >&2; exit 1 ;;
  *) cassis "$@" ;;
esac
