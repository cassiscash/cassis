#!/usr/bin/env bash
# Cassis nodes of the live tests, each a home under $LIVE/nodes/<name>.
#
#   scripts/live/node.sh <name> <cassis-wallet args...>   run a command
#   scripts/live/node.sh route <name> [run args...]
#       run it in the background as a router announcing on the private
#       relay; log at $LIVE/nodes/<name>.log
#   scripts/live/node.sh sync <name>     settle its own HTLCs once,
#                                        refunding expired ones
#   scripts/live/node.sh stop <name>
#   scripts/live/node.sh pay <name> <from network> <invoice json>
#   scripts/live/node.sh route-of <from> <to> <amount msat>
#       the route the relay's announcements give
set -euo pipefail
source "$(dirname "$0")/env.sh"

case "${1:-}" in
  route)
    # TODO: routers moved to cassis-routerd, configured by a config.toml
    # in their data dir; these homes have no such config yet.
    echo "routers now run under cassis-routerd; node.sh does not set them up yet" >&2
    exit 1 ;;
  sync) cassis "$2" sync ;;
  stop) kill -INT "$(cat "$LIVE/nodes/$2.pid")" && rm "$LIVE/nodes/$2.pid" ;;
  pay) cassis "$2" pay --from "$3" --invoice "$4" --nostr-relay "$RELAY" ;;
  route-of) cassis funder route --from "$2" --to "$3" --amount-msat "$4" --nostr-relay "$RELAY" ;;
  "") echo "usage: see $0" >&2; exit 1 ;;
  *) cassis "$@" ;;
esac
