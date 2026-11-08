#!/usr/bin/env bash
# Cassis nodes of the live tests, each a home under $LIVE/nodes/<name>:
# wallets, run one command at a time, and routers, cassis-routerd
# daemons configured through their admin interface (see env.sh).
#
#   scripts/live/node.sh <name> <cassis-wallet args...>   run a command
#   scripts/live/node.sh route <name>
#       run it in the background as a router announcing on the private
#       relay, with the networks and routes router_networks gives it;
#       log at $LIVE/nodes/<name>.log. A home that was a wallet keeps its
#       keys and funds. Applies them again on every run, over changes
#       made to them on its page.
#   scripts/live/node.sh sync <name>     settle its own HTLCs once,
#                                        refunding expired ones
#   scripts/live/node.sh stop <name>
#   scripts/live/node.sh pay <name> <from network> <invoice json>
#   scripts/live/node.sh route-of <from> <to> <amount msat>
#       the route the relay's announcements give
#
# On a router's wallets, while it runs:
#
#   scripts/live/node.sh balance <router> <network>
#   scripts/live/node.sh address <router> <network> <label start>
#       its deposit address: Rootstock, Boarding, Arkade, On-chain...
#   scripts/live/node.sh onboard <router> <network>
#   scripts/live/node.sh hops <router>   what it routed
set -euo pipefail
source "$(dirname "$0")/env.sh"

# The two networks router <name> routes between, both ways.
router_networks() {
  case "$1" in
    r1) echo "$M1 $M2" ;;
    r2) echo "$M2 $R" ;;
    r3) echo "$R $(fedimint_network)" ;;
    r4) echo "$(fedimint_network) $A" ;;
    r5) echo "$A $AL" ;;
    r6) echo "$M2 $MM" ;;
    r7) echo "$AL $M2" ;;
    *) echo "$1: not in router_networks" >&2; return 1 ;;
  esac
}

# What route.set says on top of the ends and fees of a route.
route_extras() {
  case "$1:$2" in
    # Under our arkd's 4h batches: see arkd.sh and README.md.
    "r7:$AL") echo ',"max_incoming_lifetime_secs":13136' ;;
  esac
}

# What the daemon cannot be told through its admin interface: the keys
# of its home, and a port of its own to have an interface on at all.
write_config() {
  local name="$1" config="$LIVE/nodes/$1/config.toml" seed
  [ -f "$config" ] && return 0
  seed="$(cassis "$name" seed 2> /dev/null)"
  (
    umask 077
    cat > "$config" << TOML
mnemonic = "$seed"
nostr_relays = ["$RELAY"]

[admin]
listen = "127.0.0.1:$(admin_port "$name")"
TOML
  )
}

route() {
  local name="$1" first second from to
  read -r first second <<< "$(router_networks "$name")"
  mkdir -p "$LIVE/nodes/$name"
  write_config "$name"
  start_daemon "$name" "$CASSIS_ROUTERD" --data-dir
  for network in "$first" "$second"; do
    admin_act "$name" network.set "{\"id\":\"$network\"}"
  done
  for ends in "$first $second" "$second $first"; do
    read -r from to <<< "$ends"
    admin_act "$name" route.set "{\"from\":\"$from\",\"to\":\"$to\",\"fee_base_msat\":1000,\"fee_ppm\":500,\"test_money\":true$(route_extras "$name" "$from")}"
  done
  for network in "$first" "$second"; do
    network_open "$name" "$network"
  done
}

stop() {
  local pidfile="$LIVE/nodes/$1.pid"
  if running "$1"; then
    kill -INT "$(cat "$pidfile")"
    # So that it can be started again at once, on the same port.
    for _ in $(seq 60); do
      running "$1" || break
      sleep 0.5
    done
  fi
  rm -f "$pidfile"
}

case "${1:-}" in
  route) route "$2" ;;
  sync) cassis "$2" sync ;;
  stop) stop "$2" ;;
  pay) cassis "$2" pay --from "$3" --invoice "$4" --nostr-relay "$RELAY" ;;
  route-of) cassis funder route --from "$2" --to "$3" --amount-msat "$4" --nostr-relay "$RELAY" ;;
  balance) wallet_balance "$2" "$3" ;;
  address) wallet_address "$2" "$3" "$4" ;;
  onboard) wallet_op "$2" "$3" onboard ;;
  hops) admin_js "$2" 'query(e => e.id.startsWith("hops/count/") || e.id.startsWith("hop/")).forEach(e => print(e.attrs.text));' ;;
  "") echo "usage: see $0" >&2; exit 1 ;;
  *) cassis "$@" ;;
esac
