#!/usr/bin/env bash
# Demo payments over the live environment, printing a transcript. See
# DEMO.md for what to expect, and what it needs up and funded first.
#
#   scripts/live/demo.sh balances   what every router and wallet holds
#   scripts/live/demo.sh online     payments of 1 to 4 hops to payees
#                                   that stay up, with their routes
#   scripts/live/demo.sh offline    payments through the gateway and
#                                   preimage server, starting them
set -uo pipefail
source "$(dirname "$0")/env.sh"
S="$LIVE_SCRIPTS"
F="$(fedimint_network)"

step() { echo; echo "=== $* ($(date -u +%H:%M:%S))"; }
# A node's command, with only its errors besides its output.
w() { cassis "$1" "${@:2}" 2> >(grep -E '^error' >&2); }

pay() { # <label> <payer> <from> <payee> <msat> <to>
  step "$1: $2 pays $4 $5 msat"
  cassis funder route --from "$3" --to "$6" --amount-msat "$5" --nostr-relay "$RELAY" 2>&1 |
    grep -v -E 'DEBUG|INFO' | cut -c1-110
  "$S/pay.sh" "$2" "$3" "$4" "$5" 2>&1 | cut -c1-200
  echo "exit ${PIPESTATUS[0]}"
}

balances() {
  for pair in "r1 $M1" "r1 $M2" "r2 $M2" "r2 $R" "r3 $R" "r3 $F" "r4 $F" "r4 $A" "r5 $A" "r5 $AL" \
    "r6 $M2" "r6 $MM" "r7 $AL" "r7 $M2"; do
    read -r node network <<< "$pair"
    printf '%s %s: ' "$node" "${network:0:28}"
    "$S/node.sh" balance "$node" "$network" 2>&1 | tr '\n' ' '
    echo
  done
  for spec in "alice cashu $M1" "bob cashu $M2" "carol rootstock $R" "dave fedimint $F" \
    "erin arkade $A" "frank arkade $AL" "grace cashu $MM" "henry arkade $AL"; do
    read -r node kind network <<< "$spec"
    printf '%s %s: ' "$node" "${network:0:28}"
    cassis "$node" "$kind" --network "$network" balance 2> /dev/null | tail -1
  done
  for network in "$M1" "$M2" "$AL"; do
    [ -f "$LIVE/nodes/gateway.pid" ] || break
    printf 'gateway %s: ' "${network:0:28}"
    "$S/node.sh" balance gateway "$network" 2>&1 | tr '\n' ' '
    echo
  done
  printf 'funder: '
  "$S/funder.sh" balance 2> /dev/null | tr -s ' ' | tr '\n' ' '
  echo
  printf 'arkd: '
  "$S/arkd.sh" balance | cut -c1-70
}

online() {
  pay "1 hop, cashu to cashu" alice "$M1" bob 1000000 "$M2"
  pay "2 hops to rootstock" alice "$M1" carol 1000000 "$R"
  pay "3 hops to fedimint" alice "$M1" dave 1000000 "$F"
  pay "4 hops to arkade mutinynet" alice "$M1" erin 1000000 "$A"
  pay "2 hops to our arkade" alice "$M1" frank 500000 "$AL"
  pay "2 hops to the public mint" alice "$M1" grace 1000000 "$MM"
  pay "3 hops out of the public mint" grace "$MM" dave 300000 "$F"
  pay "3 hops, arkade first" henry "$AL" dave 1000000 "$F"
}

offline() {
  export OFFLINE_NETWORKS="$M1 $M2 $AL"
  step "start the gateway and preimage server"
  "$S/offline.sh" start 2>&1 | grep -v ' saved$' | sed "s#$LIVE#\$LIVE#" | cut -c1-110
  local endpoints bob dave invoice hash out
  read -ra endpoints <<< "$("$S/offline.sh" endpoints)"
  echo "gateway ${endpoints[1]}"
  echo "preimage server ${endpoints[5]}"

  step "fund the gateway, unless it has funds"
  case "$("$S/node.sh" balance gateway "$M2")" in *": 0 sat") "$S/mint.sh" fund 2 gateway 20000 ;; esac
  case "$("$S/node.sh" balance gateway "$AL")" in *": 0 sat") "$S/arkd.sh" give gateway 3000 ;; esac
  "$S/node.sh" balance gateway "$M2"
  "$S/node.sh" balance gateway "$AL"

  step "A. one invoice: bob offline, alice pays on mint 1, the gateway pays bob on mint 2"
  OFFLINE=1 "$S/pay.sh" alice "$M1" bob 1000000 2>&1 | cut -c1-140
  echo "exit ${PIPESTATUS[0]}"
  grep '^claimed' "$LIVE/nodes/bob.redeem.log" | cut -c1-120

  step "B. standing authorization: bob authorizes once and leaves"
  bob="$(w bob info | sed -n 's/^payee key (iroh id): //p')"
  w bob authorize "${endpoints[@]}" --network "$M2" --max-amount-msat 3000000 --valid-for 86400 |
    jq -c '{destinations: (.destinations | map(.network)), max_amount_msat, min_amount_msat}'
  echo "exit ${PIPESTATUS[0]}"

  step "B1. alice asks the gateway for an invoice in bob's name, and pays it"
  invoice="$(w alice request-invoice --gateway "${endpoints[1]}" --gateway-relay "${endpoints[3]}" \
    --payee "$bob" --amount-msat 1500000 --description 'standing demo')"
  echo "$invoice" | jq -c '{payment_hash, amount_msat, networks: (.networks | map(.network))}'
  hash="$(echo "$invoice" | jq -r .payment_hash)"
  w alice pay --from "$M1" --invoice "$invoice" --nostr-relay "$RELAY" | cut -c1-100
  echo "exit ${PIPESTATUS[0]}"

  step "B2. bob comes back and redeems it"
  for _ in $(seq 12); do
    out="$(w bob redeem)"
    grep -q "^claimed $hash" <<< "$out" && break
    sleep 5
  done
  echo "$out" | cut -c1-120

  step "B3. refused: above bob's limit"
  w alice request-invoice --gateway "${endpoints[1]}" --gateway-relay "${endpoints[3]}" \
    --payee "$bob" --amount-msat 3000001 2>&1 | cut -c1-160
  echo "exit ${PIPESTATUS[0]}"

  step "B4. refused: a payee who never authorized (dave)"
  dave="$(w dave info | sed -n 's/^payee key (iroh id): //p')"
  w alice request-invoice --gateway "${endpoints[1]}" --gateway-relay "${endpoints[3]}" \
    --payee "$dave" --amount-msat 1000000 2>&1 | cut -c1-160
  echo "exit ${PIPESTATUS[0]}"

  step "C. routed to the gateway: grace pays from the public mint through r6"
  OFFLINE=1 "$S/pay.sh" grace "$MM" bob 300000 2>&1 | cut -c1-140
  echo "exit ${PIPESTATUS[0]}"
  grep '^claimed' "$LIVE/nodes/bob.redeem.log" | cut -c1-120

  step "D. refused: frank on arkade, with the default final timeout of a week"
  w frank receive --amount-msat 500000 --network "$AL" "${endpoints[@]}" 2>&1 | cut -c1-200
  echo "exit ${PIPESTATUS[0]}"

  step "D2. frank on arkade, offline for at most an hour"
  invoice="$(w frank receive --amount-msat 500000 --network "$AL" "${endpoints[@]}" --min-final-timeout 3600)"
  hash="$(echo "$invoice" | jq -r .payment_hash)"
  w alice pay --from "$M1" --invoice "$invoice" --nostr-relay "$RELAY" | cut -c1-100
  echo "exit ${PIPESTATUS[0]}"
  for _ in $(seq 12); do
    out="$(w frank redeem)"
    grep -q "^claimed $hash" <<< "$out" && break
    sleep 5
  done
  echo "$out" | cut -c1-150

  step "what their pages say"
  for daemon in gateway preimage; do
    admin_js "$daemon" 'query(e => /^(forwards\/count\/|invoices\/count\/|released\/.*\/value|released\/open)/.test(e.id)).forEach(e => print(e.id + ": " + e.attrs.text));'
  done
}

case "${1:-}" in
  balances | online | offline) "$1" ;;
  *) echo "usage: $0 balances | online | offline" >&2; exit 1 ;;
esac
