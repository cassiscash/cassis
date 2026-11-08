#!/usr/bin/env bash
# One end-to-end payment between live nodes.
#
#   scripts/live/pay.sh <payer> <from network> <payee> <amount msat> [hook]
#
# The payee serves its invoice (`invoice` waits until paid) while the payer pays
# it over the private relay's routes. `hook`, if given, runs in the
# background with the payment hash's last 7 hex digits as $1 (how logs
# abbreviate it), to inject failures mid-payment. Prints both sides'
# outcome; logs at $LIVE/nodes/<name>.{inv,pay}.log.
#
# With OFFLINE=1 the payee is offline instead: the invoice comes from
# the gateway (scripts/live/offline.sh), and the payee only comes back to
# redeem once it is paid.
set -euo pipefail
source "$(dirname "$0")/env.sh"

payer="$1" from="$2" payee="$3" amount="$4" hook="${5:-}"
L="$LIVE/nodes"
offline="${OFFLINE:-}"
rm -f "$L/$payee.inv"
if [ -n "$offline" ]; then
  read -ra endpoints <<< "$("$LIVE_SCRIPTS/offline.sh" endpoints)"
  cassis "$payee" receive --amount-msat "$amount" "${endpoints[@]}" > "$L/$payee.inv" 2> "$L/$payee.inv.log" ||
    { grep -v DEBUG "$L/$payee.inv.log" | tail -3; exit 1; }
else
  cassis "$payee" invoice --amount-msat "$amount" > "$L/$payee.inv" 2> "$L/$payee.inv.log" &
  payee_pid=$!
  until [ -s "$L/$payee.inv" ]; do
    kill -0 "$payee_pid" 2> /dev/null || { grep -v DEBUG "$L/$payee.inv.log" | tail -3; exit 1; }
    sleep 0.5
  done
fi
invoice="$(head -1 "$L/$payee.inv")"
hash="$(sed -n 's/.*"payment_hash":"\([0-9a-f]*\)".*/\1/p' <<< "$invoice")"
echo "invoice ${hash: -7}: $amount msat to $payee"
[ -n "$hook" ] && { "$hook" "${hash: -7}" & }
start=$(date +%s)
if cassis "$payer" pay --from "$from" --invoice "$invoice" --nostr-relay "$RELAY" > "$L/$payer.pay.log" 2>&1; then
  echo "payer: $(tail -1 "$L/$payer.pay.log") ($(($(date +%s) - start))s)"
else
  echo "payer: $(grep -v DEBUG "$L/$payer.pay.log" | tail -1) ($(($(date +%s) - start))s)"
fi
if [ -n "$offline" ]; then
  # The gateway pays the payee once it is paid, which takes a moment.
  for _ in $(seq 24); do
    if cassis "$payee" redeem > "$L/$payee.redeem.log" 2>&1 && grep -q "^claimed $hash" "$L/$payee.redeem.log"; then
      echo "payee: redeemed"
      exit 0
    fi
    sleep 5
  done
  echo "payee: not redeemed: $(grep -v DEBUG "$L/$payee.redeem.log" | tail -1)"
  exit 1
fi
# The payee keeps serving a while after claiming (CLAIM_GRACE).
for _ in $(seq 60); do
  kill -0 "$payee_pid" 2> /dev/null || break
  grep -q '^claimed' "$L/$payee.inv" && break
  sleep 1
done
if grep -q '^claimed' "$L/$payee.inv"; then
  echo "payee: claimed"
else
  echo "payee: not claimed"
fi
kill -INT "$payee_pid" 2> /dev/null || true
