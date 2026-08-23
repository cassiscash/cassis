#!/usr/bin/env bash
# One end-to-end payment between live nodes.
#
#   scripts/live/pay.sh <payer> <from network> <payee> <amount msat> [hook]
#
# The payee serves its invoice (`invoice --wait`) while the payer pays
# it over the private relay's routes. `hook`, if given, runs in the
# background with the payment hash's last 7 hex digits as $1 (how logs
# abbreviate it), to inject failures mid-payment. Prints both sides'
# outcome; logs at $LIVE/nodes/<name>.{inv,pay}.log.
set -euo pipefail
source "$(dirname "$0")/env.sh"

payer="$1" from="$2" payee="$3" amount="$4" hook="${5:-}"
L="$LIVE/nodes"
rm -f "$L/$payee.inv"
cassis "$payee" invoice --amount-msat "$amount" --wait > "$L/$payee.inv" 2> "$L/$payee.inv.log" &
payee_pid=$!
until [ -s "$L/$payee.inv" ]; do
  kill -0 "$payee_pid" 2> /dev/null || { grep -v DEBUG "$L/$payee.inv.log" | tail -3; exit 1; }
  sleep 0.5
done
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
