#!/usr/bin/env bash
# pay.sh hook: SIGKILL the payee's invoice waiter once the last router,
# $LAST, forwarded payment $1: every hop is then locked and nobody can
# claim, so everything must be refunded at expiry.
#
#   LAST=r3 PAYEE=dave scripts/live/pay.sh henry $AL dave 1000000 scripts/live/hooks/kill-payee.sh
set -euo pipefail
source "$(dirname "$0")/../env.sh"

log="$LIVE/nodes/$LAST.log"
until sed 's/\x1b\[[0-9;]*m//g' "$log" | grep -q "EXECUTE $1: forwarded"; do sleep 0.2; done
for pid in $(pgrep -f "nodes/$PAYEE invoice"); do kill -9 "$pid"; done
echo "hook: killed $PAYEE after $LAST forwarded $1" >&2
