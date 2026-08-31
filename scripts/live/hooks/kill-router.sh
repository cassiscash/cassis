#!/usr/bin/env bash
# pay.sh hook: SIGKILL router $ROUTER mid-payment, as soon as it logs
# that it accepted the PREPARE (`AT=prepare`, the default) or forwarded
# its outgoing HTLC (`AT=execute`) for payment $1.
#
#   ROUTER=r3 scripts/live/pay.sh henry $AL dave 1000000 scripts/live/hooks/kill-router.sh
set -euo pipefail
source "$(dirname "$0")/../env.sh"

case "${AT:-prepare}" in
  prepare) line="PREPARE $1 accepted" ;;
  execute) line="EXECUTE $1: forwarded" ;;
  *) echo "AT must be prepare or execute" >&2; exit 1 ;;
esac
log="$LIVE/nodes/$ROUTER.log"
until sed 's/\x1b\[[0-9;]*m//g' "$log" | grep -q "$line"; do sleep 0.2; done
kill -9 "$(cat "$LIVE/nodes/$ROUTER.pid")"
rm "$LIVE/nodes/$ROUTER.pid"
echo "hook: killed $ROUTER at: $line" >&2
