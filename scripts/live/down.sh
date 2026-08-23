#!/usr/bin/env bash
# Stop everything up.sh started. State under $LIVE is kept.
set -uo pipefail
source "$(dirname "$0")/env.sh"
S="$LIVE_SCRIPTS"

for pidfile in "$LIVE"/nodes/*.pid; do
  [ -e "$pidfile" ] && "$S/node.sh" stop "$(basename "$pidfile" .pid)"
done
"$S/arkd.sh" stop
"$S/fedimint.sh" stop
"$S/mint.sh" stop 1
"$S/mint.sh" stop 2
"$S/relay.sh" stop
