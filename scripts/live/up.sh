#!/usr/bin/env bash
# Bring the live environment up: relay, local mints, our federation, our
# arkd, then every router home under $LIVE/nodes listed in ROUTERS.
# Idempotent across restarts: state lives under $LIVE. See README.md for
# first-time setup and funding.
set -euo pipefail
source "$(dirname "$0")/env.sh"
S="$LIVE_SCRIPTS"

ROUTERS="${ROUTERS:-r1 r2 r3 r4 r5 r6}"

"$S/relay.sh" start
"$S/mint.sh" start 1
"$S/mint.sh" start 2
"$S/fedimint.sh" start
"$S/arkd.sh" start
for router in $ROUTERS; do
  [ -d "$LIVE/nodes/$router" ] && "$S/node.sh" route "$router"
done
