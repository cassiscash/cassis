#!/usr/bin/env bash
# Cassis dev control pane.
#
# Waits for the 3 mints to come up, mints money at each mint, delivers
# cashu to the two cli users (user1 at mint1, user3 at mint3), and funds
# the rootstock leg by sending 1000 testnet sats from router2's rootstock
# key (reused ./tmp/rsk-seed) to router3's rootstock address.
#
# Run from the repository root, inside the zellij "ctrl" pane.
set -uo pipefail

BIN="target/debug/cassis-cli"
MINT1="http://127.0.0.1:8091"
MINT2="http://127.0.0.1:8092"
MINT3="http://127.0.0.1:8093"

say()  { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
err()  { printf '\033[1;31m[ctrl] error: %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[ctrl] warn: %s\033[0m\n' "$*"; }

wait_mint() { # $1 url $2 label
  local n=0
  until curl -sf "$1/v1/info" >/dev/null 2>&1; do
    if [ $n -ge 60 ]; then err "$2 not up after 60s"; return 1; fi
    n=$((n+1)); sleep 1
  done
  say "$2 is up ($1)"
}

# ---- wait for infrastructure ---------------------------------------------
say "waiting for mints"
wait_mint "$MINT1" mint1 || true
wait_mint "$MINT2" mint2 || true
wait_mint "$MINT3" mint3 || true

# ---- mint money at each mint (cdk-cli fake wallet auto-pays the invoice) -
# mint1 -> cdk1 wallet, mint2 -> cdk2 wallet, mint3 -> cdk3 wallet
say "minting money at the mints"
cdk-cli -w tmp/cdk1 -n mint "$MINT1" 1000 2>&1 | tail -n 1
cdk-cli -w tmp/cdk2 -n mint "$MINT2" 1000 2>&1 | tail -n 1
cdk-cli -w tmp/cdk3 -n mint "$MINT3" 1000 2>&1 | tail -n 1

# ---- deliver mint1 money -> user1 ----------------------------------------
say "funding user1 (mint1)"
TOKEN1="$(cdk-cli -w tmp/cdk1 -n send -a 1000 --mint-url "$MINT1" 2>/dev/null | grep -E '^cashuB' | head -n 1)"
if [ -z "$TOKEN1" ]; then err "no token from cdk1"; else
  "$BIN" --home tmp/user1 cashu receive --proof "$TOKEN1" 2>&1 | tail -n 5
fi

# ---- deliver mint3 money -> user3 ----------------------------------------
say "funding user3 (mint3)"
TOKEN3="$(cdk-cli -w tmp/cdk3 -n send -a 1000 --mint-url "$MINT3" 2>/dev/null | grep -E '^cashuB' | head -n 1)"
if [ -z "$TOKEN3" ]; then err "no token from cdk3"; else
  "$BIN" --home tmp/user3 cashu receive --proof "$TOKEN3" 2>&1 | tail -n 5
fi

# ---- fund the rootstock leg ----------------------------------------------
# router2's rootstock key (copied ./tmp/rsk-seed) is the funder; send 1000
# testnet sats to router3's rootstock address (the other node on rsk).
say "funding rootstock::testnet leg (router2 -> router3)"
RSK3_ADDR="$("$BIN" --home tmp/router3 rootstock --network rootstock::testnet info 2>/dev/null | awk '/address:/{print $2}')"
if [ -z "$RSK3_ADDR" ]; then
  warn "could not determine router3 rootstock address; skipping rsk funding"
else
  "$BIN" --home tmp/router2 rootstock --network rootstock::testnet send \
    --to "$RSK3_ADDR" --amount-msat 1000 2>&1 | tail -n 6 || \
    warn "rsk send failed (does rsk-seed hold testnet RBTC?)"
fi

# ---- report ---------------------------------------------------------------
say "done. user balances:"
"$BIN" --home tmp/user1 cashu balance --network cashu::127.0.0.1:8091 2>&1 | tail -n 4
"$BIN" --home tmp/user3 cashu balance --network cashu::127.0.0.1:8093 2>&1 | tail -n 4
echo
printf '\033[1;32mctrl setup finished (keeping pane open). Ctrl-C to close.\033[0m\n'
