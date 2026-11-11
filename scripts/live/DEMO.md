# Live demo payments

How to run demo payments over the live environment, what they should
print, and what went wrong the first time. Transcripts of the runs below
are in `demo-logs/2026-11-09/`. `README.md` has the environment itself.

## Run it

Needs the environment of `README.md` set up and funded once, and `hypb`
on `PATH` or in `$HYPB`. With `tmp/live` already there:

```sh
cargo build -p cassis-wallet -p cassis-routerd -p cassis-gateway -p cassis-preimage-server
scripts/live/up.sh                 # some minutes: mints, federation, arkd, r1-r7
scripts/live/demo.sh balances      # check the budget below first
scripts/live/demo.sh offline       # ~2 min; starts the gateway and preimage server
scripts/live/demo.sh online        # ~7 min
scripts/live/down.sh               # once nothing is left to refund
```

Every step of the transcript ends in `exit <n>`, and a failed payment is
`exit 1` with `payer: error: ...`. Compare with
`demo-logs/2026-11-09/{06-demo-offline,07-demo-online}.log`. Their
hashes, ids and times will differ; their steps and outcomes should not.

## Budget

One `online` plus one `offline` moved this much (msat amounts are rounded):

| Who | Spends | Left on 2026-11-09 | Runs left |
|---|---|---|---|
| alice, mint 1 | ~9000 sat | 18 893 sat | 2 |
| henry, our arkade | ~1005 sat | 1 970 sat | 1 |
| grace, public mint | ~600 sat, earns 1000 | 1 276 sat | many |
| r2, Rootstock | ~4000 sat | 5 848 sat | 1 |
| r3, fedimint | ~3300 sat | 4 525 sat | 1 |
| gateway, mint 2 | ~2500 sat | 15 000 sat | 6 |
| gateway, our arkade | ~500 sat | 2 000 sat | 4 |

Routers' funds move between their two networks rather than leave, so one
side of each runs out. Top up with `mint.sh fund` (free, for alice), and
for routers `mint.sh fund`, `funder.sh send-rbtc "$(node.sh address r2 $R
Rootstock)" <sats>`, `fedimint.sh fund r3 <sats>`. The funder held 19 380
sat on mutinynet and 17 957 on Rootstock after these runs: ask for more
before it gets below what a top-up needs. Do not use `arkd.sh give` on a
wallet that has coins (finding m).

## What each demo shows

Online, in `demo.sh online`:

| Payment | Route | Seconds |
|---|---|---|
| alice → bob | 1 hop, mint 1 → mint 2 | 4 |
| alice → carol | 2 hops → Rootstock | 66 |
| alice → dave | 3 hops → fedimint | 75 |
| alice → erin | 4 hops → arkade::mutinynet | 120 |
| alice → frank, 500 sat | 2 hops → our arkade, through r7 | 4 |
| alice → grace | 2 hops → public mint | 5 |
| grace → dave, 300 sat | 3 hops out of the public mint | 40 |
| henry → dave | 3 hops, our arkade → cashu → Rootstock → fedimint | 99 |

Offline, in `demo.sh offline`, with the gateway on both mints and our
arkade. The payee has no process running when it is paid:

| Step | What happens | Expected |
|---|---|---|
| A | bob asks the gateway for one invoice, leaves; alice pays on mint 1; the gateway pays bob on mint 2; bob comes back and `redeem`s | paid, `claimed` |
| B | bob `authorize`s the gateway once, up to 3000 sat | prints the authorization |
| B1 | alice, not bob, asks the gateway for an invoice in bob's name with `request-invoice`, and pays it | paid |
| B2 | bob comes back and `redeem`s | `claimed` |
| B3 | alice asks for 3000.001 sat | refused: `this payee authorized no invoice like this one` |
| B4 | alice asks for dave, who never authorized | the same refusal |
| C | grace pays from the public mint, through r6, to the gateway on mint 2 | paid, `claimed` |
| D | frank asks for an invoice on arkade with the default final timeout of a week | refused locally: `takes HTLCs running at most 13162s` |
| D2 | the same with `--min-final-timeout 3600`; the gateway pays a VHTLC to frank | paid, `claimed` |

The last step prints what the two daemons' admin pages count: forwards
and invoices on the gateway, and what the preimage server released.

## What went wrong, and why

The first pass (`02-online.log` to `05-offline.log`) is kept because these
will happen again. None came from moving routers to `cassis-routerd`.

1. **`leg N would run ...s, its router accepts at most 2402s`** on alice →
   erin and henry → dave. r5 learns our operator's batch lifetime from
   the VTXOs its wallet ever held, and it only held ones from the old 1h
   batches (`operator batches last 3602s` in `r5.log`). Being the cheapest
   way out of our arkade, it is on those routes, and the payer does not
   try another. `arkd.sh give r5` cannot fix it (finding m), `onboard` has
   nothing to do, and a route's `max_incoming_lifetime_secs` only
   shortens. So `demo.sh online` removes r5's routes, which also deletes
   their announcements, and puts them back after. To do it by hand:
   `admin_act r5 route.remove '{"from":"…","to":"…"}'`, wait 15s, and
   `node.sh route r5` to restore. *Since then routers announce no
   lifetime and payers plan within none, so `demo.sh online` no longer
   takes r5 out: arkade's batch expiry is left to its own checks until a
   better rule replaces the lifetime.*
2. **`hop 4 failed: incoming HTLC rejected: invalid: contract expires
   before the expiry`** on alice → erin (`04-online-retry.log`), which
   paid on retry. The fedimint sender locks exactly as many blocks as the
   time left, and the receiver wants as many left when it verifies, with
   no margin. Intermittent: 1 of the 9 fedimint hops of these runs. The
   route stays locked until expiry, so `7542fbd` holds 1006 sat of alice's
   until unix time 1794228515. Routers refund on their own; alice with
   `node.sh sync alice` after that.
3. **`arkd.sh give` fails with `no coin selection possible`**: the operator
   lacks on-chain funds for the batch. `arkd.sh fund 10000` fixed it, and
   the money moved from the funder to it.

## Reading the results

- Use `node.sh balance <router> <network>` while it runs: `cassis <router>`
  refuses on a running daemon.
- Gateway forwards earn nothing: it took in and paid out the same 6600 sat.
- A payment's `payer:` line can be `paid` while the payee is `not claimed`
  or the reverse: check both, or the `exit` line, which needs both.
