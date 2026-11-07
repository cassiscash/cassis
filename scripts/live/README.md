# Live tests

Manual end-to-end tests of `cassis-wallet` wallets and (formerly `cassis-cli --route`) routers on real
test networks, replacing the old `cassis-playground`. Everything runs
on **mutinynet** (through its esplora, `https://mutinynet.com/api`; no
bitcoind) and **Rootstock testnet**, plus local fake-wallet cashu mints.
Payments are never routed through bitcoin itself: only the "L2"
ledgers below.

| Ledger | Network id | Who runs it | Funded by |
|---|---|---|---|
| local cashu mint 1 | `cashu::127.0.0.1:3338` | us, `cdk-mintd` fakewallet | `mint.sh fund` (free) |
| local cashu mint 2 | `cashu::127.0.0.1:3339` | us, `cdk-mintd` fakewallet | `mint.sh fund` (free) |
| mutinynet cashu mint | `cashu::cashu.mutinynet.com` | public (Nutshell, 100 ppk input fee) | bolt11 via `mint.sh fund-external` |
| our federation | `fedimint::<fedimint.sh invite>` | us, 1-guardian `fedimintd` on mutinynet esplora | peg-in via `fedimint.sh fund` |
| mutinynet federation | `fedimint::fed11qgqzc2nh…` (see env.sh) | public | peg-in (down when tested) |
| our arkade operator | `arkade::127.0.0.1:7070` | us, `arkd-light` on mutinynet esplora | arknotes via `arkd.sh give` |
| public arkade operator | `arkade::mutinynet` | public | boarding + `onboard` |
| Rootstock testnet | `rootstock::testnet` | public node | `funder.sh send-rbtc` |

Lightning (two LND nodes on mutinynet) is not covered yet: LND has no
esplora backend (only the unmerged lnd#10538), and neutrino rejects
mutinynet's 30s-block difficulty retargets.

## Layout

All state lives in `tmp/live/` (git-ignored):

```text
tmp/live/nodes/<name>/   cassis-wallet homes (seed, store.db, wallets)
tmp/live/nodes/<name>.log|.pid   routers running in the background
tmp/live/mint<n>/        local cdk-mintd
tmp/live/fedimint/       our fedimintd (invite-code here)
tmp/live/arkd/           our arkd-light
tmp/live/cdk-cli/        cdk-cli wallet used to mint test ecash
```

Scripts (all source `env.sh`; `cassis <node> <args>` is the CLI on a
node's home):

| Script | Does |
|---|---|
| `funder.sh` | the faucet node: `address`, `balance`, `send-btc`, `send-rbtc` |
| `relay.sh` | private `nak serve` relay for route announcements |
| `mint.sh` | local mints; `fund` (free ecash), `fund-external` (real mints) |
| `fedimint.sh` | our federation: `start` (runs DKG through the guardian UI), `invite`, `fund` |
| `arkd.sh` | our operator: `start`, `fund` (on-chain float), `note`, `give` |
| `node.sh` | `route`/`stop` nodes in the background, `sync`, `pay`, `route-of` |
| `pay.sh` | one payment with the payee serving its invoice, plus an optional failure hook |
| `up.sh` / `down.sh` | bring everything up / down again |
| `hooks/` | `pay.sh` failure hooks: `kill-router.sh`, `kill-payee.sh` |
| `arkd/build.sh` | builds `target/arkd-light` (needs go) |

Needs on `PATH`: `cdk-mintd`, `cdk-cli`, `nak`, `curl`; and
`tmp/fedimintd-v0.12.1` (or `$CASSIS_FEDIMINTD`).

## First-time setup

```sh
cargo build -p cassis-wallet
scripts/live/funder.sh address       # send mutinynet sats + tRBTC here
scripts/live/funder.sh balance

scripts/live/relay.sh start
scripts/live/mint.sh start 1; scripts/live/mint.sh start 2
scripts/live/fedimint.sh start
scripts/live/arkd.sh start && scripts/live/arkd.sh fund 30000
source scripts/live/env.sh
M1=cashu::127.0.0.1:3338 M2=cashu::127.0.0.1:3339
F=$(scripts/live/fedimint.sh invite) A=arkade::mutinynet AL=arkade::127.0.0.1:7070
R=rootstock::testnet

# Nodes: alice pays; bob, carol, dave, erin, frank receive.
cassis alice enable $M1;         scripts/live/mint.sh fund 1 alice 40000
cassis r1 enable $M1 $M2;        scripts/live/mint.sh fund 1 r1 10000; scripts/live/mint.sh fund 2 r1 10000
cassis r2 enable $M2 $R;         scripts/live/mint.sh fund 2 r2 10000
scripts/live/funder.sh send-rbtc "$(cassis r2 rootstock --network $R address)" 25000
cassis r3 enable $R $F;          scripts/live/fedimint.sh fund r3 20000
scripts/live/funder.sh send-rbtc "$(cassis r3 rootstock --network $R address)" 5000   # claim gas
cassis r4 enable $F $A
scripts/live/funder.sh send-btc "$(cassis r4 arkade --network $A address | sed -n 's/boarding: //p')" 20000
cassis r4 arkade --network $A onboard   # after the boarding tx confirms
cassis r5 enable $A $AL;         scripts/live/arkd.sh give r5 10000
cassis carol enable $R           # needs a little RBTC for claim gas, see findings
cassis bob enable $M2; cassis dave enable $F; cassis erin enable $A; cassis frank enable $AL

# The public mint: pay the printed bolt11 from faucet.mutinynet.com.
MM=cashu::cashu.mutinynet.com
cassis r6 enable $M2 $MM;        scripts/live/mint.sh fund 2 r6 10000
scripts/live/mint.sh fund-external cashu.mutinynet.com r6 20000          # prints quote + bolt11
scripts/live/mint.sh fund-external cashu.mutinynet.com r6 20000 <quote>  # after paying
cassis grace enable $MM

# Arkade-first routes: henry pays from our arkd, r7 bridges it to mint 2.
cassis henry enable $AL;         scripts/live/arkd.sh give henry 6000
cassis r7 enable $AL $M2;        scripts/live/mint.sh fund 2 r7 10000; scripts/live/arkd.sh give r7 6000

for r in r1 r2 r3 r4 r5 r6 r7; do scripts/live/node.sh route $r; done
```

Afterwards `scripts/live/up.sh` / `down.sh` restart it all;
`ROUTERS="r1 r2 r3" scripts/live/up.sh` starts only some routers.

`arkd.sh give` only works on a wallet without live VTXOs (finding m):
fund a wallet once, then move sats with `cassis <node> arkade send`.
Our arkd's batches last 4h (`ARKD_VTXO_TREE_EXPIRY`, see `arkd.sh`):
coins older than that are swept and read as 0 until
`cassis <node> arkade --network $AL onboard` settles them into a new
batch.

## Running payments

```sh
scripts/live/node.sh route-of $M1 $AL 1000000            # inspect the route
scripts/live/pay.sh alice $M1 bob 1000000                # 1 hop  (cashu → cashu)
scripts/live/pay.sh alice $M1 carol 1000000              # 2 hops (→ rootstock)
scripts/live/pay.sh alice $M1 dave 1000000               # 3 hops (→ fedimint)
scripts/live/pay.sh alice $M1 erin 1000000               # 4 hops (→ arkade::mutinynet)
scripts/live/pay.sh alice $M1 frank 1000000              # 5 hops (→ our arkade)
scripts/live/pay.sh alice $M1 grace 1000000              # 2 hops (→ cashu.mutinynet.com)
scripts/live/pay.sh grace $MM dave 500000                # 3 hops out of the public mint
scripts/live/pay.sh henry $AL dave 1000000              # 4 hops (arkade → cashu → rootstock → fedimint)
```

The payer takes the cheapest announced route, so stop the routers of
a shorter one to force a longer one: for henry's route, `node.sh stop
r4; node.sh stop r5`, then restart the relay (`relay.sh stop; relay.sh
start`, it forgets their announcements) and the remaining routers.

Inspect state with `cassis <node> payments|invoices|hops` and the
routers' logs (`tmp/live/nodes/<router>.log`). Expired HTLCs are only
refunded by a running router or, for a payer, by `node.sh sync alice`
once they expired.

## Failure and refund tests

`pay.sh`'s fifth argument is a hook run in the background with the
payment's short hash (its last 7 hex digits, as logs print it), to break
the payment midway:

```sh
H=scripts/live/hooks
# A router dies after accepting PREPARE: the payer fails at that hop,
# the routers before it refund at expiry.
ROUTER=r3 scripts/live/pay.sh henry $AL dave 1000000 $H/kill-router.sh
# A router dies after forwarding (AT=execute): restart it with
# `node.sh route r3`; it must settle or refund on its own.
AT=execute ROUTER=r3 scripts/live/pay.sh henry $AL dave 1000000 $H/kill-router.sh
# The payee dies once every hop is locked: everything refunds at expiry.
LAST=r3 PAYEE=dave scripts/live/pay.sh henry $AL dave 1000000 $H/kill-payee.sh
```

Then, for each test:

1. Routers refund on their own; the payer refunds its own HTLC with
   `scripts/live/node.sh sync henry` once it expired (step 3).
2. Note each lock's expiry: `locked … until <unix time>` in the routers'
   logs, and the payer's in `tmp/live/nodes/henry.pay.log`. The first
   leg expires last, over an hour later on long routes; rootstock and
   fedimint refunds wait for a few more blocks after it.
3. Once past it, every hop should log `<hash> refunded on <network>`:
   `grep <hash> tmp/live/nodes/*.log`, and `cassis <node> hops` shows
   `Refunded` on routers, `cassis henry payments` on the payer.

Restart killed routers with `node.sh route <router>` before the next
test.

## Results (2026-11-03)

Topology: `alice ─cashu1─ r1 ─cashu2─ r2 ─rootstock─ r3 ─fedimint(ours)─
r4 ─arkade::mutinynet─ r5 ─arkade(ours)─ frank`, payees at each stop;
plus `r6` between cashu2 and `cashu.mutinynet.com` (payee grace).

| Test | Result |
|---|---|
| 1 hop cashu → cashu | paid, 4s |
| 2 hops → rootstock | paid after fixes 1, 3 (2 min: Rootstock receipts) |
| 3 hops → fedimint | paid, 54s; payee nets 995 328 of 1 000 000 msat (finding d) |
| 4 hops → arkade::mutinynet | paid, 1m39s |
| 5 hops → our arkade | paid, 46s |
| 2 hops → cashu.mutinynet.com | paid, 5s; grace nets 999 of 1000 sat, r6 pays 1 sat too (input fees, finding d) |
| 3 hops cashu.mutinynet.com → fedimint | paid, 37s |
| amount above a router's liquidity | refused at PREPARE, nothing locked, 4s |
| expired invoice | refused before paying |
| invoice on a network no router reaches | "no route", nothing locked |
| router offline (stale announcement) | fails at PREPARE after a 60s connect timeout, nothing locked |
| payee offline | **all hops locked until expiry** (~1.8h), finding b |
| rootstock payee without RBTC | claim fails, route locked until expiry, finding a |
| router killed after EXECUTE, restarted | payer waits, then payee refuses: claim window passed (by design); everything refunds at expiry |
| router killed as payee claims, restarted | payer paid; restarted router finds the downstream claim on chain (fix 2) and settles |
| expired HTLCs | every stopped payment (payee offline, router killed, claim failed) refunded at every hop: routers on their own on cashu, rootstock, fedimint and arkade::mutinynet; the payer (3 payments, 3015 sat) once serving |

Arkade → cashu → rootstock → fedimint (2026-11-03, `henry ─arkade(ours)─
r7 ─cashu2─ r2 ─rootstock─ r3 ─fedimint─ dave`; r4/r5 stopped and the
relay restarted so the shorter arkade route is not announced):

| Test | Result |
|---|---|
| 3 hops arkade → fedimint | paid, 127s |
| r3 SIGKILLed right after accepting PREPARE | payer fails at hop 3 (connect timeout); r7 (cashu) and r2 (rootstock) refund on their own at expiry |
| payee SIGKILLed after every hop locked | r7 (cashu), r2 (rootstock), r3 (fedimint) refund on their own at expiry |
| payer's own arkade refunds (both tests) | **failed**: our arkd swept the VHTLC VTXOs at batch expiry (~1h, `ARKD_VTXO_TREE_EXPIRY=3584`) before the refunds opened (~1.5h); 2009 sat stuck, fix 7 |
| after fix 7, 1h batches | r7 announces 2270s; payer refuses before locking: `leg 0 would run 5520s, its router accepts at most 2270s` |
| after fix 7, 4h batches, r7 `--max-incoming-lifetime 13136` | paid, 74s |
| after fix 7, payee SIGKILLed after every hop locked | everyone refunds at expiry, the payer's arkade lock included (its batch outlived it by 2.4h) |
| alice → r1 → r7 → frank (arkade), r7 holding one 1005 sat VTXO | lock failed: 4 sat change, below the 330 sat dust limit (fix 8) |
| the same after fix 8, change would be 310 sat | refused at PREPARE, nothing locked, 4s |
| the same, 1000 sat of r7's 1005 + 2005 sat VTXOs | paid, 4s |
| the same 1.6h later, r7's 2010 sat change expiring 10 min before the HTLC deadline + margin | r7 refreshes it into a new batch (expiring 3.5h later), then locks: paid, 6s |

### Fixed

1. **Rootstock claims ran out of gas.** `claim()` had a fixed 30k limit
   but needs more before its storage-clear refund (net ~26k); `lock()`
   used 45.6k of 50k. Transactions now use the node's estimate + 25%.
2. **Rootstock senders could not see claims.** `check_outgoing_htlc`
   used `eth_getLogs`, which public Rootstock nodes do not serve
   (`-32601`): a router whose downstream claimed while COMMIT was lost
   would never learn the preimage. Falls back to `swaps()` and scanning
   blocks back from the tip for the `claim`/`refund` transaction.
3. **Rootstock timelocks were too short.** Blocks were assumed to be
   30s; testnet averages ~25s, so refunds opened before the agreed
   expiry, and the receiver's check failed at random at the boundary.
   Both sides now count 20s blocks, and the sender adds 10 blocks.
4. **Fedimint expirations assumed 10-minute blocks.** On a mutinynet
   (signet) federation, contracts expired 20× sooner than agreed: a
   router with fedimint as its incoming leg could see it refunded while
   its outgoing leg was still claimable. The interval now follows the
   federation's network (30s on signet).
5. **`invoice --wait` ignored Ctrl-C** (a network client installs its
   own SIGINT handler); it now stops on it.
6. **Settled hops were claimed again until they expired.** The settle
   loop worked on a hop listed at the start of its pass; when the
   payer's COMMIT settled it meanwhile, the loop found the downstream
   claim, claimed the incoming HTLC a second time (`Token Already
   Spent`, `swap has no Ether locked`), overwrote `Settled` and retried
   until expiry, ending `Failed`. No funds lost; it now reloads the hop.
7. **Arkade HTLCs could outlive their batch.** An offchain VTXO expires
   with the batch it descends from, after which the operator sweeps it
   and it can no longer be spent offchain: a VHTLC locked for longer
   could neither be refunded nor claimed (arkd: `VTXO_RECOVERABLE`), and
   the payer's payment stayed `Pending` forever. Now an HTLC must be
   over 20 minutes before its VHTLC's batch expires: receivers reject
   VHTLCs that are not, senders refresh soon-expiring coins into a new
   batch before locking, and routers announce
   `max_incoming_lifetime_secs` (the operator's batch lifetime, learnt
   from the wallet's VTXOs, less the margin; or `enable
   --max-incoming-lifetime`), which payers plan within and PREPARE
   enforces.
8. **Arkade sends could leave dust change.** The SDK's coin selection
   adds one more VTXO when the change would be below the operator's
   dust limit, but fails (`AMOUNT_TOO_LOW`) when there is none left,
   after the router had accepted PREPARE and the upstream HTLC was
   locked. `can_send` now refuses such amounts at PREPARE.

### Open findings

a. A Rootstock payee with no RBTC cannot claim (`the sender account
   doesn't exist`); nothing checks `can_receive` when creating the
   invoice, so the route is locked until expiry.
b. The payer locks every hop before it ever contacts the payee: an
   offline payee ties up the whole route's liquidity until expiry.
   Pinging the payee first would avoid most of it.
c. Announcements of dead routers stay on the relay, so the same dead
   route is retried; connect timeouts take 60s; no alternative route.
d. Payee-side ledger costs come out of the invoice amount: fedimint
   claim fees (995 328 of 1 000 000 msat with base fees on), Rootstock
   claim gas (~18 sat), cashu.mutinynet.com input fees (1 sat each side).
e. `invoice --network X` accepts networks the node has not enabled; it
   would never claim such an invoice.
f. A second process on a home whose fedimint client is open (e.g. a
   leftover `invoice --wait`) hangs silently on the database lock.
g. Payers keep retrying a hop after the payee's claim window closed.
h. The public mutinynet federation (`fedimintd.fediminttwo.mutinynet.com`)
   refused connections; cassis only says "Failed to download client
   config".
i. `cassis-lnd` also converts expiries at 600s/block and `lightning`
   takes no parameter: a mutinynet LND router would announce the same
   `lightning` network as mainnet ones.
j. `invoice --expires-in 1` fails ("must be in the future") because
   opening networks takes longer than the expiry.
k. cashu.mutinynet.com rate-limits per IP (`Rate limit exceeded`), and
   cdk-cli's quote wait polls fast enough to trip it indefinitely: a
   cassis wallet polling a public mint for long could hit the same.
l. Wallet VTXOs expire with their batch too and nothing renews them
   unless an HTLC is about to be locked: a swept wallet VTXO reads as 0
   until `onboard` settles it into a new batch (henry's 4985 sat, r7's
   2005 sat). The two VHTLCs swept before fix 7 (2009 sat) stay
   recoverable at our arkd; spending them needs a batch intent, which
   ark-client 0.12 does not expose for custom scripts.
m. Redeeming an arknote into a wallet that already holds a live VTXO
   fails (`mismatch between VTXO count (2) and connector count (1)`):
   the SDK settles the note together with the VTXO and arkd builds a
   connector for the VTXO only. `arkd.sh give` only works on wallets
   without live VTXOs.
