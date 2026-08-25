# Live tests

Manual end-to-end tests of `cassis-cli` routers and wallets on real
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
tmp/live/nodes/<name>/   cassis-cli homes (seed, store.db, wallets)
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
| `node.sh` | `route`/`serve`/`stop` nodes in the background, `pay`, `route-of` |
| `pay.sh` | one payment with the payee serving its invoice, plus an optional failure hook |
| `up.sh` / `down.sh` | bring everything up / down again |
| `arkd/build.sh` | builds `target/arkd-light` (needs go) |

Needs on `PATH`: `cdk-mintd`, `cdk-cli`, `nak`, `curl`; and
`tmp/fedimintd-v0.12.1` (or `$CASSIS_FEDIMINTD`).

## First-time setup

```sh
cargo build -p cassis-cli
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

for r in r1 r2 r3 r4 r5 r6; do scripts/live/node.sh route $r; done
```

Afterwards `scripts/live/up.sh` / `down.sh` restart it all.

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
scripts/live/pay.sh alice $M1 dave 1000000 ./hook.sh     # hook gets the short hash
```

Inspect state with `cassis <node> payments|invoices|hops` and the
routers' logs (`tmp/live/nodes/<router>.log`). Expired HTLCs are only
refunded by a serving node: `node.sh serve alice` for a payer.

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
e. `invoice --network X` accepts networks the node has not enabled; its
   `run` would never claim such an invoice.
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
