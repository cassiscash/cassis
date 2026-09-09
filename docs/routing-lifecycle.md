# Payment routing lifecycle

Walk-through of one payment through a Cassis route, in order, with the
decisions each actor makes and what can go wrong at every step.

Three actors take part:

| Actor | Role |
|---|---|
| **Payer** (`cassis-client`) | Builds the route, funds the first HTLC, walks the hops, COMMITs to the payee, monitors/refunds its own outgoing HTLC. |
| **Router** (`cassis-router`) | One hop. Receives on one network, forwards on another, watches for the preimage, claims incoming / refunds outgoing. |
| **Payee** (`cassis-cli` receive side) | Originates the preimage, claims the final HTLC on COMMIT. |

A payment's `payment_hash` is `SHA256(preimage)`. The payee holds the
preimage; every other party only ever learns it after funding an HTLC
locked to that hash. The same hash threads through every hop, which is
what makes the cross-network swap atomic.

---

## 1. Payer: find a route

`CassisClient::pay` starts from the invoice and the payer's own network.

**Decisions**

- Take the destination network from `invoice.networks`.
- Query Nostr kind-35515 announcements, build the routing graph, run
  `find_route` toward the destination.
- If the route is empty (payer and payee share one network), take the
  same-network shortcut (skip to step 6).
- Validate the route forms an unbroken network chain
  (`validate_route_networks`): hop `i`'s `outgoing` must equal hop
  `i+1`'s `incoming`, the first hop's `incoming` must equal the
  payer's network, the last hop's `outgoing` the invoice's network.

**What could go wrong**

- **No announcements / no route** → pay fails with a route error. Nothing
  funded yet, nothing to unwind.
- **Discontiguous route** → rejected before any reservation. Cheap guard
  against locking an HTLC to a claim identity that is meaningless on a
  different network.
- **Invoice missing a network hint** → pay fails immediately.

---

## 2. Payer: compute the deadline cascade

For every leg (each router hop plus a final leg for the payee) the payer
adds a buffer:

```
buffer = incoming_delta_secs + transit_slack_secs
```

`incoming_delta_secs` comes from the route announcement, else a
per-network fallback (fedimint/cashu/lightning 30 s, arkade 60 s,
liquid 300 s, rootstock 600 s). `transit_slack_secs` absorbs in-flight
latency and clock skew.

`compute_hop_expiries(now, buffers)` walks the buffers from downstream
toward the sender, so:

- hop `i`'s incoming deadline = `now + buffer[i..end].sum`
- hop `i`'s outgoing expiry  = `now + buffer[i+1..end].sum`

The first hop's incoming deadline is the most generous; the last
router's outgoing expiry is only the payee leg's buffer.

**What could go wrong**

- **Deadline too tight** → a router rejects the PREPARE (see step 4).
  The payer aborts and retries on a different route.
- **Clock skew between payer and a hop** → mitigated by
  `transit_slack_secs`, not eliminated.

---

## 3. Payer: PREPARE every hop (concurrent)

The payer sends `HopPrepare` to every hop in parallel and joins all
replies.

**Decisions**

- PREPAREs run concurrently because each hop's reply (its
  `claim_pubkey`) is not needed until DISPATCH, and DISPATCH is strictly
  after every PREPARE.
- The payer scans *all* replies even after a failure, so late-accepting
  hops are still known when it is time to DISCARD.
- Any rejection or transport failure → DISCARD the accepted subset and
  abort.

**What could go wrong**

- **A hop rejects** → recorded as `HopRejected`; the payer discards the
  reservations that succeeded and returns the error. No funds moved.
- **A reply is lost in transport** → the hop may have reserved but is
  now unreachable. Its reservation ages out on its own (600 s). The
  payer DISCARDs what it can and aborts.
- **A hop reports no claim identity** → hard error.

---

## 4. Router: handle PREPARE

`handle_prepare` is the router's first decision point.

**Decisions, in order**

1. Canonicalize network ids (normalize, warn on mismatch).
2. `validate_prepare`: non-zero hash, positive amount, incoming and
   outgoing networks supported, `incoming_deadline >= now + incoming_delta_secs`.
3. Optional operator veto hook (test/policy) — after validation.
4. `can_route(amount)` on the **outgoing** adapter: can this hop afford
   to fund the downstream HTLC right now? (cashu sums local balance;
   default accepts.)
5. `can_claim(amount)` on the **incoming** adapter: can this hop afford
   to *claim* what it is owed later? (rootstock needs gas; cashu needs
   nothing.)
6. `register_incoming_htlc(hash, amount, deadline)` on the incoming
   adapter — parks per-payment state and, for LND, creates the hold
   invoice the upstream party must pay.
7. Capacity check: at most 100 outstanding PREPAREs; reservations expire
   after 600 s and are bound to the requesting peer.

On success the reply carries `claim_pubkey` — the identity the upstream
party must lock our incoming HTLC to, self-reported so lock and claim
agree by construction — and `incoming_descriptor` (the funding handle,
LND hold invoice / fedimint claim key).

**What could go wrong**

- **Unsupported network** → reject with a clear reason.
- **`can_route` fails** (insufficient outgoing balance) → reject.
- **`can_claim` fails** (cannot afford the incoming claim later) → reject
  *before* anything is locked; otherwise the hop would commit downstream
  and only then discover it cannot claim upstream.
- **`register_incoming_htlc` fails** (e.g. LND refuses the hold invoice)
  → reject.
- **Capacity exhausted** → reject and cancel the registration that was
  just created.

Rejections here are all pre-funding; no money is at risk.

---

## 5. Payer: fund the first HTLC

After every PREPARE accepted, the payer creates the first outgoing HTLC
on its own sending network, locked to hop 0's `claim_pubkey`.

**Decisions**

- Use `pay_invoice_with_descriptor` so an LND hold-invoice target is
  paid exactly rather than a raw hash-only send.
- Immediately spawn a payment guard (see step 9) and persist a pending
  outgoing-payment row.

**What could go wrong**

- **Fund fails** → discard all reservations; nothing was funded anywhere.
- **`outgoing_htlc_descriptor` fails** → the HTLC exists but its wire
  handle is missing; the payer discards reservations, but the funded
  HTLC is still monitored/refunded by the guard.

---

## 6. Payer: walk the route (DISPATCH)

For each hop in order, the payer sends `HopDispatch` carrying the
previous hop's outgoing descriptor as the incoming descriptor, plus the
downstream hop's `claim_pubkey` as `recipient` (the payee's for the last
hop).

**What could go wrong**

- **DISPATCH fails at hop `i`** → hops `0..i` are already funded (DISCARD
  is a no-op there); hops `i..` may still hold unused reservations. The
  payer DISCARDs `i..` and aborts. Funded upstream hops resolve via their
  own watch/refund paths.

---

## 7. Router: handle DISPATCH

The hop's second decision point.

**Decisions, in order**

1. Look up the matching PREPARE (remove it — a reservation is consumed
   by its DISPATCH, and a later DISCARD becomes a no-op).
2. `verify_incoming_htlc(descriptor, hash)` on the incoming adapter: is
   the deployed incoming HTLC really claimable for this hash (right
   identity, right script/contract)?
3. `accept_incoming_htlc` — stash the incoming descriptor so the later
   `claim_incoming` can find it.
4. `create_outgoing_htlc_with_descriptor(hash, amount, outgoing_expiry,
   recipient, outgoing_target)` — fund the downstream HTLC.
5. `outgoing_htlc_descriptor(hash)` — fetch the wire handle to return.
6. Record a `DispatchedHop` (prepare + `outgoing_deadline = outgoing_expiry`)
   for the poll loop.

**What could go wrong**

- **Incoming HTLC not claimable** (wrong hash/identity/amount) → reject;
  the upstream party is responsible for the failed deployment.
- **`accept_incoming_htlc` fails** → reject.
- **`create_outgoing_htlc` fails** → `cancel_incoming_htlc` (unwind the
  PREPARE-time registration, e.g. cancel the LND hold invoice) and reject.
- **`outgoing_htlc_descriptor` fails after the outgoing HTLC was funded**
  → the hop returns an error but the funded outgoing HTLC is *not* in
  the dispatched table, so the poll loop will neither watch nor refund
  it. This is a known gap: the funds sit until network expiry.

---

## 8. Payee: COMMIT

The payer sends `HopCommit` directly to the payee (routers are skipped)
with the final descriptor. The payee matches the hash to its stored
preimage, claims the incoming HTLC, and returns the preimage.

**Decisions**

- The payee originates the preimage; claiming publishes it, which is what
  lets every upstream hop claim in turn.
- The payer verifies `SHA256(preimage) == payment_hash` before declaring
  success.

**What could go wrong**

- **Payee returns a zero preimage** (misroute / no commit handler) →
  payer errors.
- **Preimage does not hash to the payment hash** → payer errors.
- **Claim fails on the payee side** → the payee reports the error; the
  payer's guard still monitors its own outgoing HTLC.

## 8b. Payer: fan the preimage out to every hop

Once the payer holds the verified preimage, it pushes a `Committed`
message (payment hash + preimage) to every router hop in the route, so
each hop can claim its incoming HTLC immediately instead of waiting for
the poll loop to observe the preimage revealed on the downstream
network.

**Decisions**

- Concurrent and best-effort: a hop that misses the fanout still settles
  via its own watch/refund loop, so failures only log.
- Each hop validates `SHA256(preimage) == payment_hash` before burning a
  claim, so a bogus fanout cannot drop the hop's dispatch state.

**What could go wrong**

- **Hop unreachable at fanout time** → logged; the hop settles later via
  the poll loop when the downstream claim reveals the preimage.

---

## 9. Monitor: preimage watch vs refund

Both the router's poll loop and the payer's payment guard run the same
two-phase lifecycle on their outgoing HTLC:

```
watch_preimage until outgoing_expiry
    ├─ preimage arrives ──→ claim_incoming (router) / persist proof (payer)
    └─ expiry passes ─────→ refund_outgoing
```

The fanout from step 8b is the fast path that delivers the preimage to a
hop; the poll loop below is the fallback when the fanout is delayed or
lost.

**Router poll loop** (`run_poll_loop` / `poll_once`), every 30 s:

- `now >= outgoing_deadline` → refund the outgoing side; on a transient
  (`Network`) error keep the dispatch row for the next tick, else drop it.
- Else poll `watch_preimage` with the deadline capped at
  `outgoing_deadline`, so an adapter watch cannot keep the loop past the
  point where refund focus must begin.
  - `Ok(preimage)` → `claim_incoming(hash, preimage)`; drop the row
    (success or not).
  - `DeadlineExceeded` → keep polling.
  - `Network` / `Unimplemented` → log and keep polling.

**Payer payment guard**: same shape, plus it persists the preimage as
proof on arrival and retries `refund_payment` on transient errors.

**What could go wrong**

- **Preimage never arrives** → refund at expiry. Refund itself may fail
  transiently (e.g. the on-chain CLTV/locktime has not yet opened); the
  guard/loop retries until it succeeds or the row is dropped.
- **Preimage arrives after expiry** → the HTLC may already be refundable;
  the router is racing refund against claim. The incoming-side claim is
  what protects the hop; on networks where a claim still costs something
  this is the residual risk the `can_claim` check was meant to bound.
- **Refund on an already-claimed HTLC** → adapters surface
  "contract gone / nothing to refund" as a terminal case and drop the row.

---

## 10. Teardown and recovery

- **DISCARD** frees a PREPARE reservation before any HTLC exists. Only
  the peer that created it may release it; once DISPATCH consumed the
  reservation, DISCARD is a no-op.
- **Incoming side left to expire** — after a refund of the outgoing side,
  the incoming HTLC is left to expire on its own; the router never claims
  without a preimage.
- **Restart recovery** (`cassis-cli watch`) — pending outgoing HTLCs are
  persisted (invoice, hash, sender network, amount, expiry, descriptor);
  `restore_outgoing_htlc` rebuilds adapter state from the descriptor and
  resumes the same watch/refund guard. Adapters that keep watcher state
  only in memory must implement this or the payment is unmonitored after
  a restart.
