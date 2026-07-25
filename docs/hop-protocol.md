# Cassis hop protocol

Wire-level reference for the messages cassis nodes exchange while
routing a payment, plus an investigation of the serialization format.

Two channels carry everything:

| Channel                                                       | Format                   | Carries                                                    |
| ---                                                           | ---                      | ---                                                        |
| iroh QUIC, one bidirectional stream per request/response pair | postcard-encoded `Frame` | hop protocol (this doc)                                    |
| Nostr (kind 35515 events, signed)                             | JSON                     | route announcements (`RouteAnnouncement`), not per-payment |

Envelope: the requester postcard-encodes a `Frame`, writes it as a
single QUIC stream message, and reads one `Frame` back. There is no
framing header, no version field, no length prefix — the QUIC stream
delimits the message and the request type is implied by which method
sent it. 1 MiB read cap per response.

## Field classification

Throughout this doc:

- **static** — same value/meaning for the life of the protocol
  (message shape, invariants); not expected to vary per message.
- **payment** — dynamic per payment: derived from the route's
  preimage, amounts, or wall-clock.
- **hop** — fixed per (node, network) pair for the duration of a
  route; self-reported once per PREPARE and echoed back by the payer.
- **network** — payload whose exact shape depends on which network
  the hop leg runs on (`HtlcDescriptor` variants).

`payment_hash` is the constant thread across every frame of one
payment: every hop — incoming and outgoing leg alike — uses the same
hash, which is what makes the cross-network swap atomic. Amounts
shrink hop by hop (fees); deadlines shrink hop by hop (each hop
consumes its own budget from the deadline it is given).

## Messages

### `Prepare` — payer → router

Ask a hop to reserve capacity, before any HTLC exists.

| Field               | Type   | Class   | Notes                                                       |
| ---                 | ---    | ---     | ---                                                         |
| `payment_hash`      | 32 B   | payment | SHA-256 of the route preimage                               |
| `amount_msat`       | u64    | payment | outgoing amount (already minus upstream fees)               |
| `incoming_network`  | string | hop     | which of the hop's adapters will be claimed                 |
| `outgoing_network`  | string | hop     | which adapter will fund downstream                          |
| `incoming_deadline` | u64    | payment | unix secs; payer's now + hop budget + transit slack         |
| `outgoing_expiry`   | u64    | payment | unix secs; how long the downstream HTLC must stay claimable |

### `Prepared` — router → payer

| Field                 | Type         | Class   | Notes                                                                                                                         |
| ---                   | ---          | ---     | ---                                                                                                                           |
| `payment_hash`        | 32 B         | payment | echo                                                                                                                          |
| `accepted`            | bool         | payment | reservation result                                                                                                            |
| `reason`              | string?      | payment | only on rejection; **always serialized** (postcard is positional)                                                             |
| `incoming_descriptor` | descriptor?  | network | handle the payer/upstream must fund this hop's incoming side (LND hold invoice, fedimint claim key). `None` for most networks |
| `claim_pubkey`        | 32 B x-only? | hop     | identity the upstream must lock this hop's incoming HTLC to; self-reported so lock and claim agree. `None` on rejection       |

### `Dispatch` — payer → router

Tells the hop a real incoming HTLC matching its PREPARE is deployed.

| Field                 | Type        | Class   | Notes                                                                                                                                          |
| ---                   | ---         | ---     | ---                                                                                                                                            |
| `payment_hash`        | 32 B        | payment | matches the PREPARE                                                                                                                            |
| `incoming_descriptor` | descriptor  | network | payload of the deployed incoming HTLC (previous hop's `Dispatched.outgoing_descriptor`, or the payer's for hop 0)                              |
| `outgoing_target`     | descriptor? | network | downstream hop's PREPARE descriptor (LND hold invoice); consumed by the outgoing adapter                                                       |
| `recipient`           | 32 B x-only | hop     | downstream party's `claim_pubkey` — learned from downstream PREPARE replies, hence carried here and not in PREPARE (PREPAREs run concurrently) |

### `Dispatched` — router → payer

| Field                 | Type       | Class   | Notes                                                                                          |
| ---                   | ---        | ---     | ---                                                                                            |
| `payment_hash`        | 32 B       | payment | echo                                                                                           |
| `outgoing_descriptor` | descriptor | network | handle to the just-funded outgoing HTLC; becomes the next hop's `Dispatch.incoming_descriptor` |

### `Commit` — payer → payee (direct, not via routers)

| Field                 | Type       | Class   | Notes                            |
| ---                   | ---        | ---     | ---                              |
| `payment_hash`        | 32 B       | payment | matches the invoice              |
| `amount_msat`         | u64        | payment | sanity check against the invoice |
| `network`             | string     | hop     | payee's receiving network        |
| `incoming_deadline`   | u64        | payment | claim window                     |
| `incoming_descriptor` | descriptor | network | handle to the funded final HTLC  |

### `Committed` — payee → payer

| Field          | Type | Class   | Notes                                                                                      |
| ---            | ---  | ---     | ---                                                                                        |
| `payment_hash` | 32 B | payment | echo                                                                                       |
| `preimage`     | 32 B | payment | the route preimage; payee originates it, every upstream hop learns it from its own network |

### `Discard` — payer → router

| Field          | Type | Class   | Notes                  |
| ---            | ---  | ---     | ---                    |
| `payment_hash` | 32 B | payment | reservation to release |

### `Discarded` — router → payer

                 | Field      | Type    | Class   | Notes                                                        |
                 | ---        | ---     | ---     | ---                                                          |
) `payment_hash` | 32 B       | payment | echo    |
                 | `released` | bool    | payment | `false` is normal (already dispatched / aged out / rejected) |

### `Error` — any → requester

| Field          | Type   | Class   | Notes                 |
| ---            | ---    | ---     | ---                   |
| `payment_hash` | 32 B   | payment | which payment failed  |
| `message`      | string | payment | human-readable reason |

### `HtlcDescriptor` variants (the **network** payload)

Externally tagged; the tag is a 1-byte variant index under postcard.

| Variant     | Fields                                                                                        | Class   | Notes                                                                                                                   |
| ---         | ---                                                                                           | ---     | ---                                                                                                                     |
| `Cashu`     | `proofs_b64: [string]`                                                                        | network | NUT-14 HTLC-locked proofs; recipient swaps with preimage witness                                                        |
| `Fedimint`  | `claim_pubkey: string`, `funding_txid: string?`, `funding_out_idx: u64?`, `contract: string?` | network | registration descriptor = claim key only; funding descriptor = claim key + outpoint + consensus-JSON `OutgoingContract` |
| `Liquid`    | `lockup_txid`, `lockup_vout`, `refund_pubkey`, `refund_locktime`                              | network | unblinded P2WSH lockup; claim path + CLTV refund path                                                                   |
| `Arkade`    | `sender`, `receiver`, `server`, `payment_hash160`, `refund_locktime`, 3 CSV delays            | network | VHTLC taproot script inputs; all hex strings / u32s                                                                     |
| `Rootstock` | `contract`, `amount_wei: u128`, `claim_address`, `refund_address`, `timelock`                 | network | EtherSwap on RSK                                                                                                        |
| `Lightning` | `payment_request`                                                                             | network | BOLT11 hold invoice; the sender must pay this exact request                                                             |

### Not on the hop wire but adjacent

- `Invoice` (payee → payer, out of band): `payment_hash`, `amount_msat`,
  `payee` (invoice key), `expires_at`, `claim_pubkeys` (per-network
  identity the final HTLC must be locked to), `networks`, `description`,
  `iroh_peer_id`/`iroh_relay` (how to reach the payee for COMMIT),
  `payment_request`. JSON in current UIs, but postcard-clean structs.
- `RouteAnnouncement` (Nostr kind 35515, signed JSON): `node_pubkey`,
  `iroh_peer_id`, `iroh_relay`, `from`/`to` networks, fee schedule
  (`fee_base_msat`, `fee_ppm`), `incoming_delta_secs`,
  `transit_slack_secs`, `relays`.

## Format investigation

Current: **postcard**. serde-derive both sides; ~1-byte enum tags,
varint ints, no in-band type info. Properties that matter:

1. **Self-description** — can a decoder that has never seen the
   message type parse it? postcard: no (positional, tag-only).
2. **Schema evolution** — add a field without breaking peers?
3. **Canonical form** — byte-stable for a given value (signing,
   dedup, caching)?
4. **Precision** — u64/u128 money amounts survive?
5. **Ecosystem / tooling** — debuggability, non-Rust clients, wasm.

### postcard (status quo)

- (1) fails: unknown variant or reordered fields = silent desync, the
  exact hazard flagged in review. (2) append-only only: new `Option` /
  new trailing fields OK, everything else breaks. (3) yes, canonical.
  (4) yes. (5) Rust-only tooling, no human reading.
- Verdict: fine for a closed, same-version Rust fleet. Wrong shape the
  moment heterogeneous peers exist.

### JSON (`serde_json`)

- Self-describing; serde's derive mostly just swaps the serializer.
  Unknown fields ignored by default → additive evolution works, new
  enum variants fail loud (`unknown variant`) instead of desyncing.
  Human-debuggable, universal tooling.
- Costs: ~2–5× size (irrelevant at these message sizes), **u64 above
  2^53 and u128 (Rootstock wei!) need string wrapping**, no canonical
  form unless RFC 8785 (JCS) is enforced, `Option`/tag verbosity.
- Verdict: best debugging/interop story, worst type fidelity for
  money. Needs careful amount encoding.

### CBOR (`ciborium`)

- Self-describing binary data model; serde-compatible via ciborium,
  so it is nearly a drop-in like JSON. Deterministic canonical
  profiles exist (RFC 8949 canonical CBOR, dCBOR). Native 64-bit
  (and arbitrary-precision) integers — no 2^53 trap. Compact (byte
  tags + varint-style lengths), ~1.2–2× postcard. Unknown map keys
  skippable, enum tags are explicit → clean evolution and loud
  failure.
- Costs: fewer eyes than JSON, canonical profile needs to be pinned
  and enforced, serde `deserialize_any` required for tagged enums
  (ciborium supports it).
- Verdict: **best replacement candidate** — keeps serde derive, fixes
  the silent-desync class, canonical, money-safe.

### bincode

Same non-self-describing class as postcard (no `deserialize_any`,
positional), fixed-size ints (bigger), no canonical profile in
bincode 1. Strictly worse than postcard for this use. Not a candidate.

### borsh

Deterministic by spec, schema'd, NEAR-proven. Non-self-describing
(same evolution hazard as postcard, though the spec is frozen and
well-tooled). Rust-first ecosystem. A reasonable "keep binary, get a
frozen spec" move, but does not fix (1).

### protobuf

Schema-first; excellent evolution (unknown fields preserved, field
numbers stable); canonicalization not guaranteed without a canonical
profile; adds `.proto` codegen and a build step; u64 fine, u128 needs
custom mapping. The right answer if cross-language SDKs (Go/TS
wallets) become a goal; heavy for 9 messages between Rust nodes.

### FlatBuffers / Cap'n Proto

Zero-copy, random access, schema-first. Massive machinery for
sub-kilobyte request/response pairs. Not a candidate.

### MessagePack

Binary JSON; self-describing; serde via `rmp-serde` supports tagged
enums. No standard canonical profile; u64 handled as native ints.
Dominated by CBOR for this use.

### Summary

|                | self-desc. | evolution   | canonical    | money-safe    | cost            |
| ---            | ---        | ---         | ---          | ---           | ---             |
| postcard (now) | ✗          | append-only | ✓            | ✓             | tiny            |
| JSON           | ✓          | ✓ (loud)    | JCS only     | ✗ >2^53, u128 | trivial swap    |
| **CBOR**       | ✓          | ✓ (loud)    | ✓ (RFC 8949) | ✓             | serde-only swap |
| bincode        | ✗          | ✗           | ✗            | ✓             | —               |
| borsh          | ✗          | frozen spec | ✓            | ✓             | small           |
| protobuf       | ~          | ✓✓          | ~            | u128 mapping  | codegen         |
| msgpack        | ✓          | ✓           | ✗            | ✓             | small           |

### Recommendation

Short term, stay on postcard and treat the wire as
whole-fleet-atomic: any descriptor or frame change ships to every
node at once (the current model). The `Error` frame should stay
last-variant so future additions remain diagnosable.

If/when peers of different versions (or non-Rust clients) must
interoperate, move the `Frame` transport to **CBOR via ciborium**:
same serde derives, explicit tags fail loud instead of desyncing,
canonical profile available for any future signing/dedup need, no
amount-precision traps. Add a `serde_json` debug codec behind a
feature flag for tooling in the same change. Keep the descriptor
*contents* (the network payloads) as-is — they already encode the
per-network variance; only the envelope format changes.
