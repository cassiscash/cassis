# Cassis protocol specification

Status: draft. Sections marked TODO are not specified yet; until they
are, the code in `cassis-core` is the reference.

## 1. Parties and keys

- **Payer**: pays an invoice.
- **Router**: forwards a payment from one network to another, taking
  an incoming HTLC and funding an outgoing one.
- **Payee**: receives the payment.
- **Gateway**: optional; is paid in the payee's place and pays the
  payee with an HTLC on a network the payee named, so the payee can be
  offline.
- **Preimage server**: optional; chooses payment hashes for an offline
  payee, keeps their preimages and releases each one to the gateway
  only once the gateway has locked an HTLC to the payee.

Every party is identified by its iroh endpoint key, an Ed25519 public
key (32 bytes). All Cassis signatures are Ed25519 signatures (64 bytes)
by these keys.

## 2. Transport

Peers talk over iroh with the ALPN `cassis-hop/8`. Each request is one
JSON message on its own stream, answered by exactly one response.

A payment over a route of `n` routers runs:

1. **PREPARE** every router concurrently. Each checks the terms and its
   liquidity, and answers with the target its incoming HTLC must be
   locked to. The payee (or its gateway) is told of the HTLC it will be
   committed and may refuse.
2. The payer funds the first HTLC, then **EXECUTE**s the routers in
   order: each verifies its incoming HTLC, funds its outgoing one and
   returns that HTLC's descriptor.
3. **COMMIT** to the payee with the last descriptor: the payee verifies
   and claims its HTLC and returns the preimage.
4. **SETTLE** fans the preimage out to the routers.

**DISCARD** releases the PREPARE reservations of an aborted attempt.
EXECUTE and COMMIT may answer *pending* while their incoming HTLC
becomes final; the payer repeats the same request until it gets the
outcome.

TODO: the exact JSON shape of each request and response.

## 3. Signatures

### 3.1 Canonical encoding

A signature never covers JSON or any other serialization of a message.
It covers a sequence of bytes built field by field, in the order this
section lists, with these rules:

| Notation  | Encoding                                                        |
|-----------|-----------------------------------------------------------------|
| `u8`      | 1 byte                                                          |
| `u64`     | 8 bytes, big-endian                                             |
| `bytes32` | 32 raw bytes (hashes, ids, nonces)                              |
| `key`     | 32 raw bytes: an Ed25519 public key                             |
| `sig`     | 64 raw bytes: an Ed25519 signature                              |
| `bytes`   | 4-byte big-endian length, then the bytes                        |
| `str`     | as `bytes`, over the string's UTF-8                             |
| `count`   | 4-byte big-endian number of items, then each item               |
| `option T`| `0x00` if absent; `0x01` then `T` if present                    |
| `target`  | what an HTLC locks to; see below                                |

`target` is a tag byte followed by its value:

| Tag    | Value                                                  | Networks                         |
|--------|--------------------------------------------------------|----------------------------------|
| `0x00` | 32 bytes: x-only secp256k1 key                         | Cashu, Fedimint, Arkade, Bitcoin |
| `0x01` | 33 bytes: compressed secp256k1 key                     | Liquid, Rootstock                |
| `0x02` | `str`: a BOLT11 hold invoice                           | Lightning                        |

Every message starts with its **domain**, written as a `str`. The
domain names the statement and its version, so a signature over one
kind of statement can never be read as a signature over another.

Times are unix seconds. Amounts are millisatoshis.

### 3.2 What is signed

| Statement            | Signed by        | Domain                             |
|----------------------|------------------|------------------------------------|
| Receive authorization| payee            | `cassis/receive-authorization/v2`  |
| Preimage issuance    | preimage server  | `cassis/preimage-issuance/v2`      |
| Invoice (gateway)    | gateway          | `cassis/invoice/gateway/v3`        |
| Invoice (payee)      | payee            | `cassis/invoice/payee/v3`          |
| Gateway metadata     | gateway          | `cassis/gateway-metadata/v2`       |

Route announcements are Nostr events and are signed as NIP-01 says;
they are not covered here.

### 3.3 Receive authorization

The payee lets a gateway and a preimage server act for it, within
limits.

```
str     "cassis/receive-authorization/v2"
u8      kind: 0x00 single, 0x01 standing
key     payee
key     gateway
key     preimage server
option  str      preimage server relay
option  str      description
u64     valid from
u64     valid until
u64     min amount msat
u64     max amount msat
u64     min final timeout secs
count   destinations, each:
  str     network id
  target  claim key
```

A *single* authorization covers one invoice the payee builds and signs
itself; a *standing* one lets the gateway issue invoices alone.

The authorization's **id** is the SHA-256 of these bytes. Other
statements refer to the authorization by its id.

A verifier rejects an authorization whose payee, gateway and preimage
server are not three distinct keys, whose `valid from` is not before
`valid until`, whose min amount is zero or above its max, whose min
final timeout is zero, or which names no destination.

### 3.4 Preimage issuance

The preimage server vouches that it issued a payment hash under an
authorization.

```
str     "cassis/preimage-issuance/v2"
key     preimage server
bytes32 authorization id
bytes32 payment hash
u64     amount msat
option  bytes32  SHA-256 of the invoice metadata
```

The issuance also carries a `nonce` the server derives the preimage
from. The issuance signature does not cover it (a wrong nonce only
fails to produce the hash), but invoice signatures do.

### 3.5 Invoice

An invoice has one of three receivers:

- **direct**: issued and signed by the payee, which is paid at its own
  endpoint;
- **gateway**: issued by a gateway for a payee that is online when the
  invoice is made; signed by the gateway, then by the payee;
- **delegated**: issued and signed by the gateway alone, under the
  payee's standing authorization and with the preimage server's
  issuance of its hash.

Both invoice signatures cover the same **terms**:

```
bytes32 payment hash
u64     amount msat
u64     expires at
count   networks, each:
  str     network id
  target  what the payer locks to on that network
  option  u64  incoming delta secs
option  str    description
option  bytes  metadata
option  str    iroh relay
u8      receiver: 0x00 direct, 0x01 gateway, 0x02 delegated
key     payee
-- gateway and delegated receivers only:
key     gateway
-- delegated receiver only:
key     preimage server
bytes32 payee authorization id
sig     payee authorization signature
bytes32 issuance payment hash
u64     issuance amount msat
option  bytes32  issuance metadata hash
bytes32 issuance authorization id
bytes32 issuance nonce
sig     issuance signature
```

The **gateway** signs (gateway and delegated receivers):

```
str     "cassis/invoice/gateway/v3"
<terms>
```

The **payee** signs (direct and gateway receivers):

```
str     "cassis/invoice/payee/v3"
<terms>
-- gateway receiver only:
option  sig    gateway signature
```

So on a gateway invoice the payee's signature wraps the gateway's. A
delegated invoice carries no payee signature: the payee's standing
authorization stands in for it.

A verifier of a delegated invoice also checks that the authorization is
valid and standing, names the invoice's payee, gateway and preimage
server, allows its amount and description, and contains its expiry;
and that the issuance is the preimage server's, under that
authorization, for the invoice's payment hash and amount.

### 3.6 Gateway metadata

The metadata of every invoice a gateway issues carries the preimage
server's opaque metadata and the gateway's own terms, sealed with a key
only the gateway holds. Payers hand it back with PREPARE and COMMIT,
and the gateway checks its signature before opening it.

```
str     "cassis/gateway-metadata/v2"
bytes   preimage metadata
bytes   sealed terms
```

The sealed terms are opaque to everyone but the gateway and need no
canonical form.

## 4. HTLCs

TODO: for each network, the exact HTLC the payer, routers and gateway
create: script or contract, how the payment hash, claim key, refund key
and expiry appear in it, and what a descriptor carries to find and
verify it.

- Bitcoin
- Liquid
- Rootstock
- Arkade
- Cashu
- Fedimint
- Lightning (hold invoices)
