# Staking Transparency Log — Portable Specification

This document is the from-scratch specification of every canonicalization, hashing, signing, and
Merkle-tree rule the player-staking transparency log (STAKING-P2 through P5) uses. It is written so
that a compatible verifier — or a compatible reimplementation of the producer — can be built in
Python, Rust, JavaScript, or any other language **without reading this repository's Go source**.
Every formula below is transcribed exactly from `pkg/translog/*.go` (this repository) and cross-checked
against that package's test suite; nothing here is approximated or inferred. Where the source code
itself flags an ambiguity or an intentionally-undocumented behavior, this document says so rather
than guessing.

The reference (and, today, only) implementation lives in `pkg/translog/` and is consumed by the
standalone `cmd/staking-verify` CLI — see this repository's top-level `README.md` for how to run
that tool against a live operator. This document specifies the *rules*; that README specifies
*usage*.

**Schema version:** this system has produced two versions. **Schema Version 1** (`schema_version: 1`)
is the original canonicalization — everything in §1-§8 below applies to it unchanged. **Schema
Version 2** (`schema_version: 2`) is a **field-set-compatible bump**: the canonical `Entry` wire
shape (§1) is byte-identical between the two versions — the same fixed field set, the same encoding
rules, the same hash and signature construction. The only difference is in what the PRODUCER now
writes into an `EPOCH` event's `payload`: from `schema_version: 2` onward, every `EPOCH` event
additionally carries a `cap_net` key (§8.1), which unlocks four additional economic replay checks
(§9.4) that a `schema_version: 1` `EPOCH` event is not held to, because it was never signed under a
promise to carry that field. **A `schema_version: 1` receipt stays verifiable under exactly the
rules it always has, forever** — the version bump strengthens what NEW exports prove; it never
retroactively changes what an already-issued receipt proves. A canonicalizer/verifier must accept
both `1` and `2` and refuse anything else rather than guessing how to encode or replay it.

**Hash function throughout:** SHA-256. **Signature scheme throughout:** Ed25519. All hashes and
signatures are hex-encoded (lowercase) on every public wire format below.

---

## 1. Canonical JSON encoding (the "Entry")

One transparency-log event is called an **Entry**. Its canonical JSON form is the exact byte
sequence that gets hash-chained and signed — nothing outside these bytes is ever part of a
signature.

### 1.1 Fixed field set and order

An Entry canonicalizes to a JSON object containing **exactly** these fields, in this order, and no
others:

```
account            (optional, omitted if empty)
amount             (optional, omitted if not present)
idempotency_key     (required)
operator_id         (required)
payload            (required — {} if empty)
pool_id            (required)
schema_version      (required, integer)
shares             (optional, omitted if not present)
ts                 (required)
type               (required)
```

This order is not arbitrary key-insertion order — it is the sort order RFC 8785 (JSON
Canonicalization Scheme, "JCS") §3.2.3 mandates: object members sorted by their key's UTF-16 code
unit sequence. For this fixed, all-ASCII field-name set, UTF-16 code-unit order is identical to
plain byte order, so implementers who only ever canonicalize *this* fixed field set can use plain
string sort — but see §1.5 below, because the `payload` map's *keys* are not guaranteed ASCII and
need the real UTF-16 rule.

### 1.2 Field encodings

| Field | Type | Encoding |
|---|---|---|
| `account` | string | Verbatim string, JSON-escaped per §1.5. The **public** account id (never an internal id, never a user id). Omitted (key absent) when there is no account for this event (e.g. `EPOCH`) — never emitted as `null`. |
| `amount` | string | A money amount, encoded per §1.3. Omitted when not present for this event type — never `null`. |
| `idempotency_key` | string | Verbatim string, JSON-escaped per §1.5. Always present. |
| `operator_id` | string | The owning tenant's UUID, as a string. Always present. |
| `payload` | object | A flat `string -> string` map, encoded per §1.4. Always present; `{}` when empty. |
| `pool_id` | string | The pool's UUID, as a string. Always present. |
| `schema_version` | integer | Plain decimal digits, no quotes (e.g. `1` or `2`). Always present; `1` and `2` are the only values this system has ever produced (see the schema-version note above) — a canonicalizer that receives any other value MUST refuse rather than guess how to encode it. |
| `shares` | string | A money amount, encoded per §1.3. Omitted when not present for this event type — never `null`. |
| `ts` | string | The event timestamp, encoded per §1.6. Always present. |
| `type` | string | The event-type name (§8), verbatim, JSON-escaped per §1.5. Always present. |

### 1.3 Amount encoding — the `AmountScale` rule

**Constant: `AmountScale = 18`.** Every money value (`amount`, `shares`, and every sum inside the
proof-of-liabilities tree, §6) is rendered as a **plain fixed-point decimal string with exactly 18
fractional digits — never scientific notation, never a trailing/leading-digit-count that varies.**

```
CanonicalAmount(x) = plain_decimal_string(x, scale=18)
```

Examples (from the test suite, `TestCanonicalAmount_FixedEighteenPlaces`):

| Input | Canonical output |
|---|---|
| `60` | `"60.000000000000000000"` |
| `0.1` | `"0.100000000000000000"` |
| `0.000000000000000001` | `"0.000000000000000001"` |
| `1234567890.5` | `"1234567890.500000000000000000"` |
| `1e2` | `"100.000000000000000000"` (exponent notation on the input side normalizes away) |
| `-3.25` | `"-3.250000000000000000"` |
| `0` | `"0.000000000000000000"` |

18 is not an arbitrary choice — it is chosen to match the fractional scale of the
`numeric(36,18)`/`numeric(48,18)` PostgreSQL columns these values are persisted in, specifically so
that "the value stored in the database" and "the value that was signed" render to byte-identical
text with no rounding or padding ambiguity at either end.

Amounts and shares are never negative in a valid Entry (§8 covers what "valid" means per event
type); a canonicalizer need not itself reject negative values (the source does not, at this layer —
validation of sign happens at the replay layer, §9), but every legitimate value produced by this
system is non-negative.

### 1.4 The `payload` map

`payload` is a flat map of `string -> string` — values are always strings, never numbers, booleans,
nested objects, or arrays. This is deliberate: a value type that only round-trips one way through a
database JSONB column (a plain string) cannot be silently re-encoded differently between the write
path and an export.

Encoding: a JSON object whose members are the map's `(key, value)` pairs, **sorted by key using the
UTF-16 code-unit comparison from RFC 8785 §3.2.3** (not naive byte order for non-ASCII keys — see
§1.5). `nil` (absent) and `{}` (present but empty) canonicalize to the **identical** bytes: `{}`.
There is exactly one canonical representation of "no payload."

```
appendCanonicalStringMap(m):
    if len(m) == 0: return "{}"
    keys = sort(m.keys(), by=utf16_code_unit_order)
    return "{" + join(",", [ jsonString(k) + ":" + jsonString(m[k]) for k in keys ]) + "}"
```

### 1.5 String escaping (RFC 8785 §3.2.2.2, minimal escaping)

Every JSON string in the canonical form — field values, payload keys, payload values — uses this
exact escaping rule, applied rune-by-rune (Unicode code point, not byte):

| Character | Encoding |
|---|---|
| `"` (U+0022) | `\"` |
| `\` (U+005C) | `\\` |
| backspace (U+0008) | `\b` |
| tab (U+0009) | `\t` |
| newline (U+000A) | `\n` |
| form feed (U+000C) | `\f` |
| carriage return (U+000D) | `\r` |
| any other control char < U+0020 | `\u00XX` (lowercase hex, 4 digits) |
| everything else, **including non-ASCII** | emitted as **literal UTF-8** — never `\uXXXX`-escaped |

This means a payload value containing `café` or `é` appears as literal UTF-8 bytes in the canonical
form, not as an escape sequence. Confirmed by test (`TestCanonicalJSON_EscapingAndUnicodeKeys`):
a payload `{"quote\"key": "back\\slash", "ctrl": "line\nbreak\ttab", "é": "café"}` canonicalizes its
payload value to exactly:

```
{"ctrl":"line\nbreak\ttab","quote\"key":"back\\slash","é":"café"}
```

Object-member sort order for arbitrary (non-ASCII) keys is **RFC 8785 §3.2.3's UTF-16 code-unit
order**: encode each key as UTF-16 code units (surrogate pairs for astral characters), compare
lexicographically over that sequence, shorter-is-less on a common prefix.

### 1.6 Timestamp encoding — the `TSFormat` rule

**Constant: `TSFormat = "2006-01-02T15:04:05.000000Z"`** (Go reference-time layout). In
language-agnostic terms: RFC 3339, timestamp normalized to **UTC**, with **exactly six fractional
digits** (microsecond precision, zero-padded), and the UTC designator is always the literal `Z` —
never a `+00:00` offset form.

```
ts_canonical = strftime(ts.to_utc(), "%Y-%m-%dT%H:%M:%S") + "." + microseconds_zero_padded_to_6 + "Z"
```

Example: `2026-08-11T12:34:56.789012Z`.

Producers are required to **truncate to microsecond precision before storing or canonicalizing** —
this is what makes a value round-tripped through PostgreSQL's `timestamptz` (native microsecond
precision) re-render to byte-identical text every time; a canonicalizer fed a timestamp with
nanosecond precision that has not been truncated first will not match a value the producer actually
signed.

This exact format is used for `Entry.ts` (§1) and `STH.ts` (§5), and nowhere else.

### 1.7 Full worked golden vector

From `pkg/translog/canonical_test.go`'s `goldenCanonical` constant — the canonical form of a
fully-populated Entry (values chosen to exercise every field, including a multi-key payload map
inserted in non-sorted order to prove the output does not depend on construction order):

**Input** (informal):
```
schema_version:  1
operator_id:     "0b6f9f74-3a5e-4f2b-9a58-6f7d2f6a1c11"
pool_id:         "9f6e7f3a-1b2c-4d5e-8f90-a1b2c3d4e5f6"
account:         "c0ffee00-1111-2222-3333-444444444444"
type:            "STAKE"
amount:          60           (as a decimal, not a canonical string yet)
ts:              2026-08-11T12:34:56.789012 UTC
idempotency_key: "stake:abc"
payload:         {"phase": "escrow", "b": "2", "a": "1"}
shares:          (absent)
```

**Canonical bytes (exact, single line, no trailing newline):**

```json
{"account":"c0ffee00-1111-2222-3333-444444444444","amount":"60.000000000000000000","idempotency_key":"stake:abc","operator_id":"0b6f9f74-3a5e-4f2b-9a58-6f7d2f6a1c11","payload":{"a":"1","b":"2","phase":"escrow"},"pool_id":"9f6e7f3a-1b2c-4d5e-8f90-a1b2c3d4e5f6","schema_version":1,"ts":"2026-08-11T12:34:56.789012Z","type":"STAKE"}
```

**Same Entry with `account`, `amount`, and `payload` absent/empty** (from
`TestCanonicalJSON_OmitsAbsentOptionalFields` — proves `nil` payload and `{}` payload canonicalize
identically):

```json
{"idempotency_key":"stake:abc","operator_id":"0b6f9f74-3a5e-4f2b-9a58-6f7d2f6a1c11","payload":{},"pool_id":"9f6e7f3a-1b2c-4d5e-8f90-a1b2c3d4e5f6","schema_version":1,"ts":"2026-08-11T12:34:56.789012Z","type":"STAKE"}
```

---

## 2. The per-pool hash chain

One hash chain exists **per pool** (not per operator, not global). Genesis and construction:

```
GENESIS      = 32 zero bytes (0x00 repeated 32 times)

entry_hash = SHA256( 0x00 || prev_hash || canonical(entry) )
```

- `0x00` is a **domain-separation byte**: it reserves this prefix so a chain-entry hash preimage
  (`prefix || 32-byte prev_hash || variable-length canonical JSON`) can never collide in
  *interpretation* with the RFC 6962 Merkle tree's own `0x00`/`0x01`-prefixed preimages (§5), which
  have a completely different, non-overlapping shape (33 or 65 fixed bytes for the plain Merkle
  tree; here, 33 + variable). This is a structural (shape-based) separation, not merely a shared
  convention.
- The first event in a pool's chain has `prev_hash = GENESIS` (32 zero bytes). A verifier that is
  handed an export **not starting at genesis** cannot prove any balance and must refuse — a
  mid-chain start could be hiding an arbitrary prior state.
- Every subsequent event's `prev_hash` must equal the immediately preceding event's `entry_hash`
  exactly. Any edit to any signed field of any past entry — even one many events back — changes
  that entry's `entry_hash`, which breaks every `prev_hash` link after it. There is no way to alter
  history without this becoming detectable at the first affected position.

### Worked example (derived, not a literal test fixture)

Computed independently from the §1.7 golden canonical entry above, treated as a pool's first event
(`prev_hash = GENESIS`), using exactly the formula above — included so an implementer has one
concrete input/output pair to check a from-scratch implementation against, beyond the abstract
formula:

```
prev_hash (genesis) = 0000000000000000000000000000000000000000000000000000000000000000
                       (32 zero bytes, hex)
canonical(entry)     = <the exact §1.7 bytes>
entry_hash           = SHA256(0x00 || prev_hash || canonical(entry))
                     = e46f942d09788b16a6e94d6b84b3ef15cb84c9ed5b7155d477f621e58af175ad
```

(Verify this yourself: `sha256(bytes([0x00]) + bytes(32) + canonical_bytes)`.)

---

## 3. Ed25519 signing

Two artifact kinds are signed under this system — **receipts** (one per Entry) and **Signed Tree
Heads** (§5) — and they use **two different, domain-separated signature contexts** on purpose, so a
signature produced for one kind can never be replayed as a valid signature for the other, even
though the same key signs both.

### 3.1 Receipt signing (Entry)

```
SignatureContext = "nomarz-staking-v1:receipt:"          (ASCII, literal, includes the trailing colon)

signature = Ed25519_Sign(priv, SignatureContext || entry_hash)
```

`entry_hash` is the raw 32 signed bytes from §2 (**not** hex-encoded inside the signed message — hex
is a wire-format convention for JSON transport only). The context string is concatenated as raw
bytes directly in front of the raw hash bytes; there is no separator, delimiter, or length prefix
between the context and the hash.

Verification: `Ed25519_Verify(pub, SignatureContext || entry_hash, signature)`.

**Never sign or verify a raw, unprefixed `entry_hash` with this key scheme** — that is exactly the
confusion the context prefix exists to prevent (a signature over a bare 32-byte digest could
otherwise be replayed as a signature over anything else that happens to hash to those same bytes in
some unrelated protocol sharing the key).

### 3.2 Signed Tree Head signing (STH, STAKING-P3)

```
STHSignatureContext = "nomarz-staking-v1:sth:"           (ASCII, literal, includes the trailing colon)

signature = Ed25519_Sign(priv, STHSignatureContext || canonical(sth))
```

Where `canonical(sth)` is the STH's own canonical JSON form (§5.4) — **not** a hash of it; the full
canonical bytes are the signed payload, prefixed by the STH context string.

The two contexts (`"nomarz-staking-v1:receipt:"` vs. `"nomarz-staking-v1:sth:"`) are asserted by
test (`TestSTH_DomainSeparationFromReceipts`) to satisfy two properties, both load-bearing: (1) they
are not equal, and (2) **neither is a prefix of the other** — the second property matters because a
naive concatenation scheme without it could let a crafted payload straddle the boundary between one
context string and the start of its own signed content, forging a cross-context collision. Any
reimplementation introducing a third signed artifact kind in the future must pick a context that is
neither equal to nor a prefix/suffix of either of these.

### 3.3 Key-id derivation

```
KeyID(pub) = "ed25519:" + hex( SHA256(pub)[0:8] )
```

The first 8 bytes (16 hex characters) of the SHA-256 hash of the raw 32-byte Ed25519 public key,
hex-encoded, prefixed with the literal string `"ed25519:"`. This makes the key id a pure function of
the key material — a registry row asserting one key id while actually carrying a different key's
bytes is detectable by recomputing this formula, and a rotation is automatically "a new id" with no
naming coordination required.

### 3.4 Key registry resolution rule

A registry entry has `(key_id, public_key, purpose, valid_from, valid_to?)`. Resolving a signature
means: look up `key_id`, and require `valid_from <= at < valid_to` (or `valid_to` absent = still
open-ended), where **`at` is the signed artifact's own timestamp** (the Entry's `ts` for a receipt,
the STH's `ts` for a tree head) — **never** "now," the wall-clock time of verification. This is what
makes key rotation safe in both directions: a receipt signed under an old key still verifies forever
against that old key's now-closed validity window, and a newly-minted key can never be used to
retroactively validate a receipt dated before that key existed.

`purpose` is a free-text tag (`"staking-translog"` for this system's own chain/STH-signing keys,
`"wallet-attest"` for the custodial wallet service's attestation keys — the asset-attestation
surface, STAKING-P5, is outside this document's scope; see the platform's staking transparency API
reference for the attestations endpoint) used **only** to pin a specific trust anchor for a
specific job (e.g. "the wallet service's key, specifically, not any key in the registry") — it
plays no role in the cryptographic resolution
above. A registry entry parsed from a pre-`purpose` document has `purpose = ""`, which a
purpose-pinned check must treat as "states nothing," never as a wildcard match.

---

## 4. NDJSON export line format

The published export (`GET /api/v1/staking/transparency/export`, one operator's pool events) is
newline-delimited JSON, one object per line, no trailing newline required on the final line. Each
line:

```
{"entry":<canonical entry object>,"entryHash":"<hex>","keyId":"<string, OMITTED if unsigned>","prevHash":"<hex>","seq":<int>,"signature":"<hex, OMITTED if unsigned>"}
```

Key order (alphabetical, fixed): `entry`, `entryHash`, `keyId` (if present), `prevHash`, `seq`,
`signature` (if present).

**The critical property:** the `entry` value in this wrapper is the **exact same canonicalized
bytes** (§1) that were hashed and signed — spliced in verbatim, not re-serialized through a generic
JSON encoder that might reorder or re-escape anything. A verifier parses the line, **independently
re-canonicalizes** the parsed `entry` fields using §1's rules, and must get byte-identical output —
any parse/re-encode mismatch is exactly what catches a tampered export line. `seq` is a strictly
increasing global sequence number (used to locate an event and to detect gaps or out-of-order
lines — it is not part of any signed preimage; only a positional/ordering convenience of the export
format itself). `keyId`/`signature` are both omitted together for an unsigned producer (a
deployment running with no signing key configured) — never present with an empty-string value.

---

## 5. RFC 6962 Merkle tree and Signed Tree Head (STAKING-P3)

This is a **second, independent** cryptographic structure over the same per-pool sequence of
`entry_hash` values — it is not part of the hash chain (§2); it is built *on top of* it, so a
verifier can prove the **entire published history has not been rewritten**, a property the hash
chain alone cannot provide (two different, fabricated event sequences can each be internally
self-consistent under the chain construction — only an externally-recorded root, checked against a
from-scratch recomputation, can distinguish "the real history" from "a fabricated one that is
internally consistent").

### 5.1 Leaf and node hash formulas

```
MTH({})     = SHA256("")                       # the empty tree; SHA-256 of the zero-length string
leaf(e)     = SHA256( 0x00 || e )               # e = one pool's entry_hash (32 raw bytes)
node(l, r)  = SHA256( 0x01 || l || r )          # l, r = 32-byte child hashes, left then right
```

`0x00`/`0x01` here are RFC 6962 §2.1's leaf/interior domain separators — a fixed 33-byte preimage
for a leaf, a fixed 65-byte preimage for a node. This is structurally distinct from every other
`0x00`/`0x01`-prefixed construction in this system (§2's chain hash has a *variable-length*
preimage; §6's summation-tree preimages are variable-length and much larger) — no two constructions
in this spec can ever produce a colliding interpretation of the same bytes.

**`EmptyRoot` known-answer value** (`SHA256("")`, the published, universally-known SHA-256-of-empty-string constant):

```
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

(Never actually published as a real STH — a producer never signs a head over an empty tree — but a
verifier needs the value to be unambiguous.)

### 5.2 Tree shape: largest-power-of-two split, no self-pairing

Given `n >= 2` nodes at a level, split at `k = largest power of two strictly less than n`; the tree
over the first `k` and the tree over the remaining `n - k` are each built the same way recursively,
then combined with `node(left_subtree_root, right_subtree_root)`.

**An odd node at any level is promoted UNCHANGED to the next level up — it is never paired with
itself.** This is not a stylistic choice: self-pairing a duplicated last node is exactly the
CVE-2012-2459 class of vulnerability (two different leaf lists can be made to produce the same
root), and RFC 6962's largest-power-of-two split with unpaired promotion admits no such collision.
Any reimplementation that "simplifies" this by duplicating an odd node to force a perfect binary
tree is producing a **different, insecure** construction, not an equivalent one.

### 5.3 Inclusion proof — generation and verification

**Generation** (RFC 6962 §2.1.1, `PATH(m, D[n])`, recursive over leaf-hashed nodes `d`):

```
PATH(m, {d(0)}) = {}                            # single node: no path needed
PATH(m, D[n])   = PATH(m, D[0:k]) : MTH(D[k:n])          if m < k
PATH(m, D[n])   = PATH(m-k, D[k:n]) : MTH(D[0:k])         if m >= k
    where k = largest power of two < n
```

(`:` = append to the end of the list — proof entries accumulate bottom-up.)

**Verification** (RFC 9162 §2.1.3.2's iterative algorithm — this is the check an outside verifier
actually runs; it never needs the generation form above, only this):

```
VerifyInclusion(leaf_hash, index, tree_size, proof, root):
    if index < 0 or tree_size <= 0 or index >= tree_size: return false

    fn, sn = index, tree_size - 1
    r = leaf_hash
    for p in proof:
        if sn == 0: return false
        if (fn & 1) == 1 or fn == sn:
            r = node(p, r)
            while fn != 0 and (fn & 1) == 0:
                fn >>= 1
                sn >>= 1
        else:
            r = node(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root
```

`leaf_hash` here is **`leaf(entry_hash)`** (§5.1's leaf formula already applied) — not the raw
`entry_hash` itself.

### 5.4 Consistency proof — generation and verification

Proves the tree over the first `new_size` leaves is a strict append-only extension of the tree over
the first `old_size` leaves (`1 <= old_size <= new_size`; RFC 6962 does not define consistency
*from* the empty tree, and a producer never publishes a head over an empty tree to begin with).
`old_size == new_size` is the degenerate case: an empty proof, verified by requiring the two roots
be equal.

**Generation** (RFC 6962 §2.1.2, `SUBPROOF(m, D[n], b)`, `b` = "is this a complete subtree so far"):

```
SUBPROOF(m, D[n], true)  = {}                                        if m == n
SUBPROOF(m, D[n], false) = { MTH(D[n]) }                             if m == n
SUBPROOF(m, D[n], b)     = SUBPROOF(m, D[0:k], b) : MTH(D[k:n])      if m <= k
SUBPROOF(m, D[n], b)     = SUBPROOF(m-k, D[k:n], false) : MTH(D[0:k]) if m > k
    where k = largest power of two < n
```

`PROOF(old_size, D[new_size]) = SUBPROOF(old_size, D[0:new_size], true)`.

**Verification** (RFC 9162 §2.1.4.2's iterative algorithm):

```
VerifyConsistency(old_root, old_size, new_root, new_size, proof):
    if old_size < 1 or new_size < old_size: return false
    if old_size == new_size:
        return len(proof) == 0 and old_root == new_root

    nodes = proof
    if old_size is a power of two:              # old tree is already a "complete subtree"
        nodes = [old_root] + proof               # its root is implicit, not carried in `proof`
    if len(nodes) == 0: return false

    fn, sn = old_size - 1, new_size - 1
    while (fn & 1) == 1:
        fn >>= 1
        sn >>= 1

    fr = sr = nodes[0]
    for c in nodes[1:]:
        if sn == 0: return false
        if (fn & 1) == 1 or fn == sn:
            fr = node(c, fr)
            sr = node(c, sr)
            while fn != 0 and (fn & 1) == 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = node(sr, c)
        fn >>= 1
        sn >>= 1

    return sn == 0 and fr == old_root and sr == new_root
```

### 5.5 Signed Tree Head — canonical form and signature

An STH's fixed, versioned field set (JCS/UTF-16 sort order — all-ASCII field names here, so plain
byte order is equivalent):

```
operator_id      string, required
pool_id          string, required
root_hash        string, required — hex-encoded MTH over the pool's first tree_size entry hashes
schema_version   integer, required — 1
tree_size        integer, required — >= 1 (producer never signs a head over an empty tree)
ts               string, required — §1.6 TSFormat
```

`key_id` / `signature` are **not** part of this canonical (signed) form — they are the authenticator
riding alongside it, computed per §3.2.

**Canonical bytes:**

```
{"operator_id":"<...>","pool_id":"<...>","root_hash":"<64 lowercase hex chars>","schema_version":1,"tree_size":<int>,"ts":"<TSFormat>"}
```

**Golden vector** (`pkg/translog/sth_test.go`, `TestSTH_CanonicalJSONGolden` — root_hash here is the
32 bytes `0x00, 0x01, 0x02, ... 0x1f` in sequence, chosen only to be a recognizable, unambiguous test
pattern, not a real published root):

```json
{"operator_id":"0b6f9f74-3a5e-4f2b-9a58-6f7d2f6a1c11","pool_id":"9f6e7f3a-1b2c-4d5e-8f90-a1b2c3d4e5f6","root_hash":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","schema_version":1,"tree_size":42,"ts":"2026-08-11T09:30:00.123456Z"}
```

**Wire form** (`MarshalSTHLine`/`ParseSTHLine` — what `GET /staking/transparency/sth`'s `"sths"`
array elements and the `-sth` file's lines actually are; note this is a **different key ordering and
different key names** — camelCase — from the canonical/signed form above; the wire form is a
transport convenience, and a verifier must re-derive the canonical form from the parsed fields
before checking the signature, never assume the wire bytes are what was signed):

```json
{"keyId":"<omitted if unsigned>","operatorId":"<...>","poolId":"<...>","rootHash":"<hex>","schemaVersion":1,"signature":"<omitted if unsigned>","treeSize":<int>,"ts":"<TSFormat>"}
```

Golden wire line for the same sample STH (unsigned — `keyId`/`signature` both absent):

```json
{"operatorId":"0b6f9f74-3a5e-4f2b-9a58-6f7d2f6a1c11","poolId":"9f6e7f3a-1b2c-4d5e-8f90-a1b2c3d4e5f6","rootHash":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","schemaVersion":1,"treeSize":42,"ts":"2026-08-11T09:30:00.123456Z"}
```

`operatorId`/`poolId` on the wire form are JSON-string-escaped the same way as any other string
field (§1.5) even though every real producer only ever puts UUIDs there — `STH.Validate()` only
requires non-empty, not UUID-shaped, so a conforming parser/writer must not assume it is safe to
splice these values into a JSON string literal unescaped.

### 5.6 STAKING-P3 end-to-end verification: three checks per published head

Given a chain-verified export (§2, §9) and a sequence of published STHs for a pool, an independent
verifier performs, per head, in order:

1. **Root.** Recompute `MerkleRoot` (§5.1/§5.2) over the export's first `tree_size` entry hashes for
   this pool, from scratch. It must equal `root_hash` exactly. (If `tree_size` exceeds the number of
   events the export actually holds for this pool, this is an immediate, explicit failure — an
   export that is shorter than a head the operator itself published and signed is a caught
   inconsistency, not a silent gap.)
2. **Signature.** Verify the head's signature (§3.2) against the registry key valid at the head's
   own `ts` (§3.4).
3. **Consistency.** For every successive pair of heads (sorted by `tree_size`, then `ts`), generate
   `PROOF(old_size, D[new_size])` from the export's own leaf sequence and check it with
   `VerifyConsistency` (§5.4) against both published roots. Two heads published at the **same**
   `tree_size` must publish the identical `root_hash`, or the log has forked.

---

## 6. Proof-of-liabilities summation tree (STAKING-P4)

A **structurally different** tree from §5's plain Merkle tree — every interior node's hash preimage
carries the **sum of its subtree's balances inside it**. This is the load-bearing security property
(the Maxwell/Todd construction): without the sum bound into the hash, a dishonest tree-builder could
declare an interior node's sum as anything they like (e.g. `max(left, right)` instead of the true
`left + right`), forge a different sibling subtree per individual audit request so each person's
*own* proof still checks out, and understate the published total while nobody's individual
verification catches it. Binding the sum into the preimage closes this: a verifier re-derives every
parent's sum as `own_sum + sibling_sum` — **never** trusting a sum handed to it as metadata — and
that re-derived sum is itself what feeds the next level's hash, so a tree built over forged sums
cannot reproduce its own claimed root under honest verification.

### 6.1 Leaf hash formula

```
leaf(salt, public_id, balance) = SHA256( 0x00 || salt[16] || public_id[16] || CanonicalAmount(balance) )
```

- `salt`: exactly 16 random bytes, one per leaf (not shared across leaves — see §6.4 on why leaves
  outnumber accounts).
- `public_id`: exactly 16 raw bytes — a UUID in its raw binary form (**not** its 36-character
  hyphenated string form, and **not** hex-encoded) — the account's public identifier, the same
  identity that appears as `account` on Entry receipts (§1).
- `balance`: encoded via `CanonicalAmount` (§1.3) — an 18-decimal-place plain string, appended as
  its raw UTF-8/ASCII bytes (not length-prefixed at this layer — see §6.3 on why this parses
  unambiguously anyway).
- **Negative balances are refused outright**, both when building a leaf and when verifying a proof
  against one (§6.3) — never clamped to zero, never silently skipped. A negative leaf would let a
  dishonest party cancel real liabilities elsewhere in the sum while the published total still
  "balances" arithmetically.

### 6.2 Interior node hash formula

```
node(sumL, hashL, sumR, hashR) =
    SHA256( 0x01 || u16be(len(sL)) || sL || hashL[32]
                 || u16be(len(sR)) || sR || hashR[32] )

    where sL = CanonicalAmount(sumL), sR = CanonicalAmount(sumR)
```

`u16be(n)` = the integer `n` as a 2-byte big-endian unsigned integer. `hashL`/`hashR` are each
exactly 32 raw bytes (the child hashes, left and right). Each variable-length canonical-amount
string is preceded by its own 2-byte big-endian length, which is what keeps the variable-length
fields inside this preimage unambiguously parseable — there is exactly one way to split
`u16be(len) || bytes` apart, regardless of what characters the decimal string contains.

`sumL`/`sumR` fed into this formula are **always the re-derived subtree sums** (own value +
recursively re-derived child sums), never a value trusted from outside — see the file-header
rationale above.

**Split rule:** identical to §5.2 — largest-power-of-two, odd node promoted unchanged, never
self-paired, for the same CVE-2012-2459 reasoning.

### 6.3 Verification algorithm (one leaf, one proof, against a published `(root, total)` pair)

```
VerifyLiabilityProof(leaf, proof_steps, root, expected_total):
    if expected_total < 0: fail                 # a negative published total is refused outright
    hash = leaf_hash(leaf)                        # recompute from (salt, public_id, balance) — §6.1
    sum  = leaf.balance
    for step in proof_steps:                      # step = (sibling_sum, sibling_hash, is_left)
        if step.sibling_sum < 0: fail             # refuses a forged negative sibling sum
        if step.is_left:
            hash = node(step.sibling_sum, step.sibling_hash, sum, hash)
        else:
            hash = node(sum, hash, step.sibling_sum, step.sibling_hash)
        sum = sum + step.sibling_sum
    return (hash == root) and (sum == expected_total)
```

Both conditions in the final line are required — matching the root proves the leaf is a genuine
member of *some* committed tree; matching the accumulated sum against the separately-published
`expected_total` proves that tree's total is the one actually published, not merely internally
self-consistent. `is_left = true` means the sibling occupies the **left** position at that level (so
this leaf's own running node is on the right), matching the tree's left-to-right pairing order —
implementers should not assume proof-array order alone conveys side.

### 6.4 Leaf-generation privacy mitigation (why leaf count is not account count)

A plain summation tree leaks information: every inclusion proof exposes the sums of the sibling
subtrees along its own path, narrowing what an observer can infer about *other* accounts' balances.
This is a known residual limitation of the Maxwell/Todd scheme even with §6.2's sum-in-hash fix —
that fix stops **forgery**, it does not stop **leakage**. This system mitigates (does not eliminate
— full elimination needs Pedersen commitments + range proofs, explicitly out of scope) via:

1. **Split.** Each real user account's balance is split across `k` leaves, `k` drawn uniformly at
   random from `{1, 2, 3, 4}` per account per epoch, with **randomly-weighted** partition sizes that
   sum exactly to the real balance (never an even `balance / k` split — an evenly-split leaf set is
   itself a detectable pattern). Each split fragment gets its own independent 16-byte random salt.
2. **Padding.** The pool's house-owned accounts (`kind = 'platform'` and `kind = 'genesis'` — real
   accounts whose balances are genuinely part of the total, not fabricated) are split much more
   heavily, `k` uniform in `{8, ..., 16}`, and interleaved among the user leaves. This obscures both
   the true user leaf multiplicity and the true user count; it never inflates the published total,
   because the padding leaves are fragments of balance that was already counted once via the house
   accounts.
3. **Shuffle.** The combined leaf list (user fragments + house padding) is Fisher-Yates shuffled with
   a cryptographically strong random source before the tree is built, so a given account's split
   fragments are not adjacent and leaf *order* is not a stable, cross-epoch-correlatable function of
   account identity.

**Consequence for a verifier:** a given account's leaf count and split sizes are expected to change
every epoch — this is deliberate, not a bug or an inconsistency to flag. Only the **sum** of an
account's own leaves is a meaningful, stable quantity; a verifier should never expect leaf count or
individual fragment sizes to be stable across epochs.

---

## 7. Event-type vocabulary and the replay algorithm (STAKING-P2)

This section documents the event types a producer emits (the producer's internal event-model constants (mirrored 1:1 by this repository's own event-type table below)
`StakingEvent*` constants) and, precisely, how an independent verifier must **replay** them to
reconstruct every account's share balance and the pool's running total from nothing but the ordered
event stream — this is exactly the algorithm `cmd/staking-verify`'s `replayEvent` function
implements, transcribed here type by type.

### 7.1 Global rules (apply before the per-type switch)

- A negative `amount` or a negative `shares` field on **any** event is an immediate replay failure,
  regardless of type.
- State per pool: `accounts: map[public_account_id -> shares]` (default `0` for an unseen account),
  `total: shares` (running sum, starts at `0`).
- After **every** event, the invariant `Σ(accounts.values()) == total` must hold. A verifier should
  check this at minimum at every `EPOCH` event and once more at the very end of the stream (the
  reference implementation does exactly this — see the table below for the `EPOCH` re-check, plus a
  final pass over every pool once the whole export has been consumed).
- A `type` value not in the table below is **refused**, not skipped — an unrecognized type is
  semantics the current replay rules do not define, and silently ignoring it would let a future,
  unreviewed event type quietly stop affecting the replayed balance while still claiming to be part
  of a "verified" chain.

### 7.2 Per-type replay rules

| `type` | Carries `shares`? | Carries `account`? | Replay effect |
|---|---|---|---|
| `STAKE` | **Conditionally** — two phases share this type name. | Only when `shares` present. | **Escrow phase**: no `shares` field — money is held outside the pool, awaiting the next epoch's mint; **no replay effect at all**. **Mint phase**: `shares` present — mints (`account.shares += shares`, `total += shares`) at the epoch's frozen price. |
| `FEE_MINT` | Always | Always | Mint: `account.shares += shares`, `total += shares`. Distributed protocol fees minted as new shares. |
| `CAPITAL_MINT` | Always | Always | Mint: same as above. An admin capital injection. |
| `UNSTAKE_BURN` | Always | Always | Burn: `account.shares -= shares`, `total -= shares`. Refused if either would go negative. `amount` on this event is the frozen payout the holder will receive. |
| `CAPITAL_BURN` | Always | Always | Burn: same mechanics as `UNSTAKE_BURN`. An admin capital withdrawal. |
| `WRITE_DOWN` | Always | Always | Burn: same share-ledger mechanics as `UNSTAKE_BURN`/`CAPITAL_BURN` — `account.shares -= shares`, `total -= shares`. Distinct **economically** (this is a recapitalization haircut: the holder recovers nothing, and `amount` on this event is an explicit `0` rather than a real payout) but the replay algorithm treats it identically to any other burn — it only ever reads `shares`. |
| `UNSTAKE_REQUEST` | **Must be absent** | — | No share movement — a pure state-transition record (position enters the unstake queue). An event of this type carrying a `shares` field is malformed and must be refused. |
| `UNSTAKE_CANCEL` | **Must be absent** | — | No share movement — reverts a queued unstake request. |
| `UNSTAKE_CLAIM` | **Must be absent** | — | No share movement — records the wallet payout of an already-burned position; the share ledger was already updated by the `UNSTAKE_BURN` event earlier in the chain. |
| `RECAPITALIZE` | **Must be absent** | — | No share movement — a **pool-level** state transition (`halted -> active`). Whatever share movement a recapitalization actually performs is carried by its own separate `WRITE_DOWN`/`CAPITAL_MINT` events elsewhere in the chain, each replayed on their own terms per this table — `RECAPITALIZE` itself is a marker, not a ledger action. |
| `EPOCH` | **Must be absent** | — | No share movement. The event's `payload["shares_close"]` key is **required** (its absence is itself a replay failure, not a skipped check) — parse it as a decimal amount and require it to equal the **currently replayed** `total` exactly; a mismatch is a replay failure (the producer's own declared closing balance disagreeing with what the events actually add up to). Then re-check `Σ(accounts.values()) == total` for the whole pool. **At `schema_version >= 2`**, four additional economic checks apply — see §7.4. |
| `ADJUSTMENT` | **Must be absent** | — | No share movement — a governance/audit marker, mirrored on the other no-share-movement types above. |
| `POLICY_CHANGE` | **Must be absent** | — | No share movement — a **pool-level** governance marker: the operator moved this pool's stake bounds (`min_stake_amount` / `max_stake_amount`). It changes which FUTURE stakes are admissible, never the shares already outstanding, so the replay algorithm reads nothing from it beyond refusing a `shares` field. The payload carries `min_stake_amount`, `max_stake_amount`, `prev_min_stake_amount`, `prev_max_stake_amount`, `actor` and `reason`; an **uncapped** max is the literal string `"null"` on both the current and previous key, never an absent key. Emitted once per ACTUAL change — a resubmitted, value-identical policy write appends nothing. |

**Note on `ADJUSTMENT`:** The producer's internal event model defines a constant
`StakingEventAdjustment = "ADJUSTMENT"`. As of this writing no producer path emits it — it is
reserved for future use — but the reference verifier (`cmd/staking-verify`) DOES know the type and
replays it as a no-share-movement event (refusing it if it carries a `shares` field), specifically
so that if a future producer ever appends one, it does not retroactively make every later event on
that pool's chain unverifiable. A reimplementation should do the same: treat `ADJUSTMENT` as valid
input with no ledger effect, not as an unknown type to refuse.

### 7.3 Burn floor

A burn (`UNSTAKE_BURN`, `CAPITAL_BURN`, `WRITE_DOWN`) that would take an account's shares, or the
pool's running total, negative is a **hard replay failure** — not clamped to zero, not silently
skipped. No valid event stream ever produces a negative balance at any point in the replay.

### 7.4 Schema Version 2 — EPOCH economic checks

At `schema_version >= 2` (see the schema-version note in the preamble), an `EPOCH` event's payload
additionally carries `cap_net`: the net sum of CAPITAL-kind bankroll-ledger movements (deposits,
withdrawals, treasury in/out) over the same `(ledger_id_from, ledger_id_to]` watermark window `ggr`
is computed over. It is the exact value the producer's own `assets_open + ggr + cap_net ==
[pre-flow assets]` invariant asserts before it ever applies a subscription or redemption — so a
reimplementation must not derive `cap_net` independently; it is a value the producer computes once
and signs, and a verifier only ever compares against it.

Four additional checks apply to every `schema_version >= 2` `EPOCH` event, each a **hard replay
failure** on mismatch. Let `assets_mid = assets_open + ggr + cap_net` and
`shares_after_fee = shares_open + fee_shares`:

1. **Price.** When `shares_after_fee > 0`: `price` must equal `assets_mid / shares_after_fee`,
   rounded (not floored) to 36 fractional decimal digits — the exact ratio the producer itself
   divides to freeze the epoch's price, at the exact scale it uses. **This is deliberately NOT
   `assets_close / shares_close`**: subscriptions and redemptions are applied AFTER the price is
   frozen, each at its own floor-truncated rate, so the closing ratio drifts away from the frozen
   price by the sum of those truncation remainders whenever any subscription or redemption
   happened that epoch. Checking the closing ratio instead of the frozen one would false-positive
   on almost every real epoch with activity.
2. **Cross-epoch asset chaining.** One pool's EPOCH events must chain: epoch *N*'s `assets_close`
   must equal epoch *N+1*'s `assets_open`, exactly. Skipped on a pool's first EPOCH event (nothing
   to chain against yet).
3. **Epoch invariant.** `assets_close` must equal `assets_mid + net_stake_movement`, where
   `net_stake_movement` is this epoch's own net effect of subscriptions minted and redemptions
   burned since the previous EPOCH — reconstructed by the verifier purely by summing the `amount`
   field of every `STAKE` event with `shares` present (the mint phase) and subtracting the `amount`
   of every `UNSTAKE_BURN` event replayed in that window. **This is not simply
   `assets_open + ggr + cap_net`** — that identity only holds on an epoch with zero net
   subscription/redemption activity; a reimplementation that checks the naive form will
   false-positive on any epoch that actually moved stake.
4. **Fee-share mint algebra.** Recompute the producer's exact minting formula —
   `floor((fee × shares_open) / (assets_mid − fee))`, floored (not rounded) to 18 fractional decimal
   digits, using the SAME truncating integer division the producer's share-mint math uses
   throughout this system (§1.3's "truncation always favors the pool" convention) — and require the
   declared `fee_shares` to match **exactly**. Only apply this recomputation when `fee > 0` AND
   `shares_open > 0` AND `assets_mid − fee > 0`; otherwise the expected value is `0`. **Do not check
   `fee_shares × price == fee` directly** — `fee_shares` is floored and `price` is separately
   rounded, so their product only equals `fee` exactly by coincidence, not by construction; that
   check spuriously fails on almost every real winning epoch. On a losing or flat day (`fee <= 0`),
   the producer mints no fee shares but still always writes the `fee_shares` key (as `"0"`), never
   omitting it.

A `schema_version: 1` `EPOCH` event (no `cap_net` in its payload) is not subject to any of the four
checks above — only §7.2's `shares_close` check applies, exactly as it always has.

---

## 8. Known-answer test vectors

Every value in this section is quoted verbatim from `pkg/translog`'s test suite (file and test name
given per vector) unless explicitly marked "derived" (computed by the author of this document from
an already-golden input, using the formula given in the corresponding section — included for
implementer convenience, not itself a value pinned by any test).

### 8.1 Canonical Entry (§1.7)

See §1.7 above in full — both the fully-populated form and the all-optional-fields-absent form, from
`canonical_test.go`'s `TestCanonicalJSON_GoldenVector` and `TestCanonicalJSON_OmitsAbsentOptionalFields`.

### 8.2 Chain hash (derived; §2)

```
entry_hash = SHA256(0x00 || 32-zero-byte-genesis || <the §1.7 canonical bytes>)
           = e46f942d09788b16a6e94d6b84b3ef15cb84c9ed5b7155d477f621e58af175ad
```

### 8.3 STH canonical form and wire line (§5.5)

Both quoted verbatim above in §5.5, from `sth_test.go`'s `TestSTH_CanonicalJSONGolden` and
`TestSTH_WireLineGolden`.

### 8.4 RFC 6962 Merkle tree — official Certificate Transparency known-answer vectors

From `pkg/translog/merkle_test.go`'s `ctVectorInputs`/`ctVectorRoots` — these are the published RFC
6962 / Certificate Transparency `merkletree` reference test inputs (the de-facto official KATs for
this exact tree shape), reproduced here so a from-scratch reimplementation of `MTH` can self-check
without needing this repository's test file:

**Leaf inputs** (hex, index 0 through 7):

```
0:  (empty)
1:  00
2:  10
3:  2021
4:  3031
5:  40414243
6:  5051525354555657
7:  606162636465666768696a6b6c6d6e6f
```

**`MTH` over the first `n` of these inputs** (each row applies §5.1's `leaf()` to each raw input
byte string first, then §5.1/§5.2's tree construction):

| `n` | `MTH(D[n])` |
|---|---|
| 1 | `6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d` |
| 2 | `fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125` |
| 3 | `aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77` |
| 4 | `d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7` |
| 5 | `4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4` |
| 6 | `76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef` |
| 7 | `ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c` |
| 8 | `5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328` |

Each value above is a 64-character lowercase hex string (32 raw bytes), quoted verbatim from the
test source.

**`MTH({})` (empty tree):**

```
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

(This is simply `SHA256("")`, the well-known universal constant — also independently confirmed by
`TestMerkleRoot_EmptyTreeIsHashOfNothing`.)

### 8.5 Proof-of-liabilities summation tree (derived; §6)

No golden vector is pinned in the current test suite for this tree (the tests use randomly-salted,
round-trip-only fixtures rather than a fixed known-answer vector). The following 2-leaf example was
computed by the author of this document directly from §6.1/§6.2's formulas — included so an
implementer has at least one concrete checkpoint, but treat it as **derived, not test-pinned**:

```
leaf 1: salt = 0x01 x16, public_id = UUID 11111111-1111-1111-1111-111111111111, balance = 10
leaf 2: salt = 0x02 x16, public_id = UUID 22222222-2222-2222-2222-222222222222, balance = 20

leaf(leaf1) = 1347236c9ce2663dc8745f6e447d28f7c8f3ab048e10f0a29c5e4aa1ad12e2b1
leaf(leaf2) = 81a8203e064561b837f343440ebb0597d78cbf7296022c1407be150b0558bb20

root = node("10.000000000000000000", leaf(leaf1), "20.000000000000000000", leaf(leaf2))
     = 07d8a5cc4b545baea88bfe6a9c3119e20a665ef572f93f24b412cce011918909

total (root sum) = 30.000000000000000000
```

---

## 9. Summary: what a reimplementer needs, end to end

To build a compatible verifier from nothing but this document:

1. Implement §1's canonical JSON encoder for an Entry.
2. Implement §2's chain-hash construction and validate a chain of entries against it.
3. Implement §3's two Ed25519 signature contexts and §3.3's key-id derivation; resolve signatures
   against a key registry using §3.4's "at the artifact's own timestamp" rule.
4. Implement §4's NDJSON export parser, re-canonicalizing every parsed entry and comparing against
   the line's own `entryHash`.
5. Implement §7's per-type replay algorithm to reconstruct account balances and the pool total.
6. Optionally, implement §5's RFC 6962 Merkle tree + STH verification to additionally prove
   append-only history across published heads.
7. Optionally, implement §6's summation tree to verify individual proof-of-liabilities proofs.
8. Self-check every piece against §8's known-answer vectors before trusting the implementation
   against a real, live export.

See `cmd/staking-verify/README.md` for what a **complete** verifier proves and does not prove when
run end to end against a live operator's published endpoints, including the standing anchoring gap
that applies regardless of implementation language.
