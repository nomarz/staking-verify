# staking-verify

A standalone command-line tool that independently re-verifies the player-staking transparency log
published by this platform (STAKING-P2 through P5). It is written for an external auditor, a
technically sophisticated player, or anyone else who does not want to take the platform's word for
its own staking numbers — it recomputes everything itself from cryptographic primitives and a
handful of published, unauthenticated HTTP endpoints, and refuses to print "OK" unless every check
actually passes.

This document assumes no familiarity with this company's internal codebase. It does assume you are
comfortable running a command-line tool and reading `curl` output.

## What this tool proves

Run against one operator's published export (and, optionally, its Signed Tree Heads,
proof-of-liabilities proof, and asset attestations), `staking-verify` establishes, purely by
recomputation — it never trusts a stored total, a stored hash, or the server's own word for
anything:

1. **The hash chain is intact.** Every event in the exported log is chained to the one before it
   (`entry_hash = SHA256(0x00 || prev_hash || canonical(entry))`, genesis anchored at 32 zero
   bytes). Editing, reordering, or deleting any past event breaks this at the first affected
   position — there is no way to retroactively alter history without the tool detecting exactly
   where.
2. **Every event is signed by the platform.** Each event's Ed25519 signature is checked against
   the *published key registry*, resolved to the specific key that was valid **at that event's own
   timestamp** — so a key rotation months later can never invalidate (or forge) an old receipt, in
   either direction.
3. **Every account's balance is exactly what the events say it is.** The tool replays the entire
   event log itself — mints, burns, epoch closes — to rebuild every account's share balance from
   scratch. No stored balance is trusted; Σ(every account's shares) is cross-checked against the
   pool's running total throughout, and every `EPOCH` event's declared closing total is checked
   against the replay.
4. **(with `-sth`) The log has not been secretly rewritten.** A hash chain alone cannot prove
   nobody swapped the *entire* history for a different, internally-consistent one — two distinct
   histories can each individually check out. The **Signed Tree Head** mechanism (STAKING-P3, RFC
   6962) closes this gap: the tool recomputes the Merkle root over the exported events from scratch
   for every published head, checks its signature, and proves every successive pair of heads is a
   strict *append-only* extension of the one before — the property a rewritten-from-scratch chain
   cannot fake, because it cannot reproduce a root that was recorded and signed before the rewrite
   happened.
5. **(with `-pol`) Your own balance was honestly counted in a published total.** Proof-of-Liabilities
   (STAKING-P4) publishes a Merkle summation tree whose root commits to the *sum* of every staker's
   balance. Given your own leaf material and sibling path (which only you can fetch — see below),
   the tool proves your balance was counted, without revealing anyone else's balance to you or you
   to them.
6. **(with `-attest`) An attestation's signature and freshness binding are valid**, and reports the
   attested-vs-liabilities arithmetic as data for you to read.

## What this tool does NOT prove

Read this section as carefully as the one above — the gaps are as load-bearing as the guarantees.

- **It does not prove the platform holds any real-world assets.** Nothing in items 1–4 above says
  anything about money the platform actually possesses — only that the *liabilities* (what it owes
  stakers) were counted honestly and the *event history* was not tampered with.
- **Asset attestations (`-attest`, item 6) are testimony, not proof.** An attestation is a signed
  claim by a named party (e.g. the wallet service, or a human auditor whose statement staff
  recorded) — the tool checks that the claim is genuinely signed by who it says and bound to a
  specific point in time, but a signature over a false number is still just a signed false number.
  This tool, and this platform, will never call this "Proof of Reserves." Treat it as "Attested
  Reserves" and read the `basisNotes` on every figure — they say exactly what was and wasn't
  counted.
- **It does not prove the exported log is complete**, unless you also supply `-sth`. Without a
  Signed Tree Head to check the export's size against, a truncated export (the operator quietly
  withholding the most recent N events) verifies perfectly fine as far as chain/signature/replay
  are concerned — there is nothing in the chain itself that says how long it *should* be. With
  `-sth`, a truncated export is caught explicitly: the tool recomputes the Merkle root over
  whatever the export actually contains and demands it match a published head's root at that exact
  size, so an export that's shorter than a head the operator itself signed and published fails
  loudly (`STH covers N events but the export holds only M`).
- **It does not prove append-only history against a truly independent record — only against a head
  you already hold.** See [Anchoring](#anchoring-what-is-and-isnt-covered) below; this is the single
  biggest structural gap today and it is spelled out precisely, not glossed over.
- **It has no opinion on business logic** beyond replaying the published event vocabulary (stake,
  unstake, epoch mint/burn, etc.) exactly as documented. It does not evaluate whether the platform's
  fee terms, pricing, or product design are fair — only whether the numbers are internally honest
  and untampered.

## What this repository is

This is the public, standalone mirror of `staking-verify` — the platform's own reference verifier
for its staking transparency log. It imports **zero** internal (`internal/`) packages from the
platform's backend: only the published cryptographic primitives (`pkg/translog`, `pkg/attest`) and
a small vendored decimal-amount helper (`internal/money`, copied in verbatim so this module never
needs to reach a private Go module to build). Anyone can clone this repository, read every line of
what it checks, build it, and run it against a live operator's published endpoints without asking
the platform for anything or trusting anything about the platform's own build.

The specification this tool implements is documented independently of the Go source in
`docs/SPEC.md` — precise enough that a *reimplementation* in Python, Rust, or JavaScript needs no
access to this repository's code at all, only that document. Treat the spec, not this binary, as
the actual long-term trust anchor: reading and re-deriving the spec is the strongest form of
verification there is; running this binary is the convenient middle ground between that and taking
the platform's word for it.

## Build instructions

```sh
git clone https://github.com/wasabi-gaming/staking-verify.git
cd staking-verify
go build ./cmd/staking-verify
```

This produces a `staking-verify` binary in the current directory. Requires only a working Go
toolchain — every dependency (`github.com/google/uuid`, `github.com/shopspring/decimal`) is a
public Go module, so no credentials or private module access of any kind are needed. Pre-built
release binaries for common platforms are attached to this repository's
[Releases](../../releases) page, if you'd rather skip building from source.

## The four inputs

The tool never talks to the network itself — every input is a file you fetch yourself (or pipe in),
so you can save, diff, and re-verify the exact same evidence later.

| Flag | What it is | Where it comes from | Auth |
|---|---|---|---|
| `-registry keys.json` | The published Ed25519 signing-key registry (`{"keys":[...]}`) | `GET /api/v1/staking/transparency/key` | none |
| `-sth sths.ndjson` | Published Signed Tree Heads, one JSON object per line | `GET /api/v1/staking/transparency/sth?pool=<uuid>`, then `jq -c '.sths[]'` | none |
| `-pol proof.json` | Your own proof-of-liabilities leaves + sibling path for one epoch | `GET /api/v1/staking/transparency/pol/:epoch/proof?pool=<uuid>` (`:epoch` may be the literal `latest`) | **your own player JWT** — this endpoint only ever returns the caller's own leaves, so an anonymous outsider cannot fetch it for someone else |
| `-attest attestations.json` | The epoch's asset attestations next to the PoL total they're read against | `GET /api/v1/staking/transparency/attestations/:epoch?pool=<uuid>` | none |
| *(positional argument)* | The NDJSON event export | `GET /api/v1/staking/transparency/export?pool=<uuid>` (paginated — see below), or `-` for stdin | none |

Every one of these except `-pol` is a fully public, unauthenticated `GET` request — an outside
auditor with nothing but `curl` and the operator's hostname can fetch four of the five inputs
without ever logging in. Only the proof-of-liabilities *proof* (as opposed to the epoch's public
root/total, which is also unauthenticated at `GET /api/v1/staking/transparency/pol/:epoch`) requires
a real player session, because it is scoped to that player's own balance.

**Export pagination:** `GET .../export` caps each response at 5000 rows. When a page fills, the
response carries an `X-Next-From-Seq` response header — pass that value as `from_seq` on the next
request to continue. To verify balances, the export **must start at a pool's first event**
(`from_seq` omitted or `0`) — the tool refuses to replay balances from a mid-chain start, since a
partial history cannot prove what came before it.

## End-to-end example

Everything below uses clearly fake placeholder values — substitute your own operator hostname and
pool id.

```sh
OPERATOR_HOST=demo.example-operator.invalid
POOL_ID=b1f6e9a2-0f3d-4b8e-9c11-2a7e4d9c0f01

# 1. The signing-key registry (public)
curl -s "https://$OPERATOR_HOST/api/v1/staking/transparency/key" -o keys.json

# 2. The full event export for this pool, from its first event (public)
curl -s "https://$OPERATOR_HOST/api/v1/staking/transparency/export?pool=$POOL_ID" -o export.ndjson
# If the response carried an X-Next-From-Seq header, fetch the next page with
# ?pool=$POOL_ID&from_seq=<that value> and append it to export.ndjson, repeating until absent.

# 3. Published Signed Tree Heads for this pool (public)
curl -s "https://$OPERATOR_HOST/api/v1/staking/transparency/sth?pool=$POOL_ID" \
  | jq -c '.sths[]' > sths.ndjson

# 4. The epoch's asset attestations next to the PoL figure (public)
curl -s "https://$OPERATOR_HOST/api/v1/staking/transparency/attestations/latest?pool=$POOL_ID" \
  -o attestations.json

# 5. Your OWN proof-of-liabilities proof for this pool's latest epoch (requires YOUR player JWT)
curl -s \
  -H "Authorization: Bearer $PLAYER_JWT" \
  -H "Host: $OPERATOR_HOST" \
  "https://$OPERATOR_HOST/api/v1/staking/transparency/pol/latest/proof?pool=$POOL_ID" \
  -o pol_proof.json
```

Now build and run each verification mode:

```sh
go build ./cmd/staking-verify

# Chain integrity + signatures + balance replay
./staking-verify -registry keys.json export.ndjson

# The same, plus STAKING-P3: Merkle roots, STH signatures, append-only consistency
./staking-verify -registry keys.json -sth sths.ndjson export.ndjson

# STAKING-P4: your own proof-of-liabilities leaves against the published root/total
# (standalone — needs no export)
./staking-verify -pol pol_proof.json

# STAKING-P5: attestation signatures + challenge-freshness against the published heads
# (standalone — needs no export; -sth here supplies the published root set the challenges
# must match, it does not re-verify the heads' own signatures a second time)
./staking-verify -attest attestations.json -sth sths.ndjson -registry keys.json

# Or all of it in one run against the export
./staking-verify -registry keys.json -sth sths.ndjson -pol pol_proof.json \
  -attest attestations.json export.ndjson
```

Pipe the export directly instead of saving it first, if you prefer:

```sh
curl -s "https://$OPERATOR_HOST/api/v1/staking/transparency/export?pool=$POOL_ID" \
  | ./staking-verify -registry keys.json -
```

A successful run prints a summary and exits `0`:

```
OK: 128 event(s) verified across 1 pool(s) at 2026-08-14T12:00:00Z
pool b1f6e9a2-0f3d-4b8e-9c11-2a7e4d9c0f01: 128 event(s), final chain head 6539a2..., total shares 1080.000001080000000000
  account 70179f99-...: 60.000000000000000000 shares
STH: 3 head(s) verified across 1 pool(s)
pool b1f6e9a2-0f3d-4b8e-9c11-2a7e4d9c0f01: latest verified tree_size 128
PoL: 2 own leaf/leaves verified against the published root for epoch 4182 (2026-08-11), pool b1f6e9a2-0f3d-4b8e-9c11-2a7e4d9c0f01
PoL: own counted balance 40.000000000000000000 of published total 125000.000000000000000000 (57 leaves in tree)
PoL: root 6539a2...
```

### Optional: `-allow-unsigned` and `-wallet-key`

- `-allow-unsigned` accepts entries/heads with no signature at all. Use this **only** if you
  independently know the producing deployment runs unsigned (an operator with no signing key
  configured); otherwise its presence in your command line silently defeats the entire signature
  check for that run.
- `-wallet-key <hex>` pins a specific 32-byte Ed25519 public key (obtained out-of-band, e.g.
  published by the wallet operator through some other trusted channel) as the wallet service's
  attestation key for `-attest`, instead of relying on the `-registry`'s `purpose: "wallet-attest"`
  entry. Without either `-wallet-key` or a registry carrying that purpose entry, `-attest` still
  checks each record's signature, but only against the key *embedded in the record itself* — which
  proves internal self-consistency, not that any particular named party actually signed it. The
  tool's own output text says exactly which of these two modes it ran in; read it.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Everything requested verified. A summary is printed to stdout. |
| `1` | Verification **failed**. The first failing sequence number (or, for `-sth`, the failing `tree_size`) and the specific check that failed (`chain`, `signature`, `replay`, `sth`, `sth-signature`, `sth-consistency`, or the `-pol`/`-attest` equivalents) are printed to stderr. This is the exit code a CI gate or a monitoring script should treat as a hard failure. |
| `2` | Usage or I/O error — bad flags, a file that couldn't be read, malformed JSON that isn't even shaped like the expected input. This is not a verification failure; it means the tool couldn't run the check at all. |

## Anchoring: what is (and isn't) covered

Every guarantee above involving Signed Tree Heads (item 4, and everything `-sth` enables) is
relative to a head **you already hold**. If you fetched last month's STH and kept it, this tool can
prove nothing was rewritten between then and now. But if a newcomer shows up today with no prior
head at all, that alone proves nothing about whether *today's* published log is the same one that
existed a month ago — an operator could, in principle, quietly maintain two internally-consistent
histories and show each auditor whichever one they'd never seen a head from before. Closing that gap
requires **anchoring**: committing each Signed Tree Head to some medium the platform does not
control.

`pkg/attest.OpenTimestampsAnchorer` (STAKING-P5+) is a real, wired implementation of this — when an
operator enables it, each newly-published STH is submitted to independent OpenTimestamps calendar
servers, which aggregate it toward a Bitcoin timestamp transaction. `GET /staking/transparency/sth`
publishes the resulting record(s) in an additive `anchors` array; feed that array to this tool as
`-anchors anchors.ndjson` (alongside `-sth`) and it independently recomputes each anchor's digest
binding — `SHA256(canonical(sth))`, matched against the anchor's own embedded digest — for real, with
no platform-internal code imported to do it.

**What this genuinely proves, and what it does not, matters here — be precise:**

- **Checked, always, for real:** the anchor's claimed digest is exactly the SHA-256 of the STH it's
  attached to. An anchor record that doesn't bind to the head it claims to anchor is caught.
- **Never checked here:** whether the underlying OpenTimestamps proof actually resolves to a real
  Bitcoin block, or whether that block is on the best chain. This tool reports each anchor's state
  (`pending` — submitted, awaiting Bitcoin confirmation — or `confirmed`, per the calendar server's
  own testimony) and its raw reference material, but does not itself walk the OTS proof tree against
  the Bitcoin blockchain. **Confirm a `confirmed` anchor independently with the external `ots`
  tool** against the digest this tool reports — that is where the actual chain-level verification
  happens, deliberately outside this codebase, exactly the same "testimony vs. proof" split this
  system already uses for attested reserves (Attested Reserves, never Proof of Reserves).
- **Coverage is operator-dependent, not universal.** Anchoring is opt-in per operator
  (`AnchorOtsEnabled`, default off). An `-sth` result with no matching `-anchors` record is not
  itself suspicious — it may simply mean this operator hasn't enabled anchoring yet. Treat "no
  anchor for this head" as "unanchored, verify the rest on trust in the head you hold," not as a red
  flag on its own.

Until every operator enables anchoring and every anchor is independently walked to Bitcoin (by you,
via `ots`, not by this tool), the honest characterization of an UNanchored `-sth` result stands as
before: **append-only relative to a head you already hold, not against a truly independent,
externally-timestamped record.**

## Further reading

- `docs/SPEC.md` (this repository) — the portable specification of every formula this tool
  implements: canonical JSON encoding, the hash-chain construction, Ed25519 signing contexts, the
  RFC 6962 Merkle tree and STH mechanism, the proof-of-liabilities summation tree, the NDJSON
  export format, and the event-replay algorithm. Written to be implementable without reading this
  repository's Go source at all.
- The "The four inputs" table above documents every REST endpoint this tool's inputs are fetched
  from. For the full request/response shapes and error codes, ask the operator you're verifying
  for their published API reference — it is not part of this repository, since it documents a
  specific deployment's HTTP surface rather than the verification algorithm itself.
