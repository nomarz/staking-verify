// Package translog implements the domain-free primitives of the STAKING-P2 transparency log:
// RFC 8785 (JCS) canonical JSON serialization over a FIXED, VERSIONED field set (canonical.go),
// the per-pool SHA-256 hash chain (chain.go), Ed25519 receipt signing with a rotatable published
// key registry (keys.go), and the NDJSON export line format the standalone verifier consumes
// (export.go).
//
// NOTHING in this package touches a database, a network, or any casino-specific concept beyond
// the field names of one log entry. That is deliberate: cmd/staking-verify — a standalone,
// potentially open-sourceable binary — must be able to verify a published export using ONLY this
// package plus the published key registry, without trusting (or even compiling) the production
// write path in internal/.
//
// Money discipline: every amount/shares value is an exact decimal
// (github.com/wasabi-gaming/staking-verify/internal/money.Amount), serialized in the signed preimage
// as a fixed 18-decimal-place plain string ("60.000000000000000000") — no floats, no exponents,
// no scale ambiguity — matching the numeric(36,18)/numeric(48,18) columns the values round-trip
// through. 18 places exactly is what makes the DB round trip byte-stable: Postgres pads a
// numeric(x,18) column's text form to 18 fractional digits, so canonical-at-append and
// canonical-at-export cannot drift on formatting.
package translog

import (
	"errors"
	"fmt"
	"sort"
	"time"
	"unicode/utf16"

	"github.com/wasabi-gaming/staking-verify/internal/money"
)

// SchemaVersion1 is the original canonicalization schema. The value is embedded in the
// canonicalized struct itself — i.e. it is part of what gets signed — so if the canonical format
// ever changes, every already-issued receipt still self-declares which format produced it and old
// exports stay verifiable forever.
const SchemaVersion1 = 1

// SchemaVersion2 is a field-set-compatible bump: the wire shape of Entry is unchanged (no new
// struct field), but producers on this version are understood to additionally populate the EPOCH
// event's Payload with "cap_net" (the producer's epoch-settlement routine, RunEpoch) — the
// signed field cmd/staking-verify/verify.go's price/asset-chaining/invariant/fee-share-algebra
// checks require. schema_version is a SINGLE GLOBAL CONSTANT applied uniformly to every appended
// event regardless of type (the producer's translog-append routine is the
// ONE writer of the event log) — there is no per-event-type schema selection in this package —
// so bumping the producer's constant to SchemaVersion2 means every newly-appended event of every
// type (STAKE, FEE_MINT, UNSTAKE_BURN, EPOCH, ...) now carries v2, even though only EPOCH's
// payload actually gained a new key. This is deliberately the minimal-blast-radius choice over
// teaching this package to hand out a version per event type: every already-exported
// SchemaVersion1 entry keeps verifying under EXACTLY the rules it always has (Validate/
// CanonicalJSON accept both versions unchanged; the verifier's new checks are additive and gated
// on SchemaVersion >= SchemaVersion2), so nothing already published is invalidated by this bump.
const SchemaVersion2 = 2

// AmountScale is the fixed number of decimal places every amount/shares value is normalized to
// in the canonical form. MUST match the fractional scale of the numeric(36,18)/numeric(48,18)
// columns the values are stored in — see the package doc comment for why.
const AmountScale = 18

// TSFormat is the fixed canonical timestamp layout: RFC 3339, UTC, exactly six fractional
// digits (microseconds — Postgres timestamptz's native precision, so a stored ts re-renders
// byte-identically).
const TSFormat = "2006-01-02T15:04:05.000000Z"

// ErrInvalidEntry guards malformed entries reaching canonicalization.
var ErrInvalidEntry = errors.New("translog: invalid entry")

// Entry is the FIXED, VERSIONED field set of one transparency-log event — exactly what gets
// canonicalized, hashed into the chain, and signed. Field names in the canonical JSON are the
// snake_case forms noted per field; the canonical object contains nothing else.
//
// Optional fields (Account, Amount, Shares) are OMITTED from the canonical form when absent —
// never emitted as null — so "absent" has exactly one byte representation.
type Entry struct {
	// SchemaVersion is the canonicalization schema ("schema_version") — SchemaVersion1 or
	// SchemaVersion2 today; CanonicalJSON refuses anything else rather than guessing at a future
	// layout.
	SchemaVersion int
	// OperatorID is the owning tenant's uuid string ("operator_id").
	OperatorID string
	// PoolID is the pool's uuid string ("pool_id"). One hash chain exists PER pool.
	PoolID string
	// Account is the PUBLIC account id ("account", stake_accounts.public_id) — never the internal
	// account id and never a user id: the canonical form is what gets exported to anonymous
	// callers, so the private identity must be structurally unable to appear in it. Empty =
	// omitted (an event with no account, e.g. EPOCH).
	Account string
	// Type is the event type ("type"), e.g. "STAKE", "EPOCH" — vocabulary owned by the caller.
	Type string
	// Amount is the money amount ("amount"), 18-dp normalized. nil = omitted.
	Amount *money.Amount
	// Shares is the share count ("shares"), 18-dp normalized. nil = omitted.
	Shares *money.Amount
	// TS is the event timestamp ("ts"), serialized via TSFormat. Callers must truncate to
	// microseconds BEFORE storing/canonicalizing so the DB round trip is exact.
	TS time.Time
	// IdempotencyKey ("idempotency_key") binds the event to the state change that produced it.
	IdempotencyKey string
	// Payload ("payload") carries per-type extras as a FLAT string->string map — string values
	// only, so a JSONB round trip through the database cannot renumber, reorder, or otherwise
	// re-encode anything. nil serializes as the empty object {} (matching the column's DEFAULT
	// '{}'), so nil and empty are the same canonical bytes.
	Payload map[string]string
}

// Validate checks the entry can be canonicalized at all.
func (e Entry) Validate() error {
	if e.SchemaVersion != SchemaVersion1 && e.SchemaVersion != SchemaVersion2 {
		return fmt.Errorf("%w: unsupported schema_version %d", ErrInvalidEntry, e.SchemaVersion)
	}
	if e.OperatorID == "" || e.PoolID == "" {
		return fmt.Errorf("%w: operator_id and pool_id are required", ErrInvalidEntry)
	}
	if e.Type == "" {
		return fmt.Errorf("%w: type is required", ErrInvalidEntry)
	}
	if e.IdempotencyKey == "" {
		return fmt.Errorf("%w: idempotency_key is required", ErrInvalidEntry)
	}
	if e.TS.IsZero() {
		return fmt.Errorf("%w: ts is required", ErrInvalidEntry)
	}
	return nil
}

// CanonicalJSON returns the RFC 8785 (JCS) canonical serialization of the entry — the exact
// byte sequence that participates in the hash chain and (via the entry hash) the signature.
// Deterministic by construction: field order is fixed (the JCS sort of the fixed key set),
// payload keys are sorted by UTF-16 code units per JCS, amounts are 18-dp fixed-point strings,
// and the timestamp uses TSFormat.
func (e Entry) CanonicalJSON() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	// Keys below appear in their JCS (UTF-16 code unit) sort order for this fixed field set:
	// account < amount < idempotency_key < operator_id < payload < pool_id < schema_version <
	// shares < ts < type. All-ASCII keys, so this equals plain byte order.
	buf := make([]byte, 0, 512)
	buf = append(buf, '{')
	first := true
	appendField := func(key string, writeValue func([]byte) []byte) {
		if !first {
			buf = append(buf, ',')
		}
		first = false
		buf = appendJSONString(buf, key)
		buf = append(buf, ':')
		buf = writeValue(buf)
	}
	if e.Account != "" {
		appendField("account", func(b []byte) []byte { return appendJSONString(b, e.Account) })
	}
	if e.Amount != nil {
		appendField("amount", func(b []byte) []byte { return appendJSONString(b, CanonicalAmount(*e.Amount)) })
	}
	appendField("idempotency_key", func(b []byte) []byte { return appendJSONString(b, e.IdempotencyKey) })
	appendField("operator_id", func(b []byte) []byte { return appendJSONString(b, e.OperatorID) })
	appendField("payload", func(b []byte) []byte { return appendCanonicalStringMap(b, e.Payload) })
	appendField("pool_id", func(b []byte) []byte { return appendJSONString(b, e.PoolID) })
	appendField("schema_version", func(b []byte) []byte { return appendJSONInt(b, e.SchemaVersion) })
	if e.Shares != nil {
		appendField("shares", func(b []byte) []byte { return appendJSONString(b, CanonicalAmount(*e.Shares)) })
	}
	appendField("ts", func(b []byte) []byte { return appendJSONString(b, e.TS.UTC().Format(TSFormat)) })
	appendField("type", func(b []byte) []byte { return appendJSONString(b, e.Type) })
	buf = append(buf, '}')
	return buf, nil
}

// CanonicalAmount renders one money value exactly as the canonical form (and the export) carries
// it: plain decimal, exactly AmountScale fractional digits, no exponent, no floats anywhere on
// the way. Exposed so producers can normalize a value BEFORE storing it and be certain the
// stored and signed forms agree.
func CanonicalAmount(a money.Amount) string {
	return a.StringFixed(AmountScale)
}

// CanonicalPayload serializes a payload map standalone, byte-identical to how it appears inside
// CanonicalJSON — producers store this in the database so the stored payload and the signed
// payload can never disagree on serialization rules.
func CanonicalPayload(m map[string]string) []byte {
	return appendCanonicalStringMap(make([]byte, 0, 64), m)
}

// appendCanonicalStringMap serializes a flat string map as a JCS object: keys sorted by UTF-16
// code units, minimal escaping. nil and empty both render as {}.
func appendCanonicalStringMap(buf []byte, m map[string]string) []byte {
	buf = append(buf, '{')
	if len(m) > 0 {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return jcsLess(keys[i], keys[j]) })
		for i, k := range keys {
			if i > 0 {
				buf = append(buf, ',')
			}
			buf = appendJSONString(buf, k)
			buf = append(buf, ':')
			buf = appendJSONString(buf, m[k])
		}
	}
	return append(buf, '}')
}

// jcsLess compares two strings by their UTF-16 code unit sequences — RFC 8785 §3.2.3's member
// sort order. Identical to byte order for ASCII, but implemented properly so a non-ASCII payload
// key can never silently canonicalize differently here than in another compliant implementation.
func jcsLess(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// appendJSONInt writes a small non-negative integer in ES6 number form (plain digits) — the only
// numeric field in the canonical set is schema_version, so this deliberately supports nothing
// fancier (no floats exist anywhere in the preimage, by design).
func appendJSONInt(buf []byte, n int) []byte {
	return append(buf, []byte(fmt.Sprintf("%d", n))...)
}

// appendJSONString writes a JSON string with RFC 8785 §3.2.2.2 minimal escaping: only `"` and
// `\` are backslash-escaped, control characters use their short forms (\b \t \n \f \r) or
// \u00XX, and everything else — including non-ASCII — is emitted as literal UTF-8.
func appendJSONString(buf []byte, s string) []byte {
	buf = append(buf, '"')
	for _, r := range s {
		switch r {
		case '"':
			buf = append(buf, '\\', '"')
		case '\\':
			buf = append(buf, '\\', '\\')
		case '\b':
			buf = append(buf, '\\', 'b')
		case '\t':
			buf = append(buf, '\\', 't')
		case '\n':
			buf = append(buf, '\\', 'n')
		case '\f':
			buf = append(buf, '\\', 'f')
		case '\r':
			buf = append(buf, '\\', 'r')
		default:
			if r < 0x20 {
				buf = append(buf, []byte(fmt.Sprintf(`\u%04x`, r))...)
			} else {
				buf = append(buf, []byte(string(r))...)
			}
		}
	}
	return append(buf, '"')
}
