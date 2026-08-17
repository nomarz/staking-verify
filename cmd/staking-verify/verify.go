package main

// The verification core — deliberately a plain function over an io.Reader so the tests exercise
// exactly what main() runs.
//
// INDEPENDENCE RULE (the point of this binary): nothing in this package imports
// internal/ — only pkg/translog (the published canonicalization/chain/signature spec) and the
// public money package. The verifier recomputes everything from the export + the published key
// registry; it never trusts a stored total, a stored hash, or this codebase's production write
// path.
//
// WHAT IS VERIFIED, per pool (one hash chain exists per pool):
//
//  1. CHAIN — the first exported event's prev_hash is the 32-zero-byte genesis (a partial export
//     cannot prove balances, so a non-genesis start is an error), every subsequent prev_hash
//     equals the previous entry_hash, and every entry_hash recomputes EXACTLY from
//     SHA256(0x00 || prev_hash || canonical(entry)) over the re-canonicalized entry. Any edit to
//     any signed field anywhere in the log breaks this at the first affected seq.
//  2. SIGNATURES — every event's signature verifies against the registry key that was valid AT
//     THAT EVENT'S TIMESTAMP (rotation-safe both directions). Unsigned events fail unless
//     -allow-unsigned.
//  3. REPLAY — every account's share balance is rebuilt purely from the events (STAKE mints,
//     FEE_MINT/CAPITAL_MINT mint, UNSTAKE_BURN/CAPITAL_BURN burn); no balance may ever go
//     negative, Σ(account shares) must equal the running total at every event by construction
//     (cross-checked at every EPOCH event and at the end), and every EPOCH event's declared
//     shares_close must equal the replayed total at that point in the chain.

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/wasabi-gaming/staking-verify/internal/money"
	"github.com/wasabi-gaming/staking-verify/pkg/translog"
)

// Event types — restated here from the published log vocabulary rather than imported from the
// producer's internal constants (the whole point is that this binary compiles without them).
const (
	evStake          = "STAKE"
	evUnstakeRequest = "UNSTAKE_REQUEST"
	evUnstakeCancel  = "UNSTAKE_CANCEL"
	evUnstakeBurn    = "UNSTAKE_BURN"
	evUnstakeClaim   = "UNSTAKE_CLAIM"
	evEpoch          = "EPOCH"
	evFeeMint        = "FEE_MINT"
	evCapitalMint    = "CAPITAL_MINT"
	evCapitalBurn    = "CAPITAL_BURN"
	evRecapitalize   = "RECAPITALIZE"
	evWriteDown      = "WRITE_DOWN"
	// evAdjustment is DB-permitted (the CHECK constraint in migrations/083, widened in 094, allows
	// "ADJUSTMENT") but currently UNEMITTED — no producer anywhere in the repo appends this event
	// type today. It is a governance/audit event type reserved for future use. It is listed here,
	// and handled in replayEvent below, purely so that if a future producer ever does emit one,
	// this verifier does not hard-fail every downstream event on that pool's chain with "unknown
	// event type" — which would make the pool's entire public export permanently unverifiable.
	evAdjustment = "ADJUSTMENT"
	// evPolicyChange is the pool-level governance marker the producer appends whenever an operator
	// actually moves a pool's min/max stake bounds (migration 096; one event per REAL change, never
	// one per resubmitted form). It moves no shares and names no account — its whole content is the
	// payload's before/after limits plus the actor and reason — so replay treats it exactly like
	// RECAPITALIZE/ADJUSTMENT: valid input, no ledger effect, refused if it carries shares.
	evPolicyChange = "POLICY_CHANGE"
)

// stakingShareScale mirrors the producer's constant of the same name (the
// decimal scale of every shares column, numeric(48,18)) — restated here, not imported, per this
// file's INDEPENDENCE RULE above: the verifier must never compile against the producer's internal code.
const stakingShareScale = 18

// floorRatioShares mirrors the producer's epoch-settlement helper of the EXACT same name:
// floor(numerator/denominator) at stakingShareScale via a single QuoRem — numerator is expected to
// already be an exact product (fee.Mul(sharesOpen) below), so there is no intermediate rounded
// value for a later truncation to compound error against. Reimplemented rather than imported for
// the same INDEPENDENCE RULE reason as stakingShareScale above; every operand this file calls it
// with is non-negative (fee, shares, assets are never negative in a legitimate epoch), so
// QuoRem's toward-zero truncation and a true floor coincide.
func floorRatioShares(numerator, denominator money.Amount) money.Amount {
	q, _ := numerator.QuoRem(denominator, stakingShareScale)
	return q
}

// epochPayloadAmount parses one EPOCH event's payload field as a money.Amount, wrapped in the same
// *VerifyError shape every other replay failure in this file uses — used by the SchemaVersion2
// price/asset-chaining/invariant/fee-share-algebra checks in replayEvent's evEpoch case, each of
// which needs several such fields. A nil return means the field parsed cleanly.
func epochPayloadAmount(rec *translog.ExportRecord, poolID, key string) (money.Amount, *VerifyError) {
	raw, ok := rec.Entry.Payload[key]
	if !ok {
		return money.Zero, &VerifyError{Seq: rec.Seq, Pool: poolID, Check: "replay",
			Msg: fmt.Sprintf("EPOCH (schema_version %d) without a %s payload field", rec.Entry.SchemaVersion, key)}
	}
	v, err := money.Parse(raw)
	if err != nil {
		return money.Zero, &VerifyError{Seq: rec.Seq, Pool: poolID, Check: "replay",
			Msg: fmt.Sprintf("EPOCH unparseable %s %q: %v", key, raw, err)}
	}
	return v, nil
}

// VerifyError pinpoints the FIRST failure: which seq, which check, what went wrong.
type VerifyError struct {
	Seq int64
	// Line is the 1-based NDJSON line number, set ONLY for the two parse-failure paths in
	// VerifyStream (a truncated/corrupted export can't be attributed to a chain seq — there's no
	// parsed entry yet to carry one). Zero everywhere else, in which case Seq is the real chain
	// seq and Error() reports "at seq %d" as before.
	Line  int64
	Pool  string
	Check string // "parse" | "chain" | "signature" | "replay"
	Msg   string
}

func (e *VerifyError) Error() string {
	if e.Line != 0 {
		return fmt.Sprintf("VERIFICATION FAILED at line %d (pool %s) [%s]: %s", e.Line, e.Pool, e.Check, e.Msg)
	}
	return fmt.Sprintf("VERIFICATION FAILED at seq %d (pool %s) [%s]: %s", e.Seq, e.Pool, e.Check, e.Msg)
}

// PoolState is one pool's replayed state.
type PoolState struct {
	Head     []byte
	Events   int
	LastSeq  int64
	Total    money.Amount
	Accounts map[string]money.Amount
	// Operator is the operator_id the pool's events declare (first seen; every entry of a pool
	// carries the same one or the export is wrong at a level chain verification already catches).
	Operator string
	// Leaves is the pool's entry-hash sequence in chain order — the STAKING-P3 Merkle leaf
	// inputs. Populated only under Options.CollectLeaves (STH verification needs them; the
	// chain-only path skips the memory).
	Leaves [][]byte

	// --- STAKING transparency hardening (schema_version >= translog.SchemaVersion2's cap_net
	// field): fields below back the EPOCH price/asset-chaining/invariant/fee-share checks in
	// replayEvent. They are maintained for EVERY pool regardless of schema version (assets_close
	// has been in the payload since v1), so a pool that transitions from v1 to v2 epochs mid-chain
	// still has a valid comparison point the moment its first v2 EPOCH arrives — only the
	// COMPARISONS themselves are version-gated, never the bookkeeping.

	// PrevEpochAssetsClose / HasPrevEpoch remember the most recent EPOCH event's declared
	// assets_close, for the cross-epoch asset-chaining check: epoch N's assets_close must equal
	// epoch N+1's assets_open. HasPrevEpoch distinguishes "no prior epoch yet" (skip the check,
	// same convention as st.Events==0 for the chain's own genesis check) from a legitimate zero
	// balance.
	PrevEpochAssetsClose money.Amount
	HasPrevEpoch         bool
	// EpochAssetDelta accumulates the net asset movement — subscription mints (STAKE, mint phase)
	// minus unstake burns (UNSTAKE_BURN) — since the last EPOCH event on this pool. RunEpoch
	// applies subscriptions/redemptions AFTER freezing A for the epoch's ggr/cap_net invariant, so
	// assets_close = assets_open + ggr + cap_net ONLY on an epoch with no net subscription/
	// redemption activity; in general it equals assets_open + ggr + cap_net + EpochAssetDelta.
	// This is exactly why RunEpoch's own kind filters exclude stake_in/stake_out from both ggr and
	// cap_net: their contribution is already reflected in assets_close directly, never double-
	// counted through next epoch's ledger-sum window. Reset to zero after every EPOCH event.
	EpochAssetDelta money.Amount
}

// Summary is the successful-verification report.
type Summary struct {
	Events   int
	Unsigned int
	Pools    map[string]*PoolState
	// RegistrySigningKnown/RegistrySigningEnabled/RegistryActiveKeyID mirror the -registry
	// file's additive signingEnabled/activeKeyId fields (review item 10 — see Options' doc
	// comment). Known=false means "the registry gave no opinion" (an older document, or none
	// supplied), not "unsigned" — WriteSummary falls back to the old generic wording then.
	RegistrySigningKnown   bool
	RegistrySigningEnabled bool
	RegistryActiveKeyID    string
}

// Options configures a verification run.
type Options struct {
	Registry      *translog.KeyRegistry
	AllowUnsigned bool
	// CollectLeaves retains every entry hash per pool (32 bytes/event) for STAKING-P3 STH
	// verification. Off for the chain-only path, so a huge export costs no extra memory there.
	CollectLeaves bool

	// RegistrySigningKnown/RegistrySigningEnabled/RegistryActiveKeyID carry the published
	// registry's ADDITIVE signingEnabled/activeKeyId fields (GET …/transparency/key, review item
	// 10: the producer surfaces "is this deployment currently configured to sign new events" as a
	// distinct signal from a null signature on one event). translog.KeyRegistry itself only
	// models {"keys":[...]}, so main.go parses these two fields off the same raw registry file
	// separately and threads them in here — RegistrySigningKnown is false when the file predates
	// this field or -registry was not given, in which case verifyRecord falls back to its
	// pre-existing behavior exactly.
	//
	// What this changes: an unsigned entry timestamped AT OR AFTER the active key's ValidFrom is
	// NEVER accepted, -allow-unsigned or not — the registry says this operator's active key was
	// already valid then, so that entry SHOULD have been signed; a null signature there is not
	// this operator's normal unsigned-mode history; it is unexpected and always a hard failure.
	// An unsigned entry BEFORE that (or when signing was never enabled) is unchanged: still gated
	// behind -allow-unsigned, just with a clearer message about which case applies.
	RegistrySigningKnown   bool
	RegistrySigningEnabled bool
	RegistryActiveKeyID    string
}

// VerifyStream verifies one NDJSON export end to end. Returns the summary on success, or the
// first *VerifyError encountered.
func VerifyStream(r io.Reader, opts Options) (*Summary, error) {
	sum := &Summary{
		Pools:                  map[string]*PoolState{},
		RegistrySigningKnown:   opts.RegistrySigningKnown,
		RegistrySigningEnabled: opts.RegistrySigningEnabled,
		RegistryActiveKeyID:    opts.RegistryActiveKeyID,
	}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		rec, err := translog.ParseExportLine(line)
		if err != nil {
			return nil, &VerifyError{Line: int64(lineNo), Pool: "?", Check: "parse", Msg: err.Error()}
		}
		if err := verifyRecord(sum, rec, opts); err != nil {
			return nil, err
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, &VerifyError{Line: int64(lineNo), Pool: "?", Check: "parse", Msg: "read: " + err.Error()}
	}
	// Final cross-check: Σ(account shares) == replayed total, per pool. Pool IDs are sorted first
	// so that with two simultaneously-failing pools the reported failure is deterministic across
	// runs, not whichever the map's random iteration order happens to visit first.
	poolIDs := make([]string, 0, len(sum.Pools))
	for poolID := range sum.Pools {
		poolIDs = append(poolIDs, poolID)
	}
	sort.Strings(poolIDs)
	for _, poolID := range poolIDs {
		st := sum.Pools[poolID]
		if err := checkAccountSum(poolID, st, st.LastSeq); err != nil {
			return nil, err
		}
	}
	return sum, nil
}

func verifyRecord(sum *Summary, rec *translog.ExportRecord, opts Options) error {
	e := rec.Entry
	poolID := e.PoolID
	st := sum.Pools[poolID]
	if st == nil {
		st = &PoolState{Total: money.Zero, Accounts: map[string]money.Amount{}, EpochAssetDelta: money.Zero}
		sum.Pools[poolID] = st
	}

	// ── 0. Schema version ──
	// schema_version is itself a SIGNED field (part of the canonical preimage) but was never
	// independently inspected before this check — CanonicalJSON()/Validate() below happen to
	// reject an unrecognized version too, but only as a side effect, buried in a generic
	// "re-canonicalize" chain error. Checking it explicitly here gives a clear, dedicated message
	// and follows the same "an unknown thing means a newer producer needs a newer verifier, never
	// a silent skip" principle replayEvent's default: case uses for unknown event types.
	if e.SchemaVersion != translog.SchemaVersion1 && e.SchemaVersion != translog.SchemaVersion2 {
		return &VerifyError{Seq: rec.Seq, Pool: poolID, Check: "chain",
			Msg: fmt.Sprintf("unrecognized schema_version %d (this verifier only knows schema_version %d and %d) — a newer producer needs a newer verifier", e.SchemaVersion, translog.SchemaVersion1, translog.SchemaVersion2)}
	}

	// ── 0b. Operator ──
	// Every entry in one pool's chain must declare the SAME operator_id. st.Operator is otherwise
	// only ever set (never compared) on the first entry seen — without this check, a corrupted or
	// maliciously-spliced export mixing two operators' entries into one pool_id would replay
	// (and even chain/signature-verify, since operator_id is per-entry) without ever being
	// flagged as cross-tenant contamination.
	if st.Operator != "" && e.OperatorID != st.Operator {
		return &VerifyError{Seq: rec.Seq, Pool: poolID, Check: "chain",
			Msg: fmt.Sprintf("cross-operator contamination: pool's chain started with operator_id %s but this entry declares %s", st.Operator, e.OperatorID)}
	}

	// ── 1. Chain ──
	if st.Events == 0 {
		if !translog.IsGenesis(rec.PrevHash) {
			return &VerifyError{Seq: rec.Seq, Pool: poolID, Check: "chain",
				Msg: "first exported event's prev_hash is not the 32-zero-byte genesis — balances cannot be replayed from a partial export; export the pool from its first event"}
		}
	} else {
		if rec.Seq <= st.LastSeq {
			return &VerifyError{Seq: rec.Seq, Pool: poolID, Check: "chain",
				Msg: fmt.Sprintf("seq not strictly increasing (previous %d)", st.LastSeq)}
		}
		if !bytes.Equal(rec.PrevHash, st.Head) {
			return &VerifyError{Seq: rec.Seq, Pool: poolID, Check: "chain",
				Msg: fmt.Sprintf("prev_hash %x does not equal the previous entry_hash %x — the chain is broken here", rec.PrevHash, st.Head)}
		}
	}
	canonical, err := e.CanonicalJSON()
	if err != nil {
		return &VerifyError{Seq: rec.Seq, Pool: poolID, Check: "chain", Msg: "re-canonicalize: " + err.Error()}
	}
	recomputed, err := translog.NextHash(rec.PrevHash, canonical)
	if err != nil {
		return &VerifyError{Seq: rec.Seq, Pool: poolID, Check: "chain", Msg: err.Error()}
	}
	if !bytes.Equal(recomputed, rec.EntryHash) {
		return &VerifyError{Seq: rec.Seq, Pool: poolID, Check: "chain",
			Msg: fmt.Sprintf("entry_hash mismatch: stored %x, recomputed %x — this entry (or one of its fields) was altered after signing", rec.EntryHash, recomputed)}
	}

	// ── 2. Signature ──
	if len(rec.Signature) == 0 {
		// Review item 10: an unsigned entry timestamped at-or-after the registry's active
		// signing key's ValidFrom is NEVER benign — the operator's active key was already valid
		// then, so this entry should have carried a signature. This overrides -allow-unsigned
		// entirely: that flag exists for "the producer is known to run unsigned" (its own doc
		// string), and a currently-signing operator with a hole in its otherwise-signed export
		// does not meet that description.
		if opts.RegistrySigningKnown && opts.RegistrySigningEnabled && opts.Registry != nil && opts.RegistryActiveKeyID != "" {
			if rk, ok := opts.Registry.Lookup(opts.RegistryActiveKeyID); ok && !e.TS.Before(rk.ValidFrom) {
				return &VerifyError{Seq: rec.Seq, Pool: poolID, Check: "signature",
					Msg: fmt.Sprintf("entry is unsigned, but the published registry's active signing key %s was already valid at this entry's timestamp (%s) — this is NOT this operator's normal unsigned-mode history, it is unexpected and cannot be waved through with -allow-unsigned; investigate before trusting this export", opts.RegistryActiveKeyID, e.TS.UTC().Format(time.RFC3339))}
			}
		}
		if !opts.AllowUnsigned {
			msg := "entry is unsigned (no signature/keyId); rerun with -allow-unsigned only if the producer is known to run unsigned"
			switch {
			case opts.RegistrySigningKnown && !opts.RegistrySigningEnabled:
				msg = "entry is unsigned (no signature/keyId) — the published key registry confirms this operator has never configured a signing key, so its entire export is expected to be unsigned; rerun with -allow-unsigned to accept that"
			case opts.RegistrySigningKnown && opts.RegistrySigningEnabled:
				msg = "entry is unsigned (no signature/keyId), predating the operator's active signing key — legitimate history from before signing was enabled; rerun with -allow-unsigned to accept it"
			}
			return &VerifyError{Seq: rec.Seq, Pool: poolID, Check: "signature", Msg: msg}
		}
		sum.Unsigned++
	} else {
		if opts.Registry == nil {
			return &VerifyError{Seq: rec.Seq, Pool: poolID, Check: "signature", Msg: "signed entry but no key registry provided (-registry)"}
		}
		pub, rerr := opts.Registry.Resolve(rec.KeyID, e.TS)
		if rerr != nil {
			return &VerifyError{Seq: rec.Seq, Pool: poolID, Check: "signature", Msg: rerr.Error()}
		}
		if !translog.VerifyEntryHash(pub, rec.EntryHash, rec.Signature) {
			return &VerifyError{Seq: rec.Seq, Pool: poolID, Check: "signature",
				Msg: fmt.Sprintf("Ed25519 signature does not verify under key %s", rec.KeyID)}
		}
	}

	// ── 3. Replay ──
	if err := replayEvent(st, rec, poolID); err != nil {
		return err
	}

	st.Head = rec.EntryHash
	st.LastSeq = rec.Seq
	st.Events++
	sum.Events++
	if st.Operator == "" {
		st.Operator = e.OperatorID
	}
	if opts.CollectLeaves {
		st.Leaves = append(st.Leaves, rec.EntryHash)
	}
	return nil
}

func replayEvent(st *PoolState, rec *translog.ExportRecord, poolID string) error {
	e := rec.Entry
	if e.Amount != nil && e.Amount.IsNegative() {
		return &VerifyError{Seq: rec.Seq, Pool: poolID, Check: "replay", Msg: "negative amount"}
	}
	if e.Shares != nil && e.Shares.IsNegative() {
		return &VerifyError{Seq: rec.Seq, Pool: poolID, Check: "replay", Msg: "negative shares"}
	}

	mint := func() error {
		if e.Shares == nil {
			return &VerifyError{Seq: rec.Seq, Pool: poolID, Check: "replay", Msg: e.Type + " without a shares field"}
		}
		if e.Account == "" {
			return &VerifyError{Seq: rec.Seq, Pool: poolID, Check: "replay", Msg: e.Type + " mints shares but names no account"}
		}
		st.Accounts[e.Account] = accountShares(st, e.Account).Add(*e.Shares)
		st.Total = st.Total.Add(*e.Shares)
		return nil
	}
	burn := func() error {
		if e.Shares == nil {
			return &VerifyError{Seq: rec.Seq, Pool: poolID, Check: "replay", Msg: e.Type + " without a shares field"}
		}
		if e.Account == "" {
			return &VerifyError{Seq: rec.Seq, Pool: poolID, Check: "replay", Msg: e.Type + " burns shares but names no account"}
		}
		next := accountShares(st, e.Account).Sub(*e.Shares)
		if next.IsNegative() {
			return &VerifyError{Seq: rec.Seq, Pool: poolID, Check: "replay",
				Msg: fmt.Sprintf("account %s would go negative: holds %s, %s burns %s", e.Account, accountShares(st, e.Account).String(), e.Type, e.Shares.String())}
		}
		st.Accounts[e.Account] = next
		st.Total = st.Total.Sub(*e.Shares)
		if st.Total.IsNegative() {
			return &VerifyError{Seq: rec.Seq, Pool: poolID, Check: "replay", Msg: "pool total shares went negative"}
		}
		return nil
	}

	switch e.Type {
	case evStake:
		// Two phases share the type: escrow (no shares yet — wallet money held outside the
		// pool) and mint (the epoch minted shares at its frozen price).
		if e.Shares != nil {
			if err := mint(); err != nil {
				return err
			}
			// STAKING transparency hardening: the mint phase's Amount is the exact subscription
			// escrow RunEpoch moved into the leg via a stake_in ledger row THIS epoch — accumulate
			// it for the EPOCH invariant check below (st.EpochAssetDelta), since stake_in is
			// deliberately excluded from both ggr and cap_net's ledger-kind filters.
			if e.Amount != nil {
				st.EpochAssetDelta = st.EpochAssetDelta.Add(*e.Amount)
			}
			return nil
		}
		return nil
	case evFeeMint, evCapitalMint:
		return mint()
	case evUnstakeBurn:
		if err := burn(); err != nil {
			return err
		}
		// STAKING transparency hardening: symmetric to the mint-phase STAKE case above — the
		// payout RunEpoch moved OUT of the leg via a stake_out ledger row this epoch.
		if e.Amount != nil {
			st.EpochAssetDelta = st.EpochAssetDelta.Sub(*e.Amount)
		}
		return nil
	case evCapitalBurn, evWriteDown:
		// WRITE_DOWN is a burn like any other as far as the share ledger is concerned: the named
		// account loses exactly Shares, and the pool total falls by the same. Its Amount is 0 (what
		// the holder recovered) rather than the payout the other two burns carry, but replay only
		// ever reads Shares, so that distinction needs no special handling here. Neither kind feeds
		// EpochAssetDelta: their asset movement (if any) is capital-hook territory, already
		// reflected via cap_net, not the stake_in/stake_out pair the EPOCH invariant reconciles.
		return burn()
	case evUnstakeRequest, evUnstakeCancel, evUnstakeClaim, evRecapitalize:
		// State transitions / wallet payout: no share movement by definition. RECAPITALIZE is a
		// POOL-level state transition (halted -> active) with the same property — the producer
		// appends it with no account and no shares; whatever share movement a recapitalization
		// performs is carried by its OWN separate WRITE_DOWN/CAPITAL_MINT events, each replayed
		// on its own terms below/above.
		if e.Shares != nil {
			return &VerifyError{Seq: rec.Seq, Pool: poolID, Check: "replay", Msg: e.Type + " must not carry a shares field"}
		}
		return nil
	case evEpoch:
		if e.Shares != nil {
			return &VerifyError{Seq: rec.Seq, Pool: poolID, Check: "replay", Msg: "EPOCH must not carry a shares field"}
		}
		// The epoch declares its closing share total; it must equal the replayed one. The producer
		// ALWAYS writes shares_close as part of its EPOCH event
		// append, so a missing key is refused rather than silently skipped — this is the
		// strongest cross-check in the file and must not be optional.
		declared, ok := e.Payload["shares_close"]
		if !ok {
			return &VerifyError{Seq: rec.Seq, Pool: poolID, Check: "replay", Msg: "EPOCH without a shares_close payload field"}
		}
		want, err := money.Parse(declared)
		if err != nil {
			return &VerifyError{Seq: rec.Seq, Pool: poolID, Check: "replay", Msg: "unparseable shares_close: " + err.Error()}
		}
		if !want.Equal(st.Total) {
			return &VerifyError{Seq: rec.Seq, Pool: poolID, Check: "replay",
				Msg: fmt.Sprintf("EPOCH declares shares_close=%s but replaying the log yields %s", want.String(), st.Total.String())}
		}
		if err := checkAccountSum(poolID, st, rec.Seq); err != nil {
			return err
		}

		// Cross-epoch asset-chain bookkeeping: track THIS epoch's declared assets_close
		// unconditionally (assets_close has been in the payload since schema_version 1), so a pool
		// that transitions from v1 to v2 epochs mid-chain already has a valid comparison point the
		// moment its first v2 EPOCH arrives — see PoolState's doc comment. Parsed defensively: a
		// malformed/missing assets_close on a v1 event (never checked before this change) must not
		// crash replay; it simply leaves nothing to chain the NEXT epoch against, same as "no prior
		// epoch yet".
		var thisAssetsClose money.Amount
		haveThisAssetsClose := false
		if raw, ok := e.Payload["assets_close"]; ok {
			if v, perr := money.Parse(raw); perr == nil {
				thisAssetsClose, haveThisAssetsClose = v, true
			}
		}

		// STAKING transparency hardening (schema_version >= translog.SchemaVersion2): the producer
		// gained a "cap_net" payload field — see the producer's epoch-settlement routine (RunEpoch),
		// where cap_net is the EXACT variable its own A == assets_open + ggr + cap_net invariant
		// asserts before committing. Enough to check the PRICE, the cross-epoch ASSET chain, the
		// epoch's own asset invariant, and the fee-share mint algebra — not just the share ledger.
		// v1 EPOCH events (no cap_net) skip all four checks below exactly as they always have:
		// nothing already exported is held to a stronger bar than it was signed under.
		if e.SchemaVersion >= translog.SchemaVersion2 {
			assetsOpen, verr := epochPayloadAmount(rec, poolID, "assets_open")
			if verr != nil {
				return verr
			}
			ggr, verr := epochPayloadAmount(rec, poolID, "ggr")
			if verr != nil {
				return verr
			}
			capNet, verr := epochPayloadAmount(rec, poolID, "cap_net")
			if verr != nil {
				return verr
			}
			fee, verr := epochPayloadAmount(rec, poolID, "fee")
			if verr != nil {
				return verr
			}
			feeShares, verr := epochPayloadAmount(rec, poolID, "fee_shares")
			if verr != nil {
				return verr
			}
			price, verr := epochPayloadAmount(rec, poolID, "price")
			if verr != nil {
				return verr
			}
			sharesOpen, verr := epochPayloadAmount(rec, poolID, "shares_open")
			if verr != nil {
				return verr
			}
			if !haveThisAssetsClose {
				return &VerifyError{Seq: rec.Seq, Pool: poolID, Check: "replay",
					Msg: fmt.Sprintf("EPOCH (schema_version %d) without a parseable assets_close payload field", e.SchemaVersion)}
			}

			assetsMid := assetsOpen.Add(ggr).Add(capNet)
			sharesAfterFee := sharesOpen.Add(feeShares)

			// 1. Price consistency: price must equal the frozen assets_mid/(shares_open+fee_shares)
			// ratio RunEpoch actually divides (A.DivRound(sharesAfterFee, 36)) — deliberately NOT a
			// naive assets_close/shares_close: subscriptions/redemptions are applied AFTER the
			// price is frozen, each at a floor-truncated rate, which drifts the CLOSING ratio away
			// from the frozen price by the sum of those truncation remainders whenever there was
			// any subscription/redemption activity this epoch.
			if sharesAfterFee.IsPositive() {
				wantPrice := assetsMid.DivRound(sharesAfterFee, 36)
				if !wantPrice.Equal(price) {
					return &VerifyError{Seq: rec.Seq, Pool: poolID, Check: "replay",
						Msg: fmt.Sprintf("EPOCH declares price=%s but (assets_open=%s + ggr=%s + cap_net=%s) / (shares_open=%s + fee_shares=%s) recomputes to %s",
							price.String(), assetsOpen.String(), ggr.String(), capNet.String(), sharesOpen.String(), feeShares.String(), wantPrice.String())}
				}
			}

			// 2. Asset chaining across epochs: epoch N's assets_close must equal epoch N+1's
			// assets_open — skipped on the pool's first EPOCH event (nothing to chain against yet).
			if st.HasPrevEpoch && !assetsOpen.Equal(st.PrevEpochAssetsClose) {
				return &VerifyError{Seq: rec.Seq, Pool: poolID, Check: "replay",
					Msg: fmt.Sprintf("EPOCH declares assets_open=%s but this pool's previous EPOCH closed at assets_close=%s — the asset chain is broken here",
						assetsOpen.String(), st.PrevEpochAssetsClose.String())}
			}

			// 3. Invariant: assets_close == assets_open + ggr + cap_net + this epoch's OWN net
			// stake movement (st.EpochAssetDelta, accumulated purely from the STAKE(mint-phase)/
			// UNSTAKE_BURN events already replayed between the previous EPOCH and this one — see
			// PoolState's doc comment for why assets_close cannot be checked against
			// assets_open+ggr+cap_net alone whenever an epoch minted subscriptions or burned
			// redemptions). This is the same invariant RunEpoch itself asserts (aborting the whole
			// epoch transaction on mismatch) before it ever applies a subscription or redemption,
			// extended here with the piece the signed payload alone cannot reconstruct.
			wantClose := assetsMid.Add(st.EpochAssetDelta)
			if !wantClose.Equal(thisAssetsClose) {
				return &VerifyError{Seq: rec.Seq, Pool: poolID, Check: "replay",
					Msg: fmt.Sprintf("EPOCH invariant broken: assets_open=%s + ggr=%s + cap_net=%s + net_stake_movement=%s = %s, but declares assets_close=%s",
						assetsOpen.String(), ggr.String(), capNet.String(), st.EpochAssetDelta.String(), wantClose.String(), thisAssetsClose.String())}
			}

			// 4. Fee-share algebra: recompute the EXACT mint formula RunEpoch uses —
			// floorRatioShares(fee*shares_open, assets_mid-fee), the SAME truncating QuoRem at
			// stakingShareScale=18 the producer calls — and require the declared fee_shares to
			// match byte-for-byte. Checking fee_shares.Mul(price)==fee directly would spuriously
			// fail on almost every real winning epoch: feeShares is FLOORED and price is itself
			// DivRound-ed, so their product only equals fee exactly when fee/shares_open/assets_mid
			// happen to divide evenly, which is not the common case. On a losing/flat day (fee <=
			// 0) the producer never mints (feeShares stays money.Zero, and the key is still always
			// written — never omitted), which wantFeeShares's zero-value default matches exactly.
			denom := assetsMid.Sub(fee)
			wantFeeShares := money.Zero
			if fee.IsPositive() && sharesOpen.IsPositive() && denom.IsPositive() {
				wantFeeShares = floorRatioShares(fee.Mul(sharesOpen), denom)
			}
			if !wantFeeShares.Equal(feeShares) {
				return &VerifyError{Seq: rec.Seq, Pool: poolID, Check: "replay",
					Msg: fmt.Sprintf("EPOCH declares fee_shares=%s but fee=%s over shares_open=%s and (assets_open+ggr+cap_net-fee)=%s recomputes to %s",
						feeShares.String(), fee.String(), sharesOpen.String(), denom.String(), wantFeeShares.String())}
			}
		}

		if haveThisAssetsClose {
			st.PrevEpochAssetsClose = thisAssetsClose
			st.HasPrevEpoch = true
		}
		st.EpochAssetDelta = money.Zero
		return nil
	case evAdjustment, evPolicyChange:
		// ADJUSTMENT is DB-permitted but currently unemitted (see the evAdjustment constant's
		// comment above) — a governance/audit event with no share movement, mirrored on
		// evUnstakeRequest/evUnstakeCancel/evUnstakeClaim/evRecapitalize's handling just above:
		// state transitions carry no shares by definition, so refuse if it does. POLICY_CHANGE IS
		// emitted (SetPoolLimits, migration 096) and has the identical property: it records that
		// the operator moved the pool's min/max stake bounds, which changes what FUTURE stakes are
		// admissible but moves not one share of what is already staked. Its payload is audit
		// content, not ledger content, so replay reads none of it.
		if e.Shares != nil {
			return &VerifyError{Seq: rec.Seq, Pool: poolID, Check: "replay", Msg: e.Type + " must not carry a shares field"}
		}
		return nil
	default:
		// An unknown type is semantics this verifier cannot replay — refusing is the only honest
		// answer (a newer producer needs a newer verifier, never a silent skip).
		return &VerifyError{Seq: rec.Seq, Pool: poolID, Check: "replay", Msg: "unknown event type " + e.Type}
	}
}

func accountShares(st *PoolState, account string) money.Amount {
	if v, ok := st.Accounts[account]; ok {
		return v
	}
	return money.Zero
}

// checkAccountSum asserts Σ(account shares) == the replayed pool total.
func checkAccountSum(poolID string, st *PoolState, seq int64) error {
	sum := money.Zero
	for _, v := range st.Accounts {
		sum = sum.Add(v)
	}
	if !sum.Equal(st.Total) {
		return &VerifyError{Seq: seq, Pool: poolID, Check: "replay",
			Msg: fmt.Sprintf("Σ account shares (%s) != pool total (%s)", sum.String(), st.Total.String())}
	}
	return nil
}

// WriteSummary renders the success report.
func WriteSummary(w io.Writer, sum *Summary, verifiedAt time.Time) {
	fmt.Fprintf(w, "OK: %d event(s) verified across %d pool(s) at %s\n", sum.Events, len(sum.Pools), verifiedAt.UTC().Format(time.RFC3339))
	if sum.Unsigned > 0 {
		// By the time this prints, verifyRecord has already hard-failed any unsigned entry that
		// the registry says should have been signed (review item 10) — every count reaching here
		// is one of the two BENIGN cases, so report which one instead of a generic warning.
		switch {
		case sum.RegistrySigningKnown && !sum.RegistrySigningEnabled:
			fmt.Fprintf(w, "NOTE: %d event(s) were unsigned — expected: the published registry confirms this operator has never configured a signing key\n", sum.Unsigned)
		case sum.RegistrySigningKnown && sum.RegistrySigningEnabled:
			fmt.Fprintf(w, "NOTE: %d event(s) were unsigned, all predating the operator's active signing key %s — legitimate pre-signing history\n", sum.Unsigned, sum.RegistryActiveKeyID)
		default:
			fmt.Fprintf(w, "WARNING: %d event(s) were UNSIGNED (allowed by -allow-unsigned)\n", sum.Unsigned)
		}
	}
	poolIDs := make([]string, 0, len(sum.Pools))
	for id := range sum.Pools {
		poolIDs = append(poolIDs, id)
	}
	sort.Strings(poolIDs)
	for _, id := range poolIDs {
		st := sum.Pools[id]
		fmt.Fprintf(w, "pool %s: %d event(s), final chain head %x, total shares %s\n", id, st.Events, st.Head, st.Total.String())
		accounts := make([]string, 0, len(st.Accounts))
		for a := range st.Accounts {
			accounts = append(accounts, a)
		}
		sort.Strings(accounts)
		for _, a := range accounts {
			fmt.Fprintf(w, "  account %s: %s shares\n", a, st.Accounts[a].String())
		}
	}
}
