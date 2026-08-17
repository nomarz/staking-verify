package main

// Verifier tests over a SYNTHETIC log produced with nothing but pkg/translog — the same position
// an outside auditor building their own tooling would be in. The fixture walks a realistic pool
// lifecycle (genesis capitalization, stake escrow+mint, fee mint, epoch close, unstake
// request/burn, claim, capital burn) and the tests assert:
//
//   - a clean log verifies end to end (chain + signatures + replay + Σshares == total),
//   - corrupting ONE stored field is detected at exactly that seq with a chain-check failure,
//   - truncating the head of the export (non-genesis start) is refused,
//   - an unsigned log is refused unless -allow-unsigned,
//   - an EPOCH declaring a wrong shares_close is caught by the replay.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/wasabi-gaming/staking-verify/internal/money"
	"github.com/wasabi-gaming/staking-verify/pkg/translog"
)

const (
	fxOperator = "0b6f9f74-3a5e-4f2b-9a58-6f7d2f6a1c11"
	fxPool     = "9f6e7f3a-1b2c-4d5e-8f90-a1b2c3d4e5f6"
	fxPlatform = "aaaa1111-0000-0000-0000-000000000001"
	fxStaker   = "bbbb2222-0000-0000-0000-000000000002"
)

type fixtureBuilder struct {
	t      *testing.T
	signer *translog.Signer
	head   []byte
	seq    int64
	ts     time.Time
	lines  [][]byte
	// hashes is the entry-hash sequence in chain order — the STAKING-P3 Merkle leaf inputs the
	// sth_test.go fixtures build published heads from.
	hashes [][]byte
}

func newFixture(t *testing.T, signer *translog.Signer) *fixtureBuilder {
	return &fixtureBuilder{
		t: t, signer: signer, head: translog.Genesis(),
		ts: time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC),
	}
}

func (f *fixtureBuilder) amt(s string) *money.Amount {
	f.t.Helper()
	a, err := money.Parse(s)
	if err != nil {
		f.t.Fatalf("parse %q: %v", s, err)
	}
	return &a
}

func (f *fixtureBuilder) append(evType, account string, amount, shares *money.Amount, idem string, payload map[string]string) {
	f.t.Helper()
	f.seq++
	f.ts = f.ts.Add(time.Minute)
	entry := translog.Entry{
		SchemaVersion: translog.SchemaVersion1, OperatorID: fxOperator, PoolID: fxPool,
		Account: account, Type: evType, Amount: amount, Shares: shares,
		TS: f.ts, IdempotencyKey: idem, Payload: payload,
	}
	f.appendEntry(entry)
}

// appendWithOperator is append's twin for the ONE field append() always fixes to fxOperator: it
// lets a test stamp a caller-chosen operator_id on one entry while everything else about it
// (pool_id, chaining, signing) is identical to append()'s. Used only by the
// cross-operator-contamination regression test (V5) — a chain-valid, signature-valid entry that
// simply declares a DIFFERENT tenant than the pool's earlier entries, which is exactly the
// scenario st.Operator's mismatch check exists to catch.
func (f *fixtureBuilder) appendWithOperator(operatorID, evType, account string, amount, shares *money.Amount, idem string, payload map[string]string) {
	f.t.Helper()
	f.seq++
	f.ts = f.ts.Add(time.Minute)
	entry := translog.Entry{
		SchemaVersion: translog.SchemaVersion1, OperatorID: operatorID, PoolID: fxPool,
		Account: account, Type: evType, Amount: amount, Shares: shares,
		TS: f.ts, IdempotencyKey: idem, Payload: payload,
	}
	f.appendEntry(entry)
}

// appendV2 is append's SchemaVersion2 twin — used by the STAKING transparency hardening tests
// (price/asset-chaining/invariant/fee-share-algebra), which need the EPOCH event's cap_net-bearing
// v2 payload. Every other field behaves exactly like append().
func (f *fixtureBuilder) appendV2(evType, account string, amount, shares *money.Amount, idem string, payload map[string]string) {
	f.t.Helper()
	f.seq++
	f.ts = f.ts.Add(time.Minute)
	entry := translog.Entry{
		SchemaVersion: translog.SchemaVersion2, OperatorID: fxOperator, PoolID: fxPool,
		Account: account, Type: evType, Amount: amount, Shares: shares,
		TS: f.ts, IdempotencyKey: idem, Payload: payload,
	}
	f.appendEntry(entry)
}

// appendEntry chains, (optionally) signs, and appends an already-built entry — the shared core
// append() and appendWithOperator() both delegate to.
func (f *fixtureBuilder) appendEntry(entry translog.Entry) {
	f.t.Helper()
	entryHash, _, err := translog.ChainEntry(f.head, entry)
	if err != nil {
		f.t.Fatalf("chain %s: %v", entry.IdempotencyKey, err)
	}
	rec := translog.ExportRecord{Seq: f.seq, Entry: entry, PrevHash: f.head, EntryHash: entryHash}
	if f.signer != nil {
		rec.Signature = f.signer.Sign(entryHash)
		rec.KeyID = f.signer.KeyID()
	}
	line, err := rec.MarshalLine()
	if err != nil {
		f.t.Fatalf("marshal %s: %v", entry.IdempotencyKey, err)
	}
	f.lines = append(f.lines, line)
	f.hashes = append(f.hashes, entryHash)
	f.head = entryHash
}

func (f *fixtureBuilder) ndjson() []byte {
	return append(bytes.Join(f.lines, []byte("\n")), '\n')
}

// buildLifecycle produces the full fixture: pool capitalized at 1000 (+ genesis-lock dust),
// staker stakes 60 (escrow then mint), a winning day mints 5 fee shares to the platform, the
// staker exits, and the platform withdraws 100.
func buildLifecycle(t *testing.T, signer *translog.Signer) *fixtureBuilder {
	f := newFixture(t, signer)
	f.append(evCapitalMint, fxPlatform, f.amt("1000"), f.amt("1000.000001"), "genesis:"+fxPool,
		map[string]string{"genesis": "true", "platform_shares": "1000", "genesis_lock_shares": "0.000001"})
	f.append(evStake, fxStaker, f.amt("60"), nil, "stake:t1", map[string]string{"phase": "escrow", "position_id": "p1"})
	f.append(evStake, fxStaker, f.amt("60"), f.amt("60"), "stake_mint:s1", map[string]string{"phase": "mint", "position_id": "p1"})
	f.append(evEpoch, "", nil, nil, "epoch:"+fxPool+":2026-08-01",
		map[string]string{"epoch_date": "2026-08-01", "shares_close": "1060.000001000000000000"})
	f.append(evFeeMint, fxPlatform, f.amt("10"), f.amt("5"), "fee_mint:"+fxPool+":2026-08-02",
		map[string]string{"epoch_date": "2026-08-02"})
	f.append(evUnstakeRequest, fxStaker, nil, nil, "unstake_request:p1:1", map[string]string{"position_id": "p1"})
	f.append(evUnstakeCancel, fxStaker, nil, nil, "unstake_cancel:p1:1", map[string]string{"position_id": "p1"})
	f.append(evUnstakeRequest, fxStaker, nil, nil, "unstake_request:p1:2", map[string]string{"position_id": "p1"})
	f.append(evUnstakeBurn, fxStaker, f.amt("61.5"), f.amt("60"), "unstake_burn:p1:2026-08-02",
		map[string]string{"position_id": "p1"})
	f.append(evEpoch, "", nil, nil, "epoch:"+fxPool+":2026-08-02",
		map[string]string{"epoch_date": "2026-08-02", "shares_close": "1005.000001000000000000"})
	f.append(evUnstakeClaim, fxStaker, f.amt("61.5"), nil, "unstake_claim:p1", map[string]string{"position_id": "p1"})
	f.append(evCapitalBurn, fxPlatform, f.amt("100"), f.amt("98.7"), "capital:ledger-42",
		map[string]string{"kind": "ops_withdrawal"})
	return f
}

func fixtureRegistry(t *testing.T, signer *translog.Signer) *translog.KeyRegistry {
	t.Helper()
	reg, err := translog.NewKeyRegistry([]translog.RegistryKey{{
		KeyID: signer.KeyID(), PublicKey: signer.PublicKey(),
		ValidFrom: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	return reg
}

func fixtureSigner(t *testing.T) *translog.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	s, err := translog.NewSigner(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return s
}

func TestVerify_CleanLifecycleVerifies(t *testing.T) {
	signer := fixtureSigner(t)
	f := buildLifecycle(t, signer)
	sum, err := VerifyStream(bytes.NewReader(f.ndjson()), Options{Registry: fixtureRegistry(t, signer)})
	if err != nil {
		t.Fatalf("VerifyStream: %v", err)
	}
	if sum.Events != 12 || len(sum.Pools) != 1 {
		t.Fatalf("summary = %d events / %d pools, want 12 / 1", sum.Events, len(sum.Pools))
	}
	st := sum.Pools[fxPool]
	// Replayed total: 1000.000001 + 60 + 5 − 60 − 98.7 = 906.300001
	if want := "906.300001"; st.Total.String() != want {
		t.Fatalf("replayed total shares = %s, want %s", st.Total.String(), want)
	}
	if !bytes.Equal(st.Head, f.head) {
		t.Fatalf("final chain head mismatch")
	}
	if got := st.Accounts[fxStaker]; !got.IsZero() {
		t.Fatalf("staker's replayed final shares = %s, want 0 (fully exited)", got.String())
	}
}

// TestVerify_TamperedAmountIsDetectedAtItsSeq: edit ONE stored field (the fee-mint amount at
// seq 5) in the export and the verifier must fail AT seq 5 with a chain-check failure — the
// signature/hash commit to the original bytes.
func TestVerify_TamperedAmountIsDetectedAtItsSeq(t *testing.T) {
	signer := fixtureSigner(t)
	f := buildLifecycle(t, signer)
	tampered := bytes.Replace(f.ndjson(),
		[]byte(`"amount":"10.000000000000000000"`),
		[]byte(`"amount":"1000.000000000000000000"`), 1)
	if bytes.Equal(tampered, f.ndjson()) {
		t.Fatalf("tamper substitution did not apply — fixture changed?")
	}
	_, err := VerifyStream(bytes.NewReader(tampered), Options{Registry: fixtureRegistry(t, signer)})
	if err == nil {
		t.Fatalf("tampered export VERIFIED — the chain provides no integrity")
	}
	verr, ok := err.(*VerifyError)
	if !ok {
		t.Fatalf("error is %T, want *VerifyError: %v", err, err)
	}
	if verr.Seq != 5 || verr.Check != "chain" {
		t.Fatalf("failure at seq %d check %q, want seq 5 check \"chain\": %v", verr.Seq, verr.Check, verr)
	}
}

func TestVerify_TruncatedHeadIsRefused(t *testing.T) {
	signer := fixtureSigner(t)
	f := buildLifecycle(t, signer)
	// Drop the first line: the export now starts mid-chain, which cannot prove balances.
	body := f.ndjson()
	idx := bytes.IndexByte(body, '\n')
	_, err := VerifyStream(bytes.NewReader(body[idx+1:]), Options{Registry: fixtureRegistry(t, signer)})
	verr, ok := err.(*VerifyError)
	if !ok || verr.Check != "chain" || !strings.Contains(verr.Msg, "genesis") {
		t.Fatalf("truncated export: err = %v, want a chain/genesis refusal", err)
	}
}

func TestVerify_UnsignedRefusedUnlessAllowed(t *testing.T) {
	f := buildLifecycle(t, nil) // no signer: unsigned log
	_, err := VerifyStream(bytes.NewReader(f.ndjson()), Options{})
	verr, ok := err.(*VerifyError)
	if !ok || verr.Check != "signature" {
		t.Fatalf("unsigned export: err = %v, want a signature refusal", err)
	}
	sum, err := VerifyStream(bytes.NewReader(f.ndjson()), Options{AllowUnsigned: true})
	if err != nil {
		t.Fatalf("unsigned export with -allow-unsigned: %v", err)
	}
	if sum.Unsigned != 12 {
		t.Fatalf("unsigned count = %d, want 12", sum.Unsigned)
	}
}

// Review item 10: -registry's additive signingEnabled/activeKeyId fields must let the verifier
// distinguish "this operator has never signed anything" (registry: signingEnabled=false) from
// "this entry is unsigned even though the operator's active key was already valid" (always
// unexpected, never accepted) from "this entry predates the operator's active key" (legitimate
// history, still gated behind -allow-unsigned, just labeled precisely).

// TestVerify_UnsignedWithSigningDisabledRegistry_MessageAndSummaryAreDistinct: the registry
// confirms this operator has NEVER configured a signing key — refused without -allow-unsigned
// with a message naming exactly that (not the generic "producer known to run unsigned" wording),
// and WriteSummary prints a calm NOTE, not the old generic WARNING, once accepted.
func TestVerify_UnsignedWithSigningDisabledRegistry_MessageAndSummaryAreDistinct(t *testing.T) {
	f := buildLifecycle(t, nil) // no signer: unsigned log

	_, err := VerifyStream(bytes.NewReader(f.ndjson()), Options{RegistrySigningKnown: true, RegistrySigningEnabled: false})
	verr, ok := err.(*VerifyError)
	if !ok || verr.Check != "signature" || !strings.Contains(verr.Msg, "never configured a signing key") {
		t.Fatalf("err = %v, want a signature refusal naming the registry's signingEnabled=false state", err)
	}

	sum, err := VerifyStream(bytes.NewReader(f.ndjson()), Options{AllowUnsigned: true, RegistrySigningKnown: true, RegistrySigningEnabled: false})
	if err != nil {
		t.Fatalf("unsigned export with -allow-unsigned: %v", err)
	}
	if sum.Unsigned != 12 {
		t.Fatalf("unsigned count = %d, want 12", sum.Unsigned)
	}
	var buf bytes.Buffer
	WriteSummary(&buf, sum, time.Now())
	out := buf.String()
	if !strings.Contains(out, "NOTE:") || !strings.Contains(out, "never configured a signing key") {
		t.Fatalf("summary = %q, want a NOTE naming the registry's signingEnabled=false state, not the generic WARNING", out)
	}
	if strings.Contains(out, "WARNING") {
		t.Fatalf("summary = %q, want no generic WARNING wording once the registry state is known", out)
	}
}

// TestVerify_UnsignedWithActiveSigningKey_AlwaysFailsRegardlessOfAllowUnsigned: the registry says
// this operator's active key was ALREADY VALID at every one of these entries' timestamps, so an
// unsigned entry here is unexpected — it must be refused even with -allow-unsigned, since that
// flag's own contract ("the producer is known to run unsigned") does not hold for a currently-
// signing operator.
func TestVerify_UnsignedWithActiveSigningKey_AlwaysFailsRegardlessOfAllowUnsigned(t *testing.T) {
	f := buildLifecycle(t, nil) // no signer: unsigned log
	activeKey := fixtureSigner(t)
	reg, err := translog.NewKeyRegistry([]translog.RegistryKey{{
		KeyID: activeKey.KeyID(), PublicKey: activeKey.PublicKey(),
		ValidFrom: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), // before every fixture entry's ts
	}})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	opts := Options{
		Registry: reg, RegistrySigningKnown: true, RegistrySigningEnabled: true, RegistryActiveKeyID: activeKey.KeyID(),
	}

	_, err = VerifyStream(bytes.NewReader(f.ndjson()), opts)
	verr, ok := err.(*VerifyError)
	if !ok || verr.Check != "signature" || !strings.Contains(verr.Msg, "cannot be waved through with -allow-unsigned") {
		t.Fatalf("err = %v, want an unexpected-unsigned refusal", err)
	}

	opts.AllowUnsigned = true
	_, err = VerifyStream(bytes.NewReader(f.ndjson()), opts)
	verr, ok = err.(*VerifyError)
	if !ok || verr.Check != "signature" || !strings.Contains(verr.Msg, "cannot be waved through with -allow-unsigned") {
		t.Fatalf("err = %v with -allow-unsigned, want the SAME unexpected-unsigned refusal (not waved through)", err)
	}
}

// TestVerify_UnsignedPredatingActiveKey_LegitimateHistory: the registry's active key was NOT yet
// valid at any of these entries' timestamps — this is legitimate pre-signing history (an operator
// that started unsigned and later configured a key), still gated behind -allow-unsigned as
// before, but labeled as exactly that rather than the generic wording.
func TestVerify_UnsignedPredatingActiveKey_LegitimateHistory(t *testing.T) {
	f := buildLifecycle(t, nil) // no signer: unsigned log
	activeKey := fixtureSigner(t)
	reg, err := translog.NewKeyRegistry([]translog.RegistryKey{{
		KeyID: activeKey.KeyID(), PublicKey: activeKey.PublicKey(),
		ValidFrom: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), // after every fixture entry's ts
	}})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	opts := Options{
		Registry: reg, RegistrySigningKnown: true, RegistrySigningEnabled: true, RegistryActiveKeyID: activeKey.KeyID(),
	}

	_, err = VerifyStream(bytes.NewReader(f.ndjson()), opts)
	verr, ok := err.(*VerifyError)
	if !ok || verr.Check != "signature" || !strings.Contains(verr.Msg, "predating the operator's active signing key") {
		t.Fatalf("err = %v, want a refusal naming this as pre-signing history", err)
	}

	opts.AllowUnsigned = true
	sum, err := VerifyStream(bytes.NewReader(f.ndjson()), opts)
	if err != nil {
		t.Fatalf("unsigned export predating the active key, with -allow-unsigned: %v", err)
	}
	if sum.Unsigned != 12 {
		t.Fatalf("unsigned count = %d, want 12", sum.Unsigned)
	}
	var buf bytes.Buffer
	WriteSummary(&buf, sum, time.Now())
	out := buf.String()
	if !strings.Contains(out, "NOTE:") || !strings.Contains(out, "predating the operator's active signing key") {
		t.Fatalf("summary = %q, want a NOTE naming this as pre-signing history", out)
	}
}

func TestVerify_EpochSharesCloseMismatchIsCaught(t *testing.T) {
	signer := fixtureSigner(t)
	f := newFixture(t, signer)
	f.append(evCapitalMint, fxPlatform, f.amt("100"), f.amt("100"), "genesis:"+fxPool, map[string]string{"genesis": "true"})
	// The producer LIES about the closing total — signed lie, so chain+signature pass; only the
	// replay can catch it.
	f.append(evEpoch, "", nil, nil, "epoch:x", map[string]string{"shares_close": "999"})
	_, err := VerifyStream(bytes.NewReader(f.ndjson()), Options{Registry: fixtureRegistry(t, signer)})
	verr, ok := err.(*VerifyError)
	if !ok || verr.Check != "replay" || !strings.Contains(verr.Msg, "shares_close") {
		t.Fatalf("lying EPOCH: err = %v, want a replay/shares_close failure", err)
	}
}

// TestVerify_RecapitalizeReplaysWithNoShareMovement is the regression test for the pre-existing
// verifier gap: RECAPITALIZE has been an appendable event type since migration 083 (and a
// PRODUCED one since AdminStakingRecapitalize shipped), but replayEvent had no case for it, so it
// fell through to the unknown-type refusal — meaning ANY already-recapitalized pool's export
// failed verification outright. The event moves no shares by construction (the producer appends it
// with no Shares field, see repositories.StakingRepository.RecapitalizePool), so replaying it is a
// no-op on balances, exactly like UNSTAKE_REQUEST.
func TestVerify_RecapitalizeReplaysWithNoShareMovement(t *testing.T) {
	signer := fixtureSigner(t)
	f := newFixture(t, signer)
	f.append(evCapitalMint, fxPlatform, f.amt("100"), f.amt("100"), "genesis:"+fxPool, nil)
	f.append(evRecapitalize, "", nil, nil, "recapitalize:"+fxPool+":r1",
		map[string]string{"balance": "100", "actor": "bo:ann", "reason": "leg re-funded"})
	sum, err := VerifyStream(bytes.NewReader(f.ndjson()), Options{Registry: fixtureRegistry(t, signer)})
	if err != nil {
		t.Fatalf("VerifyStream over a recapitalized pool: %v", err)
	}
	if want := "100"; sum.Pools[fxPool].Total.String() != want {
		t.Fatalf("replayed total after RECAPITALIZE = %s, want %s (the event moves no shares)", sum.Pools[fxPool].Total.String(), want)
	}
}

// TestVerify_RecapitalizeCarryingSharesIsRefused: the no-share-movement semantics above are
// ASSERTED, not assumed — a RECAPITALIZE that carries a shares field is a producer this verifier
// does not understand, and converging on it would silently mis-state the pool's total.
func TestVerify_RecapitalizeCarryingSharesIsRefused(t *testing.T) {
	signer := fixtureSigner(t)
	f := newFixture(t, signer)
	f.append(evCapitalMint, fxPlatform, f.amt("100"), f.amt("100"), "genesis:"+fxPool, nil)
	f.append(evRecapitalize, "", nil, f.amt("5"), "recapitalize:"+fxPool+":r1", nil)
	_, err := VerifyStream(bytes.NewReader(f.ndjson()), Options{Registry: fixtureRegistry(t, signer)})
	verr, ok := err.(*VerifyError)
	if !ok || verr.Check != "replay" || !strings.Contains(verr.Msg, "must not carry a shares field") {
		t.Fatalf("RECAPITALIZE with shares: err = %v, want a replay/shares refusal", err)
	}
}

func TestVerify_BurnBeyondBalanceIsCaught(t *testing.T) {
	signer := fixtureSigner(t)
	f := newFixture(t, signer)
	f.append(evCapitalMint, fxPlatform, f.amt("100"), f.amt("100"), "genesis:"+fxPool, nil)
	f.append(evUnstakeBurn, fxStaker, f.amt("10"), f.amt("10"), "unstake_burn:px:d", nil)
	_, err := VerifyStream(bytes.NewReader(f.ndjson()), Options{Registry: fixtureRegistry(t, signer)})
	verr, ok := err.(*VerifyError)
	if !ok || verr.Check != "replay" || !strings.Contains(verr.Msg, "negative") {
		t.Fatalf("over-burn: err = %v, want a replay/negative-balance failure", err)
	}
}

// TestVerify_AdjustmentReplaysWithNoShareMovement is the regression test for V2: ADJUSTMENT is
// DB-permitted (migrations/083, widened in 094) but currently unemitted by any producer. Before
// this fix, replayEvent had no case for it, so it fell through to the unknown-type refusal —
// meaning ANY pool that ever picked up a future ADJUSTMENT row would become permanently
// unverifiable. It carries no share movement by construction, mirroring RECAPITALIZE.
func TestVerify_AdjustmentReplaysWithNoShareMovement(t *testing.T) {
	signer := fixtureSigner(t)
	f := newFixture(t, signer)
	f.append(evCapitalMint, fxPlatform, f.amt("100"), f.amt("100"), "genesis:"+fxPool, nil)
	f.append(evAdjustment, "", nil, nil, "adjustment:"+fxPool+":a1",
		map[string]string{"actor": "bo:ann", "reason": "manual correction, no share movement"})
	sum, err := VerifyStream(bytes.NewReader(f.ndjson()), Options{Registry: fixtureRegistry(t, signer)})
	if err != nil {
		t.Fatalf("VerifyStream over a pool with an ADJUSTMENT event: %v", err)
	}
	if want := "100"; sum.Pools[fxPool].Total.String() != want {
		t.Fatalf("replayed total after ADJUSTMENT = %s, want %s (the event moves no shares)", sum.Pools[fxPool].Total.String(), want)
	}
}

// TestVerify_AdjustmentCarryingSharesIsRefused asserts the no-share-movement semantics above,
// not assumes them — an ADJUSTMENT that carries a shares field is a producer this verifier does
// not understand, and converging on it would silently mis-state the pool's total.
func TestVerify_AdjustmentCarryingSharesIsRefused(t *testing.T) {
	signer := fixtureSigner(t)
	f := newFixture(t, signer)
	f.append(evCapitalMint, fxPlatform, f.amt("100"), f.amt("100"), "genesis:"+fxPool, nil)
	f.append(evAdjustment, "", nil, f.amt("5"), "adjustment:"+fxPool+":a1", nil)
	_, err := VerifyStream(bytes.NewReader(f.ndjson()), Options{Registry: fixtureRegistry(t, signer)})
	verr, ok := err.(*VerifyError)
	if !ok || verr.Check != "replay" || !strings.Contains(verr.Msg, "must not carry a shares field") {
		t.Fatalf("ADJUSTMENT with shares: err = %v, want a replay/shares refusal", err)
	}
}

// TestVerify_PolicyChangeReplaysWithNoShareMovement: POLICY_CHANGE (migration 096) is the
// pool-level marker SetPoolLimits appends when an operator actually moves a pool's min/max stake
// bounds. Unlike ADJUSTMENT it IS emitted by a live producer, so a verifier without a case for it
// would make every pool whose limits were ever edited permanently unverifiable from that seq
// onward. It moves no shares: the bounds constrain FUTURE stakes, never outstanding ones.
func TestVerify_PolicyChangeReplaysWithNoShareMovement(t *testing.T) {
	signer := fixtureSigner(t)
	f := newFixture(t, signer)
	f.append(evCapitalMint, fxPlatform, f.amt("100"), f.amt("100"), "genesis:"+fxPool, nil)
	f.append(evPolicyChange, "", nil, nil, "policy_change:"+fxPool+":8f2c1d7e-0000-4000-8000-000000000001",
		map[string]string{
			"min_stake_amount": "10.000000000000000000", "max_stake_amount": "500.000000000000000000",
			"prev_min_stake_amount": "1.000000000000000000", "prev_max_stake_amount": "null",
			"actor": "bo:ann", "reason": "raise floor for launch",
		})
	sum, err := VerifyStream(bytes.NewReader(f.ndjson()), Options{Registry: fixtureRegistry(t, signer)})
	if err != nil {
		t.Fatalf("VerifyStream over a pool with a POLICY_CHANGE event: %v", err)
	}
	if want := "100"; sum.Pools[fxPool].Total.String() != want {
		t.Fatalf("replayed total after POLICY_CHANGE = %s, want %s (the event moves no shares)", sum.Pools[fxPool].Total.String(), want)
	}
}

// TestVerify_PolicyChangeCarryingSharesIsRefused asserts the no-share-movement semantics above,
// not assumes them — a POLICY_CHANGE that carries a shares field is a producer this verifier does
// not understand, and converging on it would silently mis-state the pool's total.
func TestVerify_PolicyChangeCarryingSharesIsRefused(t *testing.T) {
	signer := fixtureSigner(t)
	f := newFixture(t, signer)
	f.append(evCapitalMint, fxPlatform, f.amt("100"), f.amt("100"), "genesis:"+fxPool, nil)
	f.append(evPolicyChange, "", nil, f.amt("5"), "policy_change:"+fxPool+":8f2c1d7e-0000-4000-8000-000000000001", nil)
	_, err := VerifyStream(bytes.NewReader(f.ndjson()), Options{Registry: fixtureRegistry(t, signer)})
	verr, ok := err.(*VerifyError)
	if !ok || verr.Check != "replay" || !strings.Contains(verr.Msg, "must not carry a shares field") {
		t.Fatalf("POLICY_CHANGE with shares: err = %v, want a replay/shares refusal", err)
	}
}

// TestVerify_EpochMissingSharesCloseIsRefused is the regression test for V3: the producer ALWAYS
// writes shares_close as part of its EPOCH event append, so treating
// it as optional silently skips the strongest cross-check in the file. An EPOCH without it must
// now be refused, not silently pass.
func TestVerify_EpochMissingSharesCloseIsRefused(t *testing.T) {
	signer := fixtureSigner(t)
	f := newFixture(t, signer)
	f.append(evCapitalMint, fxPlatform, f.amt("100"), f.amt("100"), "genesis:"+fxPool, nil)
	f.append(evEpoch, "", nil, nil, "epoch:x", map[string]string{"epoch_date": "2026-08-01"})
	_, err := VerifyStream(bytes.NewReader(f.ndjson()), Options{Registry: fixtureRegistry(t, signer)})
	verr, ok := err.(*VerifyError)
	if !ok || verr.Check != "replay" || !strings.Contains(verr.Msg, "shares_close") {
		t.Fatalf("EPOCH without shares_close: err = %v, want a replay/shares_close failure", err)
	}
}

// TestVerify_UnrecognizedSchemaVersionIsRefused is the regression test for V4: schema_version is
// itself a SIGNED field but was never independently checked. A future producer's entries (a
// hypothetical schema_version 3 — 2 is now a RECOGNIZED version, see
// TestVerify_SchemaVersion2EpochWithoutNewChecksStillVerifies and the cap_net-bearing tests below)
// must not silently replay under today's canonicalization rules — this verifier must refuse
// rather than guess. The tamper is applied via raw byte substitution (like
// TestVerify_TamperedAmountIsDetectedAtItsSeq) rather than the fixture builder, because
// Entry.CanonicalJSON/Validate itself refuses to canonicalize (and therefore sign) any
// schema_version other than translog.SchemaVersion1/SchemaVersion2 — there is no legitimate way
// to build one through the production path with today's pkg/translog.
func TestVerify_UnrecognizedSchemaVersionIsRefused(t *testing.T) {
	signer := fixtureSigner(t)
	f := newFixture(t, signer)
	f.append(evCapitalMint, fxPlatform, f.amt("100"), f.amt("100"), "genesis:"+fxPool, nil)
	tampered := bytes.Replace(f.ndjson(), []byte(`"schema_version":1`), []byte(`"schema_version":3`), 1)
	if bytes.Equal(tampered, f.ndjson()) {
		t.Fatalf("schema_version substitution did not apply — fixture changed?")
	}
	_, err := VerifyStream(bytes.NewReader(tampered), Options{Registry: fixtureRegistry(t, signer)})
	verr, ok := err.(*VerifyError)
	if !ok || verr.Check != "chain" || !strings.Contains(verr.Msg, "schema_version") {
		t.Fatalf("unrecognized schema_version: err = %v, want a chain/schema_version refusal", err)
	}
}

// TestVerify_CrossOperatorContaminationIsCaught is the regression test for V5: st.Operator was
// captured from the first entry only and never compared against later entries of the same pool's
// chain — a corrupted or maliciously spliced export mixing two operators' entries into one
// pool_id would otherwise replay (and even chain/signature-verify, since operator_id is a
// per-entry field) without ever being flagged.
func TestVerify_CrossOperatorContaminationIsCaught(t *testing.T) {
	signer := fixtureSigner(t)
	f := newFixture(t, signer)
	f.append(evCapitalMint, fxPlatform, f.amt("100"), f.amt("100"), "genesis:"+fxPool, nil)
	otherOperator := "cccc3333-0000-0000-0000-000000000003"
	f.appendWithOperator(otherOperator, evFeeMint, fxPlatform, f.amt("1"), f.amt("1"), "fee_mint:contaminated", nil)
	_, err := VerifyStream(bytes.NewReader(f.ndjson()), Options{Registry: fixtureRegistry(t, signer)})
	verr, ok := err.(*VerifyError)
	if !ok || verr.Check != "chain" || !strings.Contains(verr.Msg, "cross-operator") {
		t.Fatalf("cross-operator entry: err = %v, want a chain/cross-operator refusal", err)
	}
}

// TestVerify_ParseFailureReportsLineNotSeq is the regression test for V6: VerifyError.Seq carried
// a LINE NUMBER on the two parse-failure paths in VerifyStream (there's no parsed entry yet to
// carry a real chain seq), but Error() always printed "at seq %d" regardless — confusing for the
// common failure case of a truncated/corrupted download. The new Line field must be set instead,
// and Error() must say "at line N".
func TestVerify_ParseFailureReportsLineNotSeq(t *testing.T) {
	bad := []byte("this is not json\n")
	_, err := VerifyStream(bytes.NewReader(bad), Options{})
	verr, ok := err.(*VerifyError)
	if !ok || verr.Check != "parse" {
		t.Fatalf("malformed line: err = %v, want a parse failure", err)
	}
	if verr.Line != 1 {
		t.Fatalf("Line = %d, want 1", verr.Line)
	}
	msg := verr.Error()
	if !strings.Contains(msg, "at line 1") {
		t.Fatalf("Error() = %q, want it to contain \"at line 1\"", msg)
	}
	if strings.Contains(msg, "at seq") {
		t.Fatalf("Error() = %q, want it to NOT say \"at seq\" for a parse failure", msg)
	}
}

// ─── STAKING transparency hardening: schema_version 2's cap_net-gated EPOCH checks ───
//
// epochV2Expected recomputes the fee_shares/price a legitimate v2 EPOCH must declare, using the
// SAME primitives (floorRatioShares, money.Amount.DivRound) both this test file and verify.go's
// evEpoch case call — i.e. it mirrors the producer's epoch-settlement (RunEpoch) formula
// (fee_shares = floor(fee*shares_open / (assets_mid-fee)); price = assets_mid.DivRound(shares_open
// + fee_shares, 36)) without importing internal/, exactly like verify.go's own reimplementation.
func epochV2Expected(assetsOpen, ggr, capNet, sharesOpen, fee money.Amount) (feeShares, price money.Amount) {
	assetsMid := assetsOpen.Add(ggr).Add(capNet)
	denom := assetsMid.Sub(fee)
	feeShares = money.Zero
	if fee.IsPositive() && sharesOpen.IsPositive() && denom.IsPositive() {
		feeShares = floorRatioShares(fee.Mul(sharesOpen), denom)
	}
	sharesAfterFee := sharesOpen.Add(feeShares)
	price = money.Zero
	if sharesAfterFee.IsPositive() {
		price = assetsMid.DivRound(sharesAfterFee, 36)
	}
	return feeShares, price
}

// epochV2Payload builds one EPOCH event's v2 payload map from already-decided values — every field
// staking_epoch.go's RunEpoch writes today (epoch_date, ledger_id_from/to omitted: no check reads
// them) plus cap_net.
func epochV2Payload(epochDate string, assetsOpen, assetsClose, sharesOpen, sharesClose, ggr, capNet, fee, feeShares, price money.Amount) map[string]string {
	return map[string]string{
		"epoch_date":   epochDate,
		"assets_open":  assetsOpen.String(),
		"assets_close": assetsClose.String(),
		"shares_open":  sharesOpen.String(),
		"shares_close": translog.CanonicalAmount(sharesClose),
		"ggr":          ggr.String(),
		"cap_net":      capNet.String(),
		"fee":          fee.String(),
		"fee_shares":   feeShares.String(),
		"price":        price.String(),
	}
}

// buildV2EpochFixture builds: genesis capitalization (900/900) → a winning epoch with a fee mint
// (fee=100 on ggr=100, cap_net=0), one subscription (amount=50, mint-phase shares=50), one
// redemption (payout=20, shares burned=20) → a v2 EPOCH event whose payload is entirely correct BY
// CONSTRUCTION. assets_close (1030) deliberately does NOT equal assets_open+ggr+cap_net (1000) —
// the fixture exists specifically to prove the invariant check accounts for the epoch's own net
// stake movement (EpochAssetDelta = 50-20 = 30) rather than the naive assets_close ==
// assets_open+ggr+cap_net identity, which would wrongly reject this (entirely legitimate) epoch.
func buildV2EpochFixture(t *testing.T, signer *translog.Signer) *fixtureBuilder {
	t.Helper()
	f := newFixture(t, signer)
	assetsOpen, ggr, capNet, sharesOpen, fee := money.MustParse("900"), money.MustParse("100"), money.MustParse("0"), money.MustParse("900"), money.MustParse("100")
	feeShares, price := epochV2Expected(assetsOpen, ggr, capNet, sharesOpen, fee)

	f.append(evCapitalMint, fxPlatform, f.amt("900"), f.amt("900"), "genesis:"+fxPool, map[string]string{"genesis": "true"})
	f.append(evFeeMint, fxPlatform, &fee, &feeShares, "fee_mint:"+fxPool+":2026-08-02", map[string]string{"epoch_date": "2026-08-02"})
	f.append(evStake, fxStaker, f.amt("50"), f.amt("50"), "stake_mint:s1", map[string]string{"phase": "mint", "position_id": "p1"})
	f.append(evUnstakeBurn, fxStaker, f.amt("20"), f.amt("20"), "unstake_burn:p2:2026-08-02", map[string]string{"position_id": "p2"})

	sharesClose := sharesOpen.Add(feeShares).Add(money.MustParse("50")).Sub(money.MustParse("20"))       // 1030
	assetsClose := assetsOpen.Add(ggr).Add(capNet).Add(money.MustParse("50")).Sub(money.MustParse("20")) // 1030
	f.appendV2(evEpoch, "", nil, nil, "epoch:"+fxPool+":2026-08-02",
		epochV2Payload("2026-08-02", assetsOpen, assetsClose, sharesOpen, sharesClose, ggr, capNet, fee, feeShares, price))
	return f
}

func TestVerify_SchemaVersion2EpochWithNetStakeMovementPasses(t *testing.T) {
	signer := fixtureSigner(t)
	f := buildV2EpochFixture(t, signer)
	sum, err := VerifyStream(bytes.NewReader(f.ndjson()), Options{Registry: fixtureRegistry(t, signer)})
	if err != nil {
		t.Fatalf("VerifyStream: %v", err)
	}
	st := sum.Pools[fxPool]
	if want := "1030"; st.Total.String() != want {
		t.Fatalf("replayed total = %s, want %s", st.Total.String(), want)
	}
	if !st.HasPrevEpoch {
		t.Fatalf("HasPrevEpoch = false after a v2 EPOCH, want true")
	}
	if want := "1030"; st.PrevEpochAssetsClose.String() != want {
		t.Fatalf("PrevEpochAssetsClose = %s, want %s", st.PrevEpochAssetsClose.String(), want)
	}
	if !st.EpochAssetDelta.IsZero() {
		t.Fatalf("EpochAssetDelta = %s after an EPOCH event, want reset to 0", st.EpochAssetDelta.String())
	}
}

// TestVerify_SchemaVersion2PriceMismatchIsCaught: check #1. The declared price disagrees with
// (assets_open+ggr+cap_net)/(shares_open+fee_shares) — the frozen ratio RunEpoch actually divides
// — while every OTHER field in the fixture stays correct, isolating the failure to this one check.
//
// The wrong price is baked into the entry BEFORE it is chained/signed (not a post-hoc byte
// substitution on an already-signed export, like TestVerify_TamperedAmountIsDetectedAtItsSeq
// uses): a signed field edited after the fact is caught one layer earlier, by the CHAIN check's
// entry_hash mismatch — this test's whole point is proving the REPLAY-level check catches a
// producer that itself signed an internally wrong number, which only a fixture built wrong from
// the start (a forged/buggy producer, not a tampered export) can exercise.
func TestVerify_SchemaVersion2PriceMismatchIsCaught(t *testing.T) {
	signer := fixtureSigner(t)
	f := newFixture(t, signer)
	assetsOpen, ggr, capNet, sharesOpen, fee := money.MustParse("900"), money.MustParse("100"), money.MustParse("0"), money.MustParse("900"), money.MustParse("100")
	feeShares, _ := epochV2Expected(assetsOpen, ggr, capNet, sharesOpen, fee)
	wrongPrice := money.MustParse("2") // correct price is 1

	f.append(evCapitalMint, fxPlatform, f.amt("900"), f.amt("900"), "genesis:"+fxPool, map[string]string{"genesis": "true"})
	f.append(evFeeMint, fxPlatform, &fee, &feeShares, "fee_mint:"+fxPool+":2026-08-02", map[string]string{"epoch_date": "2026-08-02"})
	sharesClose := sharesOpen.Add(feeShares)
	assetsClose := assetsOpen.Add(ggr).Add(capNet) // no subs/redemptions: invariant holds regardless of price
	f.appendV2(evEpoch, "", nil, nil, "epoch:"+fxPool+":2026-08-02",
		epochV2Payload("2026-08-02", assetsOpen, assetsClose, sharesOpen, sharesClose, ggr, capNet, fee, feeShares, wrongPrice))

	_, err := VerifyStream(bytes.NewReader(f.ndjson()), Options{Registry: fixtureRegistry(t, signer)})
	verr, ok := err.(*VerifyError)
	if !ok || verr.Check != "replay" || !strings.Contains(verr.Msg, "declares price=") {
		t.Fatalf("wrong price: err = %v, want a replay/price failure", err)
	}
}

// TestVerify_SchemaVersion2AssetChainBreakIsCaught: check #2, across two epochs. Epoch 2 declares
// an assets_open that does not match epoch 1's assets_close, while epoch 2 is otherwise entirely
// self-consistent (its own price/invariant/fee-share checks all pass), isolating the failure to
// the cross-epoch asset-chaining check.
func TestVerify_SchemaVersion2AssetChainBreakIsCaught(t *testing.T) {
	signer := fixtureSigner(t)
	f := buildV2EpochFixture(t, signer) // epoch 1: assets_close = 1030 (real)

	wrongAssetsOpen := money.MustParse("999") // should be 1030
	ggr2, capNet2, fee2 := money.MustParse("31"), money.MustParse("0"), money.MustParse("0")
	sharesOpen2 := money.MustParse("1030") // = epoch 1's replayed shares_close
	feeShares2, price2 := epochV2Expected(wrongAssetsOpen, ggr2, capNet2, sharesOpen2, fee2)
	assetsClose2 := wrongAssetsOpen.Add(ggr2).Add(capNet2) // no subs/redemptions this epoch: invariant still holds internally
	f.appendV2(evEpoch, "", nil, nil, "epoch:"+fxPool+":2026-08-03",
		epochV2Payload("2026-08-03", wrongAssetsOpen, assetsClose2, sharesOpen2, sharesOpen2, ggr2, capNet2, fee2, feeShares2, price2))

	_, err := VerifyStream(bytes.NewReader(f.ndjson()), Options{Registry: fixtureRegistry(t, signer)})
	verr, ok := err.(*VerifyError)
	if !ok || verr.Check != "replay" || !strings.Contains(verr.Msg, "asset chain is broken") {
		t.Fatalf("broken asset chain: err = %v, want a replay/asset-chain failure", err)
	}
}

// TestVerify_SchemaVersion2InvariantMismatchIsCaught: check #3. assets_close disagrees with
// assets_open+ggr+cap_net+net-stake-movement — price and fee_shares are both left correct so the
// failure is isolated to the invariant check specifically. Like the price test above, the wrong
// value is baked into the entry before signing (not a post-hoc tamper), so this genuinely exercises
// the REPLAY-level check rather than the CHAIN-level entry_hash mismatch one layer earlier.
func TestVerify_SchemaVersion2InvariantMismatchIsCaught(t *testing.T) {
	signer := fixtureSigner(t)
	f := newFixture(t, signer)
	assetsOpen, ggr, capNet, sharesOpen, fee := money.MustParse("900"), money.MustParse("100"), money.MustParse("0"), money.MustParse("900"), money.MustParse("100")
	feeShares, price := epochV2Expected(assetsOpen, ggr, capNet, sharesOpen, fee)
	wrongAssetsClose := money.MustParse("900") // correct value is 1000 (no subs/redemptions this epoch)

	f.append(evCapitalMint, fxPlatform, f.amt("900"), f.amt("900"), "genesis:"+fxPool, map[string]string{"genesis": "true"})
	f.append(evFeeMint, fxPlatform, &fee, &feeShares, "fee_mint:"+fxPool+":2026-08-02", map[string]string{"epoch_date": "2026-08-02"})
	sharesClose := sharesOpen.Add(feeShares)
	f.appendV2(evEpoch, "", nil, nil, "epoch:"+fxPool+":2026-08-02",
		epochV2Payload("2026-08-02", assetsOpen, wrongAssetsClose, sharesOpen, sharesClose, ggr, capNet, fee, feeShares, price))

	_, err := VerifyStream(bytes.NewReader(f.ndjson()), Options{Registry: fixtureRegistry(t, signer)})
	verr, ok := err.(*VerifyError)
	if !ok || verr.Check != "replay" || !strings.Contains(verr.Msg, "EPOCH invariant broken") {
		t.Fatalf("broken invariant: err = %v, want a replay/invariant failure", err)
	}
}

// TestVerify_SchemaVersion2FeeShareAlgebraMismatchIsCaught: check #4. fee_shares disagrees with
// floor(fee*shares_open / (assets_mid-fee)) — price is recomputed to stay consistent with the
// WRONG fee_shares (so check #1 passes) and there is no subscription/redemption activity this
// epoch (so check #3's invariant, unaffected by fee_shares, also passes), isolating the failure to
// the fee-share algebra check.
func TestVerify_SchemaVersion2FeeShareAlgebraMismatchIsCaught(t *testing.T) {
	signer := fixtureSigner(t)
	f := newFixture(t, signer)
	assetsOpen, ggr, capNet, sharesOpen, fee := money.MustParse("900"), money.MustParse("100"), money.MustParse("0"), money.MustParse("900"), money.MustParse("100")
	wrongFeeShares := money.MustParse("90") // correct value is 100 (900*100/900)
	assetsMid := assetsOpen.Add(ggr).Add(capNet)
	priceMatchingWrongFeeShares := assetsMid.DivRound(sharesOpen.Add(wrongFeeShares), 36)

	f.append(evCapitalMint, fxPlatform, f.amt("900"), f.amt("900"), "genesis:"+fxPool, map[string]string{"genesis": "true"})
	f.append(evFeeMint, fxPlatform, &fee, &wrongFeeShares, "fee_mint:"+fxPool+":2026-08-02", map[string]string{"epoch_date": "2026-08-02"})
	sharesClose := sharesOpen.Add(wrongFeeShares)
	assetsClose := assetsMid // no subs/redemptions: invariant holds regardless of fee_shares
	f.appendV2(evEpoch, "", nil, nil, "epoch:"+fxPool+":2026-08-02",
		epochV2Payload("2026-08-02", assetsOpen, assetsClose, sharesOpen, sharesClose, ggr, capNet, fee, wrongFeeShares, priceMatchingWrongFeeShares))

	_, err := VerifyStream(bytes.NewReader(f.ndjson()), Options{Registry: fixtureRegistry(t, signer)})
	verr, ok := err.(*VerifyError)
	if !ok || verr.Check != "replay" || !strings.Contains(verr.Msg, "declares fee_shares=") {
		t.Fatalf("wrong fee_shares: err = %v, want a replay/fee_shares failure", err)
	}
}

// TestVerify_SchemaVersion1EpochSkipsNewChecks is the backward-compatibility regression test: a
// SchemaVersion1 EPOCH event — no cap_net field, exactly what every already-exported real chain
// looks like today — must keep verifying successfully even when its price/assets/ggr are
// internally nonsensical by the NEW checks' standards. This is the single most important test in
// this change: a mistake here would break every already-exported real chain, not just future ones.
func TestVerify_SchemaVersion1EpochSkipsNewChecks(t *testing.T) {
	signer := fixtureSigner(t)
	f := newFixture(t, signer)
	f.append(evCapitalMint, fxPlatform, f.amt("900"), f.amt("900"), "genesis:"+fxPool, map[string]string{"genesis": "true"})
	// shares_close (the ONE field the pre-existing check reads) is correct; every other number is
	// deliberately absurd — wrong by every new check's formula — to prove none of them run.
	f.append(evEpoch, "", nil, nil, "epoch:"+fxPool+":2026-08-01", map[string]string{
		"epoch_date":   "2026-08-01",
		"assets_open":  "1",
		"assets_close": "999999",
		"shares_open":  "1",
		"shares_close": "900",
		"ggr":          "7",
		"fee":          "3",
		"fee_shares":   "3",
		"price":        "42",
		// no cap_net key at all — this is what makes it v1 in spirit, on top of SchemaVersion1
		// itself: a real pre-this-change export literally cannot carry this key.
	})
	sum, err := VerifyStream(bytes.NewReader(f.ndjson()), Options{Registry: fixtureRegistry(t, signer)})
	if err != nil {
		t.Fatalf("VerifyStream over a v1 EPOCH with nonsensical (but v2-check-irrelevant) fields: %v", err)
	}
	if want := "900"; sum.Pools[fxPool].Total.String() != want {
		t.Fatalf("replayed total = %s, want %s", sum.Pools[fxPool].Total.String(), want)
	}
	// The tracker still updates from the v1 payload's assets_close (defensively parsed, best
	// effort) so a LATER v2 epoch on the same pool has a valid chain point — but nothing compares
	// against it while schema_version stays 1.
	if !sum.Pools[fxPool].HasPrevEpoch {
		t.Fatalf("HasPrevEpoch = false after a v1 EPOCH with a parseable assets_close, want true")
	}
}
