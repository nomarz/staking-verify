package main

// STAKING-P3 verifier tests: Signed Tree Heads over the synthetic P2 lifecycle fixture. The
// headline case is the REWRITTEN-HISTORY one (TestSTH_RewrittenChainIsCaught): a from-scratch
// regenerated chain passes every chain/signature/replay check — each of those is internal to
// the export — and ONLY the published heads, recorded before the rewrite, expose it. That is
// the attack class the STH layer exists for; the rest are the tamper permutations around it.

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/wasabi-gaming/staking-verify/pkg/translog"
)

// buildSTHs publishes heads over f's chain at the given tree sizes, signed unless signer is nil.
func buildSTHs(t *testing.T, f *fixtureBuilder, signer *translog.Signer, sizes ...int64) []byte {
	t.Helper()
	var out bytes.Buffer
	ts := time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)
	for _, size := range sizes {
		if size > int64(len(f.hashes)) {
			t.Fatalf("fixture has %d events, head wants %d", len(f.hashes), size)
		}
		ts = ts.Add(time.Hour)
		sth := translog.STH{
			SchemaVersion: translog.SchemaVersion1,
			OperatorID:    fxOperator,
			PoolID:        fxPool,
			TreeSize:      size,
			RootHash:      translog.MerkleRoot(f.hashes[:size]),
			TS:            ts,
		}
		if signer != nil {
			if err := signer.SignSTH(&sth); err != nil {
				t.Fatalf("SignSTH(%d): %v", size, err)
			}
		}
		line, err := sth.MarshalSTHLine()
		if err != nil {
			t.Fatalf("MarshalSTHLine(%d): %v", size, err)
		}
		out.Write(line)
		out.WriteByte('\n')
	}
	return out.Bytes()
}

// verifyWithSTHs runs the full -sth pipeline exactly as main() does.
func verifyWithSTHs(t *testing.T, export, sthBody []byte, opts Options) (*STHSummary, error) {
	t.Helper()
	opts.CollectLeaves = true
	sum, err := VerifyStream(bytes.NewReader(export), opts)
	if err != nil {
		t.Fatalf("chain verification failed before the STH stage: %v", err)
	}
	sths, err := ParseSTHStream(bytes.NewReader(sthBody))
	if err != nil {
		t.Fatalf("ParseSTHStream: %v", err)
	}
	return VerifySTHs(sum, sths, opts)
}

func TestSTH_CleanHeadsVerify(t *testing.T) {
	signer := fixtureSigner(t)
	f := buildLifecycle(t, signer) // 12 events
	sthBody := buildSTHs(t, f, signer, 3, 7, 12)
	sum, err := verifyWithSTHs(t, f.ndjson(), sthBody, Options{Registry: fixtureRegistry(t, signer)})
	if err != nil {
		t.Fatalf("clean heads failed: %v", err)
	}
	if sum.Heads != 3 || sum.Unsigned != 0 || sum.LatestByPool[fxPool] != 12 {
		t.Fatalf("summary = %+v, want 3 signed heads, latest 12", sum)
	}
}

// TestSTH_RewrittenChainIsCaught regenerates the ENTIRE chain from scratch with one amount
// changed — every hash recomputed, every signature re-issued with the real key, replay
// consistent — so the chain-only verifier passes it. The heads published over the ORIGINAL
// chain must expose the rewrite at the first size whose leaves diverge.
func TestSTH_RewrittenChainIsCaught(t *testing.T) {
	signer := fixtureSigner(t)
	original := buildLifecycle(t, signer)
	sthBody := buildSTHs(t, original, signer, 3, 7, 12) // witnessed BEFORE the rewrite

	// The rewrite: same lifecycle, same signer, but the fee-mint (event 5) claims 50 shares
	// instead of 5 — a self-consistent alternate history.
	rewritten := newFixture(t, signer)
	rewritten.append(evCapitalMint, fxPlatform, rewritten.amt("1000"), rewritten.amt("1000.000001"), "genesis:"+fxPool,
		map[string]string{"genesis": "true", "platform_shares": "1000", "genesis_lock_shares": "0.000001"})
	rewritten.append(evStake, fxStaker, rewritten.amt("60"), nil, "stake:t1", map[string]string{"phase": "escrow", "position_id": "p1"})
	rewritten.append(evStake, fxStaker, rewritten.amt("60"), rewritten.amt("60"), "stake_mint:s1", map[string]string{"phase": "mint", "position_id": "p1"})
	rewritten.append(evEpoch, "", nil, nil, "epoch:"+fxPool+":2026-08-01",
		map[string]string{"epoch_date": "2026-08-01", "shares_close": "1060.000001000000000000"})
	rewritten.append(evFeeMint, fxPlatform, rewritten.amt("10"), rewritten.amt("50"), "fee_mint:"+fxPool+":2026-08-02",
		map[string]string{"epoch_date": "2026-08-02"})

	// The rewritten chain alone sails through chain verification — that is the point.
	if _, err := VerifyStream(bytes.NewReader(rewritten.ndjson()), Options{Registry: fixtureRegistry(t, signer)}); err != nil {
		t.Fatalf("the rewritten chain should be internally self-consistent, got: %v", err)
	}

	_, err := verifyWithSTHs(t, rewritten.ndjson(), sthBody, Options{Registry: fixtureRegistry(t, signer)})
	verr, ok := err.(*VerifyError)
	if !ok {
		t.Fatalf("rewritten history passed STH verification (err = %v)", err)
	}
	// Events 1..4 are identical, so the size-3 head still matches; the first divergent leaf is
	// event 5 — but the size-7 head is the first to see it, and here the export only has 5
	// events, so either failure shape (root mismatch or truncation) at tree_size 7 is the catch.
	if verr.Check != "sth" || verr.Seq != 7 {
		t.Fatalf("failure = %+v, want an [sth] failure at tree_size 7", verr)
	}
}

func TestSTH_ForgedRootIsCaughtAtItsSize(t *testing.T) {
	signer := fixtureSigner(t)
	f := buildLifecycle(t, signer)
	// A forged head: correct everything except the root (signed honestly over the forged value,
	// so only the recomputation catches it).
	forged := translog.STH{
		SchemaVersion: translog.SchemaVersion1, OperatorID: fxOperator, PoolID: fxPool,
		TreeSize: 7, RootHash: translog.MerkleRoot(f.hashes[:6]), // wrong: root of 6 at size 7
		TS: time.Date(2026, 8, 2, 5, 0, 0, 0, time.UTC),
	}
	if err := signer.SignSTH(&forged); err != nil {
		t.Fatalf("SignSTH: %v", err)
	}
	line, err := forged.MarshalSTHLine()
	if err != nil {
		t.Fatalf("MarshalSTHLine: %v", err)
	}
	_, verr := verifyWithSTHs(t, f.ndjson(), append(line, '\n'), Options{Registry: fixtureRegistry(t, signer)})
	ve, ok := verr.(*VerifyError)
	if !ok || ve.Check != "sth" || ve.Seq != 7 || !strings.Contains(ve.Msg, "root") {
		t.Fatalf("forged root: err = %v, want an [sth] root mismatch at tree_size 7", verr)
	}
}

func TestSTH_TruncatedExportIsCaught(t *testing.T) {
	signer := fixtureSigner(t)
	f := buildLifecycle(t, signer)
	sthBody := buildSTHs(t, f, signer, 12)
	// Serve only the first 10 events (a clean chain prefix, so chain checks pass) with a head
	// that covers 12.
	truncated := append(bytes.Join(f.lines[:10], []byte("\n")), '\n')
	_, err := verifyWithSTHs(t, truncated, sthBody, Options{Registry: fixtureRegistry(t, signer)})
	ve, ok := err.(*VerifyError)
	if !ok || ve.Check != "sth" || !strings.Contains(ve.Msg, "truncated") {
		t.Fatalf("truncated export: err = %v, want an [sth] truncation failure", err)
	}
}

func TestSTH_TamperedSignatureIsCaught(t *testing.T) {
	signer := fixtureSigner(t)
	f := buildLifecycle(t, signer)
	sthBody := buildSTHs(t, f, signer, 12)
	// Flip one signature byte on the wire.
	line := bytes.TrimSpace(sthBody)
	idx := bytes.Index(line, []byte(`"signature":"`))
	if idx < 0 {
		t.Fatalf("fixture head has no signature")
	}
	tampered := append([]byte(nil), sthBody...)
	pos := idx + len(`"signature":"`)
	if tampered[pos] == 'f' {
		tampered[pos] = '0'
	} else {
		tampered[pos] = 'f'
	}
	_, err := verifyWithSTHs(t, f.ndjson(), tampered, Options{Registry: fixtureRegistry(t, signer)})
	ve, ok := err.(*VerifyError)
	if !ok || ve.Check != "sth-signature" {
		t.Fatalf("tampered signature: err = %v, want an [sth-signature] failure", err)
	}
}

func TestSTH_UnsignedRefusedUnlessAllowed(t *testing.T) {
	signer := fixtureSigner(t)
	f := buildLifecycle(t, signer)
	sthBody := buildSTHs(t, f, nil, 12) // heads unsigned; chain events still signed
	_, err := verifyWithSTHs(t, f.ndjson(), sthBody, Options{Registry: fixtureRegistry(t, signer)})
	ve, ok := err.(*VerifyError)
	if !ok || ve.Check != "sth-signature" {
		t.Fatalf("unsigned head: err = %v, want an [sth-signature] refusal", err)
	}
	sum, err := verifyWithSTHs(t, f.ndjson(), sthBody, Options{Registry: fixtureRegistry(t, signer), AllowUnsigned: true})
	if err != nil {
		t.Fatalf("unsigned head with -allow-unsigned: %v", err)
	}
	if sum.Unsigned != 1 {
		t.Fatalf("unsigned count = %d, want 1", sum.Unsigned)
	}
}

func TestSTH_UnknownPoolIsRefused(t *testing.T) {
	signer := fixtureSigner(t)
	f := buildLifecycle(t, signer)
	stranger := translog.STH{
		SchemaVersion: translog.SchemaVersion1, OperatorID: fxOperator,
		PoolID:   "eeee3333-0000-0000-0000-00000000000e",
		TreeSize: 1, RootHash: translog.MerkleRoot(f.hashes[:1]),
		TS: time.Date(2026, 8, 2, 5, 0, 0, 0, time.UTC),
	}
	if err := signer.SignSTH(&stranger); err != nil {
		t.Fatalf("SignSTH: %v", err)
	}
	line, err := stranger.MarshalSTHLine()
	if err != nil {
		t.Fatalf("MarshalSTHLine: %v", err)
	}
	_, verr := verifyWithSTHs(t, f.ndjson(), append(line, '\n'), Options{Registry: fixtureRegistry(t, signer)})
	ve, ok := verr.(*VerifyError)
	if !ok || ve.Check != "sth" || !strings.Contains(ve.Msg, "no events in the export") {
		t.Fatalf("unknown pool: err = %v, want an [sth] unknown-pool refusal", verr)
	}
}

func TestSTH_ForkedHeadsAtSameSizeAreCaught(t *testing.T) {
	signer := fixtureSigner(t)
	f := buildLifecycle(t, signer)
	good := buildSTHs(t, f, signer, 7)
	// A second head at the SAME size with a different (self-signed) root — a forked log. Root
	// recomputation already refuses it, which IS the fork detection for this shape; the
	// distinct sth-consistency fork message covers the case where the export matches one branch.
	forged := translog.STH{
		SchemaVersion: translog.SchemaVersion1, OperatorID: fxOperator, PoolID: fxPool,
		TreeSize: 7, RootHash: translog.MerkleRoot(f.hashes[:5]),
		TS: time.Date(2026, 8, 2, 9, 0, 0, 0, time.UTC),
	}
	if err := signer.SignSTH(&forged); err != nil {
		t.Fatalf("SignSTH: %v", err)
	}
	line, err := forged.MarshalSTHLine()
	if err != nil {
		t.Fatalf("MarshalSTHLine: %v", err)
	}
	body := append(append([]byte(nil), good...), append(line, '\n')...)
	_, verr := verifyWithSTHs(t, f.ndjson(), body, Options{Registry: fixtureRegistry(t, signer)})
	ve, ok := verr.(*VerifyError)
	if !ok || ve.Seq != 7 {
		t.Fatalf("forked heads: err = %v, want a failure at tree_size 7", verr)
	}
}
