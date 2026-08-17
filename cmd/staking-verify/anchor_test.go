package main

// STAKING-P5+ anchor-report tests: the -anchors input is matched against already -sth-verified
// heads and its digest binding is independently recomputed (see sth.go's "OpenTimestamps anchor
// reporting" section). These tests deliberately build the anchor `ref` JSON by hand (a bare
// {"digest":"..."} object, plus whatever extra fields a real pkg/attest.OTSReceiptPayload also
// carries) rather than importing pkg/attest — this binary's whole point is verifying without
// trusting the producer's own code, so the test should not lean on the exact same struct the production
// path uses either.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/wasabi-gaming/staking-verify/pkg/translog"
)

// sthTestTS is a fixed timestamp for the synthetic heads these tests build directly (not via
// buildSTHs, which stamps its own) — translog.STH.Validate requires a non-zero TS.
var sthTestTS = time.Date(2026, 8, 14, 0, 0, 0, 0, time.UTC)

// anchorRef builds a minimal, honest {"digest":"...hex..."} ref for sth, plus a couple of
// bookkeeping fields a real receipt also carries (asserting VerifyAnchors ignores them).
func anchorRef(t *testing.T, sth translog.STH) string {
	t.Helper()
	canonical, err := sth.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	sum := sha256.Sum256(canonical)
	payload := map[string]any{
		"schemaVersion": 1,
		"digest":        hex.EncodeToString(sum[:]),
		"submissions":   []any{map[string]any{"calendar": "https://a.pool.opentimestamps.org", "pending": "aabbcc"}},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal ref: %v", err)
	}
	return string(raw)
}

func TestVerifyAnchors_DigestBindingOK(t *testing.T) {
	signer := fixtureSigner(t)
	f := buildLifecycle(t, signer)
	sth := translog.STH{
		SchemaVersion: translog.SchemaVersion1, OperatorID: fxOperator, PoolID: fxPool,
		TreeSize: 12, RootHash: translog.MerkleRoot(f.hashes[:12]), TS: sthTestTS,
	}
	if err := signer.SignSTH(&sth); err != nil {
		t.Fatalf("SignSTH: %v", err)
	}
	anchors := []StakingSTHAnchorRecord{
		{PoolID: fxPool, TreeSize: 12, Kind: "opentimestamps", State: "pending", Ref: anchorRef(t, sth)},
	}
	reports, err := VerifyAnchors([]*translog.STH{&sth}, anchors)
	if err != nil {
		t.Fatalf("VerifyAnchors: %v", err)
	}
	if len(reports) != 1 {
		t.Fatalf("want 1 report, got %d", len(reports))
	}
	rep := reports[0]
	if !rep.DigestChecked || !rep.DigestOK {
		t.Fatalf("report = %+v, want digest checked and OK", rep)
	}
	if rep.State != "pending" {
		t.Fatalf("state = %q, want pending (testimony relayed as-is)", rep.State)
	}
}

// TestVerifyAnchors_DigestMismatchIsHardFailure: an anchor whose embedded digest does not match
// the actually-published head must fail loudly — this is the one thing VerifyAnchors is FOR.
func TestVerifyAnchors_DigestMismatchIsHardFailure(t *testing.T) {
	signer := fixtureSigner(t)
	f := buildLifecycle(t, signer)
	sth := translog.STH{
		SchemaVersion: translog.SchemaVersion1, OperatorID: fxOperator, PoolID: fxPool,
		TreeSize: 12, RootHash: translog.MerkleRoot(f.hashes[:12]), TS: sthTestTS,
	}
	if err := signer.SignSTH(&sth); err != nil {
		t.Fatalf("SignSTH: %v", err)
	}
	// Build a ref bound to a DIFFERENT head (tree_size 7) but claim it anchors tree_size 12.
	other := translog.STH{
		SchemaVersion: translog.SchemaVersion1, OperatorID: fxOperator, PoolID: fxPool,
		TreeSize: 7, RootHash: translog.MerkleRoot(f.hashes[:7]), TS: sthTestTS,
	}
	if err := signer.SignSTH(&other); err != nil {
		t.Fatalf("SignSTH: %v", err)
	}
	anchors := []StakingSTHAnchorRecord{
		{PoolID: fxPool, TreeSize: 12, Kind: "opentimestamps", State: "pending", Ref: anchorRef(t, other)},
	}
	_, err := VerifyAnchors([]*translog.STH{&sth}, anchors)
	ve, ok := err.(*VerifyError)
	if !ok || ve.Check != "anchor" || !strings.Contains(ve.Msg, "does not bind") {
		t.Fatalf("digest mismatch: err = %v, want an [anchor] binding failure", err)
	}
}

// TestVerifyAnchors_UnknownHeadIsRefused: an anchor naming a (pool, tree_size) with no matching
// verified head is refused outright — the wrong -sth file, or a forged anchor claim.
func TestVerifyAnchors_UnknownHeadIsRefused(t *testing.T) {
	signer := fixtureSigner(t)
	f := buildLifecycle(t, signer)
	sth := translog.STH{
		SchemaVersion: translog.SchemaVersion1, OperatorID: fxOperator, PoolID: fxPool,
		TreeSize: 12, RootHash: translog.MerkleRoot(f.hashes[:12]), TS: sthTestTS,
	}
	if err := signer.SignSTH(&sth); err != nil {
		t.Fatalf("SignSTH: %v", err)
	}
	anchors := []StakingSTHAnchorRecord{
		{PoolID: fxPool, TreeSize: 999, Kind: "opentimestamps", State: "pending", Ref: anchorRef(t, sth)},
	}
	_, err := VerifyAnchors([]*translog.STH{&sth}, anchors)
	ve, ok := err.(*VerifyError)
	if !ok || ve.Check != "anchor" || !strings.Contains(ve.Msg, "no corresponding verified STH") {
		t.Fatalf("unknown head: err = %v, want an [anchor] refusal", err)
	}
}

// TestVerifyAnchors_UnrecognizedRefShapeIsNotAnError: a ref that isn't the {"digest":...} shape
// (a different/future anchor kind) is reported as "not checked", never treated as a failure.
func TestVerifyAnchors_UnrecognizedRefShapeIsNotAnError(t *testing.T) {
	signer := fixtureSigner(t)
	f := buildLifecycle(t, signer)
	sth := translog.STH{
		SchemaVersion: translog.SchemaVersion1, OperatorID: fxOperator, PoolID: fxPool,
		TreeSize: 12, RootHash: translog.MerkleRoot(f.hashes[:12]), TS: sthTestTS,
	}
	if err := signer.SignSTH(&sth); err != nil {
		t.Fatalf("SignSTH: %v", err)
	}
	anchors := []StakingSTHAnchorRecord{
		{PoolID: fxPool, TreeSize: 12, Kind: "rfc3161", State: "confirmed", Ref: `{"tsaToken":"opaque-bytes-here"}`},
	}
	reports, err := VerifyAnchors([]*translog.STH{&sth}, anchors)
	if err != nil {
		t.Fatalf("VerifyAnchors should not fail on an unrecognized ref shape: %v", err)
	}
	if reports[0].DigestChecked {
		t.Fatalf("report should say digest was NOT checked for this ref shape")
	}
}

func TestParseAnchorStream_RoundTrip(t *testing.T) {
	body := `{"poolId":"` + fxPool + `","treeSize":12,"kind":"opentimestamps","state":"pending","ref":"{}","submittedAt":"2026-08-14T00:00:00Z"}` + "\n" +
		"\n" + // blank lines skipped
		`{"poolId":"` + fxPool + `","treeSize":22,"kind":"opentimestamps","state":"confirmed","ref":"{}","submittedAt":"2026-08-14T00:00:00Z","confirmedAt":"2026-08-14T06:00:00Z"}`
	recs, err := ParseAnchorStream(strings.NewReader(body))
	if err != nil {
		t.Fatalf("ParseAnchorStream: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("want 2 records, got %d", len(recs))
	}
	if recs[0].TreeSize != 12 || recs[1].TreeSize != 22 {
		t.Fatalf("tree sizes = %d, %d", recs[0].TreeSize, recs[1].TreeSize)
	}
	if recs[1].State != "confirmed" || recs[1].ConfirmedAt == "" {
		t.Fatalf("second record = %+v, want confirmed with a confirmedAt", recs[1])
	}
}
