package main

// STAKING-P4: proof-of-liabilities verification — the -pol half of the verifier.
//
// Input: the JSON response body of GET /api/v1/staking/transparency/pol/:epoch/proof, saved
// verbatim to a file. The wire form AND the verification both live in pkg/translog
// (LiabilityProofDoc — the same one-contract rule as STH lines), so this file is only the CLI
// shell: parse, verify, report.
//
// What Verify establishes, without trusting any server assertion beyond the two published
// commitments (rootHash, totalAmount): every own leaf's hash recomputed from (salt, public_id,
// balance); every parent's sum RE-DERIVED (never trusted) and re-hashed with the sums inside
// the preimage — exactly the walk that catches a Maxwell/Todd forged-sum tree; the final hash
// equal to the published root; the accumulated sum equal to the published total; and the
// response's own display aggregate (ownBalance) equal to the Σ of the balances actually proven.

import (
	"encoding/hex"
	"fmt"
	"io"

	"github.com/wasabi-gaming/staking-verify/internal/money"
	"github.com/wasabi-gaming/staking-verify/pkg/translog"
)

// PoLSummary is the successful -pol verification report.
type PoLSummary struct {
	PoolID      string
	EpochID     int64
	EpochDate   string
	LeafCount   int
	OwnLeaves   int
	OwnBalance  money.Amount
	TotalAmount money.Amount
	RootHash    string
}

// VerifyPoLStream parses and verifies one saved proof response.
func VerifyPoLStream(r io.Reader) (*PoLSummary, error) {
	doc, err := translog.ParseLiabilityProofDoc(r)
	if err != nil {
		return nil, err
	}
	own, err := doc.Verify()
	if err != nil {
		return nil, err
	}
	total, err := money.Parse(doc.TotalAmount)
	if err != nil {
		return nil, fmt.Errorf("pol: totalAmount is not a decimal: %w", err)
	}
	return &PoLSummary{
		PoolID: doc.PoolID, EpochID: doc.EpochID, EpochDate: doc.EpochDate,
		LeafCount: doc.LeafCount, OwnLeaves: len(doc.Leaves),
		OwnBalance: own, TotalAmount: total, RootHash: doc.RootHash,
	}, nil
}

// WritePoLSummary prints the successful report.
func WritePoLSummary(w io.Writer, sum *PoLSummary) {
	fmt.Fprintf(w, "PoL: %d own leaf/leaves verified against the published root for epoch %d (%s), pool %s\n",
		sum.OwnLeaves, sum.EpochID, sum.EpochDate, sum.PoolID)
	fmt.Fprintf(w, "PoL: own counted balance %s of published total %s (%d leaves in tree)\n",
		money.String(sum.OwnBalance), money.String(sum.TotalAmount), sum.LeafCount)
	if root, err := hex.DecodeString(sum.RootHash); err == nil {
		fmt.Fprintf(w, "PoL: root %s\n", hex.EncodeToString(root))
	}
}
