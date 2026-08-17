package translog

// STAKING-P4: the WIRE form of one proof-of-liabilities proof response — owned by this package
// (not by the HTTP handler, not by the CLI) for the same reason STH lines are (sth.go's
// MarshalSTHLine): what the API serves and what cmd/staking-verify consumes must be ONE
// contract, byte-compatible by construction, with no second definition to drift.
//
//	The platform's GET …/pol/:epoch/proof endpoint renders through this doc;
//	cmd/staking-verify -pol parses and verifies through it.
//
// Verification here trusts NOTHING the server asserted beyond the two published commitments
// (rootHash, totalAmount) the proofs are verified AGAINST; the server's display aggregate
// (ownBalance), when present, must itself agree with the material or verification fails.

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"github.com/google/uuid"
	"github.com/wasabi-gaming/staking-verify/internal/money"
)

// LiabilityWireStep is one sibling step: 18-dp fixed sum, hex hash, and side.
type LiabilityWireStep struct {
	Sum    string `json:"sum"`
	Hash   string `json:"hash"`
	IsLeft bool   `json:"isLeft"`
}

// LiabilityWireLeaf is one of the caller's own leaves with its sibling path.
type LiabilityWireLeaf struct {
	LeafIndex int                 `json:"leafIndex"`
	Salt      string              `json:"salt"`
	PublicID  string              `json:"publicId"`
	Balance   string              `json:"balance"`
	Proof     []LiabilityWireStep `json:"proof"`
}

// LiabilityProofDoc is the authed proof response body. NO verdict field exists here, by design
// — material only; Verify below is what turns it into a verdict, on the CLIENT's side.
type LiabilityProofDoc struct {
	EpochID     int64               `json:"epochId"`
	EpochDate   string              `json:"epochDate"`
	PoolID      string              `json:"poolId"`
	RootHash    string              `json:"rootHash"`
	TotalAmount string              `json:"totalAmount"`
	LeafCount   int                 `json:"leafCount"`
	SaltSetID   string              `json:"saltSetId,omitempty"`
	PublishedAt string              `json:"publishedAt,omitempty"`
	OwnBalance  string              `json:"ownBalance,omitempty"`
	Leaves      []LiabilityWireLeaf `json:"leaves"`
}

// NewLiabilityWireLeaf renders one leaf + proof into the wire form (hex bytes, 18-dp amounts).
func NewLiabilityWireLeaf(leaf LiabilityLeaf, proof LiabilityProof) LiabilityWireLeaf {
	steps := make([]LiabilityWireStep, 0, len(proof.Steps))
	for _, st := range proof.Steps {
		steps = append(steps, LiabilityWireStep{
			Sum:    CanonicalAmount(st.Sum),
			Hash:   hex.EncodeToString(st.Hash),
			IsLeft: st.IsLeft,
		})
	}
	return LiabilityWireLeaf{
		LeafIndex: proof.LeafIndex,
		Salt:      hex.EncodeToString(leaf.Salt),
		PublicID:  leaf.PublicID.String(),
		Balance:   CanonicalAmount(leaf.Balance),
		Proof:     steps,
	}
}

// ParseLiabilityProofDoc decodes one saved proof response body.
func ParseLiabilityProofDoc(r io.Reader) (*LiabilityProofDoc, error) {
	var d LiabilityProofDoc
	if err := json.NewDecoder(r).Decode(&d); err != nil {
		return nil, fmt.Errorf("translog: parse liability proof doc: %w", err)
	}
	if len(d.Leaves) == 0 {
		return nil, fmt.Errorf("translog: liability proof doc carries no leaves")
	}
	return &d, nil
}

// decode rebuilds one wire leaf's typed material.
func (w LiabilityWireLeaf) decode() (LiabilityLeaf, LiabilityProof, error) {
	salt, err := hex.DecodeString(w.Salt)
	if err != nil {
		return LiabilityLeaf{}, LiabilityProof{}, fmt.Errorf("leaf %d salt is not hex: %w", w.LeafIndex, err)
	}
	publicID, err := uuid.Parse(w.PublicID)
	if err != nil {
		return LiabilityLeaf{}, LiabilityProof{}, fmt.Errorf("leaf %d publicId is not a uuid: %w", w.LeafIndex, err)
	}
	balance, err := money.Parse(w.Balance)
	if err != nil {
		return LiabilityLeaf{}, LiabilityProof{}, fmt.Errorf("leaf %d balance is not a decimal: %w", w.LeafIndex, err)
	}
	leaf := LiabilityLeaf{Salt: salt, PublicID: publicID, Balance: balance}
	proof := LiabilityProof{LeafIndex: w.LeafIndex}
	for i, st := range w.Proof {
		h, err := hex.DecodeString(st.Hash)
		if err != nil {
			return LiabilityLeaf{}, LiabilityProof{}, fmt.Errorf("leaf %d proof step %d hash is not hex: %w", w.LeafIndex, i, err)
		}
		sum, err := money.Parse(st.Sum)
		if err != nil {
			return LiabilityLeaf{}, LiabilityProof{}, fmt.Errorf("leaf %d proof step %d sum is not a decimal: %w", w.LeafIndex, i, err)
		}
		proof.Steps = append(proof.Steps, LiabilityProofStep{Sum: sum, Hash: h, IsLeft: st.IsLeft})
	}
	return leaf, proof, nil
}

// Verify re-verifies every own leaf against the doc's published (rootHash, totalAmount) with
// VerifyLiabilityProof, and — when the doc carries an ownBalance — requires it to equal the Σ of
// the balances actually proven. Returns that Σ. The first failure aborts with the leaf index and
// the failing check.
func (d *LiabilityProofDoc) Verify() (money.Amount, error) {
	root, err := hex.DecodeString(d.RootHash)
	if err != nil {
		return money.Zero, fmt.Errorf("translog: rootHash is not hex: %w", err)
	}
	total, err := money.Parse(d.TotalAmount)
	if err != nil {
		return money.Zero, fmt.Errorf("translog: totalAmount is not a decimal: %w", err)
	}
	own := money.Zero
	for _, wire := range d.Leaves {
		leaf, proof, err := wire.decode()
		if err != nil {
			return money.Zero, fmt.Errorf("translog: %w", err)
		}
		ok, err := VerifyLiabilityProof(leaf, proof, root, total)
		if err != nil {
			return money.Zero, fmt.Errorf("translog: leaf %d proof is malformed: %w", wire.LeafIndex, err)
		}
		if !ok {
			return money.Zero, fmt.Errorf("translog: leaf %d FAILED verification against the published root/total", wire.LeafIndex)
		}
		own = own.Add(leaf.Balance)
	}
	if d.OwnBalance != "" {
		claimed, err := money.Parse(d.OwnBalance)
		if err != nil {
			return money.Zero, fmt.Errorf("translog: ownBalance is not a decimal: %w", err)
		}
		if !claimed.Equal(own) {
			return money.Zero, fmt.Errorf("translog: asserted ownBalance %s does not equal the proven leaf sum %s",
				d.OwnBalance, money.String(own))
		}
	}
	return own, nil
}
