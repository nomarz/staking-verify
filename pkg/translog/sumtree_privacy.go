package translog

// STAKING-P4: leaf-generation privacy mitigation for the summation tree.
//
// A plain summation tree LEAKS: every inclusion proof exposes the sums of the sibling subtrees
// along its path, which narrows what an observer can infer about other accounts' balances. That
// is the known residual limitation of the Maxwell/Todd scheme even with sumtree.go's sum-in-hash
// fix — the fix stops FORGERY; it does not stop LEAKAGE. Full elimination needs Pedersen
// commitments + range proofs (Provisions-style), explicitly out of scope for this phase; this
// file MITIGATES instead:
//
//  1. SPLIT — each real user account's balance is split across k ∈ {1..4} leaves (k drawn per
//     account per generation), with RANDOM partition sizes that sum exactly to the real balance
//     — never balance/k evenly, since evenly-split leaves are themselves a recognizable pattern.
//     Each split leaf gets its OWN LiabilitySaltSize random salt.
//  2. PADDING — house-owned accounts (the pool's kind='platform' and kind='genesis' rows —
//     REAL accounts whose balances are genuinely part of the total) are split across a much
//     wider k ∈ {8..16}. Their extra leaves are the padding: interleaved among user leaves they
//     obscure both the per-user leaf multiplicity and the true user count, while reassigning
//     only balance that was ALREADY counted — padding never inflates the total (asserted by the
//     tests: Total() == Σ input balances regardless of splitting). A house account whose balance
//     is zero still emits its k leaves, all zero-valued: position without economic weight.
//     Padding is never attributed to a fabricated identity — a leaf attributed to nobody real
//     would itself be detectable and would not genuinely be part of the total.
//  3. SHUFFLE — the combined leaf list is Fisher-Yates shuffled with crypto-grade randomness, so
//     an account's split leaves are not adjacent and leaf ORDER is not a stable function of
//     account identity across generations (a stable pattern would correlate accounts across
//     epochs on its own).
//
// The tree/proof machinery in sumtree.go neither knows nor cares whether a leaf is a whole
// balance, a split fragment, or house padding — a verifier checking their own proof sees only
// their own leaf material and the sibling path.
//
// PADDING SIZE RATIONALE (k ∈ {8..16} per house account, i.e. 16..32 house leaves per pool from
// the two house rows): every pool always carries the platform + genesis rows, so even a pool
// with a handful of stakers gets a padding floor that dominates the user leaf count, while the
// worst case adds only ~32 leaves — negligible against tree size at any scale where leakage
// would otherwise be meaningful.

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"

	"github.com/google/uuid"
	"github.com/wasabi-gaming/staking-verify/internal/money"
)

// User accounts split across 1..4 leaves; house accounts across 8..16 (the padding).
const (
	liabilityUserSplitMin  = 1
	liabilityUserSplitMax  = 4
	liabilityHouseSplitMin = 8
	liabilityHouseSplitMax = 16
)

// LiabilityAccountInput is one account to be represented in the tree. House marks the pool's
// own platform/genesis holdings (they get the padding-heavy split above).
type LiabilityAccountInput struct {
	PublicID uuid.UUID
	Balance  money.Amount
	House    bool
}

// GeneratedLiabilityLeaf is one output leaf plus the assignment data the producer persists so
// it can later serve the account's own leaves back to it: which input account the leaf belongs
// to and whether it is house padding.
type GeneratedLiabilityLeaf struct {
	Leaf LiabilityLeaf
	// AccountIndex indexes into the accounts slice given to GenerateLiabilityLeaves.
	AccountIndex int
	// IsPadding marks a leaf attributed to a House account — real balance, but present (in its
	// multiplicity) to obscure user leaf statistics.
	IsPadding bool
}

// GenerateLiabilityLeaves builds the split + padded + shuffled leaf list for one tree. rnd is
// the randomness source (nil = crypto/rand.Reader; injectable ONLY so tests can starve it —
// production callers pass nil). Refuses negative balances outright, the same rule as
// BuildLiabilityTree.
//
// Deliberately NON-deterministic: two calls over the same accounts yield different salts,
// splits and order — determinism across epochs would itself leak account correlation.
func GenerateLiabilityLeaves(accounts []LiabilityAccountInput, rnd io.Reader) ([]GeneratedLiabilityLeaf, error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	if len(accounts) == 0 {
		return nil, fmt.Errorf("%w: no accounts", ErrLiabilityLeaf)
	}
	var out []GeneratedLiabilityLeaf
	for i, acct := range accounts {
		if acct.Balance.IsNegative() {
			return nil, fmt.Errorf("%w: account %d (%s) has negative balance %s", ErrLiabilityLeaf,
				i, acct.PublicID, CanonicalAmount(acct.Balance))
		}
		lo, hi := liabilityUserSplitMin, liabilityUserSplitMax
		if acct.House {
			lo, hi = liabilityHouseSplitMin, liabilityHouseSplitMax
		}
		k, err := randIntIn(rnd, lo, hi)
		if err != nil {
			return nil, err
		}
		parts, err := randPartition(rnd, acct.Balance, k)
		if err != nil {
			return nil, err
		}
		for _, part := range parts {
			salt := make([]byte, LiabilitySaltSize)
			if _, err := io.ReadFull(rnd, salt); err != nil {
				return nil, fmt.Errorf("translog: read salt: %w", err)
			}
			out = append(out, GeneratedLiabilityLeaf{
				Leaf:         LiabilityLeaf{Salt: salt, PublicID: acct.PublicID, Balance: part},
				AccountIndex: i,
				IsPadding:    acct.House,
			})
		}
	}
	// Fisher-Yates over the combined list — split leaves must not stay adjacent, and order must
	// not encode account identity.
	for i := len(out) - 1; i > 0; i-- {
		j, err := randIntIn(rnd, 0, i)
		if err != nil {
			return nil, err
		}
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// randIntIn returns a uniform random int in [lo, hi] from rnd.
func randIntIn(rnd io.Reader, lo, hi int) (int, error) {
	if hi <= lo {
		return lo, nil
	}
	n, err := rand.Int(rnd, big.NewInt(int64(hi-lo+1)))
	if err != nil {
		return 0, fmt.Errorf("translog: read random int: %w", err)
	}
	return lo + int(n.Int64()), nil
}

// randPartition splits total into k non-negative parts that sum EXACTLY to total, with random
// (weight-proportional) sizes. Each part i < k-1 is floor(total * w_i / W) at AmountScale — a
// truncation, so the running sum never exceeds total and the exact remainder lands in the last
// part. Zero-valued parts are possible and fine (a real-account zero leaf is still a position
// in the tree).
func randPartition(rnd io.Reader, total money.Amount, k int) ([]money.Amount, error) {
	if k <= 1 || total.IsZero() {
		parts := make([]money.Amount, k)
		if k > 0 {
			parts[0] = total
		}
		for i := 1; i < k; i++ {
			parts[i] = money.Zero
		}
		return parts, nil
	}
	weights := make([]int64, k)
	var sum int64
	for i := range weights {
		var buf [4]byte
		if _, err := io.ReadFull(rnd, buf[:]); err != nil {
			return nil, fmt.Errorf("translog: read partition weight: %w", err)
		}
		// 1..2^31: never zero, no overflow concerns on the sum for k <= 16.
		weights[i] = int64(binary.BigEndian.Uint32(buf[:])>>1) + 1
		sum += weights[i]
	}
	w := money.FromInt(sum)
	parts := make([]money.Amount, 0, k)
	remaining := total
	for i := 0; i < k-1; i++ {
		q, _ := total.Mul(money.FromInt(weights[i])).QuoRem(w, AmountScale)
		parts = append(parts, q)
		remaining = remaining.Sub(q)
	}
	parts = append(parts, remaining)
	if remaining.IsNegative() {
		// Unreachable by construction (each part truncates its exact share), kept as a hard
		// guard: a negative part must never survive into a leaf.
		return nil, fmt.Errorf("%w: partition produced negative remainder %s", ErrLiabilityLeaf, CanonicalAmount(remaining))
	}
	return parts, nil
}
