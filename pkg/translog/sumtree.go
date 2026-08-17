package translog

// STAKING-P4: the summation Merkle tree ("proof of liabilities") — a DIFFERENT tree shape from
// merkle.go's plain RFC 6962 tree, and the difference is not optional: every interior node
// carries the SUM of its subtree's balances INSIDE its hash preimage.
//
// Shapes (SHA-256 throughout; amounts serialized via CanonicalAmount — exactly AmountScale=18
// fractional digits, plain decimal, no exponent, matching this package's money discipline):
//
//	leaf(salt, public_id, balance) = SHA256(0x00 || salt[16] || public_id[16] || CanonicalAmount(balance))
//	node(sumL, hashL, sumR, hashR) = SHA256(0x01 || u16be(len(sL)) || sL || hashL[32]
//	                                             || u16be(len(sR)) || sR || hashR[32])
//	  where sL = CanonicalAmount(sumL), sR = CanonicalAmount(sumR)
//
// THE ONE HARD SECURITY REQUIREMENT (Maxwell/Todd): the child SUMS are part of what gets hashed,
// never metadata carried alongside the hash. With sums outside the preimage, a dishonest
// tree-builder can declare an interior node's sum as max(left, right) instead of left + right,
// forge the sibling subtree per-request so each INDIVIDUAL proof still verifies, and publish a
// total that understates real liabilities — while every staker who checks their own proof sees
// it pass. Binding the sums into the hash makes that forgery detectable: the verifier re-derives
// every parent's sum as sumSelf + sumSibling (it never trusts a declared parent sum) and feeds
// that derived sum into the next level's preimage, so a tree built over forged sums cannot
// reproduce its own published root under an honest verifier.
//
// ENCODING UNAMBIGUITY: within a leaf preimage, salt and public_id are FIXED-width (16 bytes
// each, enforced) and the variable-length amount comes last — one parse. Within a node preimage,
// each variable-length sum carries a 2-byte big-endian length prefix and each hash is exactly 32
// bytes — one parse. Domain separation from merkle.go's trees is structural on top of the shared
// 0x00/0x01 prefixes: a P3 leaf preimage is exactly 33 bytes (0x00 || 32-byte entry hash) while
// a liability leaf preimage is >= 34 (1+16+16+at least one amount char); a P3 node preimage is
// exactly 65 bytes while a liability node preimage is >= 70.
//
// NEGATIVE BALANCES ARE REFUSED EVERYWHERE — build side and verify side. A negative leaf lets a
// dishonest operator cancel real liabilities elsewhere in the sum while the total still
// "balances"; the correct response is refusing to build (or accept) the tree at all, never
// clamping to zero or skipping the leaf. The verifier equally rejects any negative SIBLING sum
// in a proof, or a forged path could smuggle the same cancellation in at verify time.
//
// Split rule: RFC 6962's largest-power-of-two-below-n split, an odd node PROMOTED UNCHANGED —
// never self-paired — the same shape (and the same CVE-2012-2459 reasoning) as merkle.go.
//
// This file is pure: no database, no clock, no I/O, no casino concept beyond "a public account
// id and a balance" — cmd/staking-verify verifies published proofs with EXACTLY these functions.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/wasabi-gaming/staking-verify/internal/money"
)

// LiabilitySaltSize is the REQUIRED length of every leaf salt. Fixed width is what keeps the
// leaf preimage parse-unambiguous (see the file header); 16 random bytes is far beyond
// brute-force range for hiding a balance behind its hash.
const LiabilitySaltSize = 16

// liabilityLeafPrefix / liabilityNodePrefix are the domain separators (see the file header for
// why sharing merkle.go's byte VALUES is still collision-free).
const (
	liabilityLeafPrefix byte = 0x00
	liabilityNodePrefix byte = 0x01
)

// ErrLiabilityLeaf guards malformed leaves: wrong salt length, or a NEGATIVE balance (refused
// outright — see the file header).
var ErrLiabilityLeaf = errors.New("translog: invalid liability leaf")

// ErrLiabilityProof guards malformed proof material: wrong hash length, or a NEGATIVE sibling
// sum (the verify-side half of the negative-balance refusal).
var ErrLiabilityProof = errors.New("translog: invalid liability proof")

// ErrLiabilityRange guards out-of-range proof requests.
var ErrLiabilityRange = errors.New("translog: liability leaf index out of range")

// LiabilityLeaf is one leaf's full preimage material: a per-leaf random salt, the account's
// PUBLIC id (stake_accounts.public_id — never an internal id), and this leaf's balance share.
// One real account may be split across several leaves (sumtree_privacy.go); the tree neither
// knows nor cares.
type LiabilityLeaf struct {
	Salt     []byte
	PublicID uuid.UUID
	Balance  money.Amount
}

// validate rejects what must never enter a preimage.
func (l LiabilityLeaf) validate() error {
	if len(l.Salt) != LiabilitySaltSize {
		return fmt.Errorf("%w: salt is %d bytes, want %d", ErrLiabilityLeaf, len(l.Salt), LiabilitySaltSize)
	}
	if l.Balance.IsNegative() {
		return fmt.Errorf("%w: negative balance %s (a negative leaf cancels real liabilities; refuse, never clamp)",
			ErrLiabilityLeaf, CanonicalAmount(l.Balance))
	}
	return nil
}

// LiabilityLeafHash computes leaf(salt, public_id, balance). Errors on a malformed leaf rather
// than hashing garbage.
func LiabilityLeafHash(l LiabilityLeaf) ([]byte, error) {
	if err := l.validate(); err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write([]byte{liabilityLeafPrefix})
	h.Write(l.Salt)
	id := l.PublicID // uuid.UUID is [16]byte
	h.Write(id[:])
	h.Write([]byte(CanonicalAmount(l.Balance)))
	return h.Sum(nil), nil
}

// liabilityNodeHash computes node(sumL, hashL, sumR, hashR) — the sums INSIDE the preimage.
func liabilityNodeHash(sumL money.Amount, hashL []byte, sumR money.Amount, hashR []byte) []byte {
	sL := []byte(CanonicalAmount(sumL))
	sR := []byte(CanonicalAmount(sumR))
	var lenBuf [2]byte
	h := sha256.New()
	h.Write([]byte{liabilityNodePrefix})
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(sL))) //nolint:gosec // canonical decimal strings are tiny
	h.Write(lenBuf[:])
	h.Write(sL)
	h.Write(hashL)
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(sR))) //nolint:gosec // canonical decimal strings are tiny
	h.Write(lenBuf[:])
	h.Write(sR)
	h.Write(hashR)
	return h.Sum(nil)
}

// liabilityNode is one computed tree position: its subtree sum and hash.
type liabilityNode struct {
	sum  money.Amount
	hash []byte
}

// LiabilityTree is a fully built summation tree. Build once with BuildLiabilityTree; the levels
// are retained so ProofFor is O(log n) lookups rather than a rebuild.
type LiabilityTree struct {
	leaves []LiabilityLeaf
	// levels[0] is the leaf level (hash + own balance as sum); each higher level pairs
	// left-to-right, promoting an unpaired last node unchanged. levels[len-1] has exactly one
	// node: the root.
	levels [][]liabilityNode
}

// BuildLiabilityTree builds the tree over the given leaves, in the given order. Refuses an empty
// leaf list, any malformed salt, and ANY negative balance (see the file header).
func BuildLiabilityTree(leaves []LiabilityLeaf) (*LiabilityTree, error) {
	if len(leaves) == 0 {
		return nil, fmt.Errorf("%w: no leaves", ErrLiabilityLeaf)
	}
	level := make([]liabilityNode, len(leaves))
	for i, leaf := range leaves {
		h, err := LiabilityLeafHash(leaf)
		if err != nil {
			return nil, fmt.Errorf("leaf %d: %w", i, err)
		}
		level[i] = liabilityNode{sum: leaf.Balance, hash: h}
	}
	levels := [][]liabilityNode{level}
	for len(level) > 1 {
		next := make([]liabilityNode, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				// Odd node: PROMOTED UNCHANGED — never self-paired (merkle.go's rule, same
				// reasoning).
				next = append(next, level[i])
				continue
			}
			l, r := level[i], level[i+1]
			next = append(next, liabilityNode{
				sum:  l.sum.Add(r.sum),
				hash: liabilityNodeHash(l.sum, l.hash, r.sum, r.hash),
			})
		}
		levels = append(levels, next)
		level = next
	}
	cp := make([]LiabilityLeaf, len(leaves))
	copy(cp, leaves)
	return &LiabilityTree{leaves: cp, levels: levels}, nil
}

// Root returns the tree's root hash (a copy).
func (t *LiabilityTree) Root() []byte {
	root := t.levels[len(t.levels)-1][0]
	return append([]byte(nil), root.hash...)
}

// Total returns the root sum: Σ of every leaf balance — the number the root hash publicly
// commits to.
func (t *LiabilityTree) Total() money.Amount {
	return t.levels[len(t.levels)-1][0].sum
}

// LeafCount returns how many leaves the tree was built over.
func (t *LiabilityTree) LeafCount() int { return len(t.leaves) }

// Leaf returns the leaf at index (a copy of its material).
func (t *LiabilityTree) Leaf(index int) (LiabilityLeaf, error) {
	if index < 0 || index >= len(t.leaves) {
		return LiabilityLeaf{}, fmt.Errorf("%w: index %d, leaf count %d", ErrLiabilityRange, index, len(t.leaves))
	}
	l := t.leaves[index]
	l.Salt = append([]byte(nil), l.Salt...)
	return l, nil
}

// LiabilityProofStep is one sibling on the path from a leaf to the root: the sibling subtree's
// SUM and HASH, and which side it sits on. The sum is proof material the verifier re-hashes —
// never a value to trust on its own.
type LiabilityProofStep struct {
	Sum    money.Amount
	Hash   []byte
	IsLeft bool // true = the sibling is the LEFT child at this level (the prover's node is right)
}

// LiabilityProof is one leaf's sibling path. LeafIndex is carried for display/serving; the hash
// walk itself takes each step's side from IsLeft — with the sums bound into every preimage, any
// side arrangement that verifies is one the committed tree actually contains.
type LiabilityProof struct {
	LeafIndex int
	Steps     []LiabilityProofStep
}

// ProofFor returns the sibling path for the leaf at index. A level where the node is promoted
// unpaired contributes NO step (the verifier's walk simply carries the running (sum, hash) up).
func (t *LiabilityTree) ProofFor(index int) (LiabilityProof, error) {
	if index < 0 || index >= len(t.leaves) {
		return LiabilityProof{}, fmt.Errorf("%w: index %d, leaf count %d", ErrLiabilityRange, index, len(t.leaves))
	}
	proof := LiabilityProof{LeafIndex: index}
	pos := index
	for lvl := 0; lvl < len(t.levels)-1; lvl++ {
		level := t.levels[lvl]
		var siblingPos int
		var isLeft bool
		if pos%2 == 0 {
			siblingPos, isLeft = pos+1, false
		} else {
			siblingPos, isLeft = pos-1, true
		}
		if siblingPos < len(level) {
			sib := level[siblingPos]
			proof.Steps = append(proof.Steps, LiabilityProofStep{
				Sum:    sib.sum,
				Hash:   append([]byte(nil), sib.hash...),
				IsLeft: isLeft,
			})
		}
		// else: promoted unchanged — no step at this level.
		pos /= 2
	}
	return proof, nil
}

// VerifyLiabilityProof checks one leaf's inclusion against a published (root, expectedTotal)
// pair. It recomputes the leaf hash from the leaf material, walks the path re-deriving each
// parent's SUM (sumSelf + sumSibling — declared parent sums are never accepted) and HASH (the
// derived sums inside the preimage), and requires BOTH that the final hash equals root AND that
// the fully-accumulated sum equals expectedTotal exactly.
//
// Rejections: a malformed leaf or proof (negative balance, negative sibling sum, wrong salt/hash
// length) returns (false, error); an honest-shape proof that simply does not verify returns
// (false, nil). Only (true, nil) means the leaf is committed under this root and counted in this
// total.
func VerifyLiabilityProof(leaf LiabilityLeaf, proof LiabilityProof, root []byte, expectedTotal money.Amount) (bool, error) {
	leafHash, err := LiabilityLeafHash(leaf)
	if err != nil {
		return false, err
	}
	if len(root) != HashSize {
		return false, fmt.Errorf("%w: root is %d bytes, want %d", ErrLiabilityProof, len(root), HashSize)
	}
	if expectedTotal.IsNegative() {
		return false, fmt.Errorf("%w: negative expected total %s", ErrLiabilityProof, CanonicalAmount(expectedTotal))
	}
	sum, hash := leaf.Balance, leafHash
	for i, step := range proof.Steps {
		if len(step.Hash) != HashSize {
			return false, fmt.Errorf("%w: step %d hash is %d bytes, want %d", ErrLiabilityProof, i, len(step.Hash), HashSize)
		}
		if step.Sum.IsNegative() {
			// The verify-side half of the negative-balance refusal: a forged negative sibling
			// sum would cancel real liabilities out of the accumulated total.
			return false, fmt.Errorf("%w: step %d has negative sibling sum %s", ErrLiabilityProof, i, CanonicalAmount(step.Sum))
		}
		if step.IsLeft {
			hash = liabilityNodeHash(step.Sum, step.Hash, sum, hash)
		} else {
			hash = liabilityNodeHash(sum, hash, step.Sum, step.Hash)
		}
		sum = sum.Add(step.Sum)
	}
	return bytes.Equal(hash, root) && sum.Equal(expectedTotal), nil
}
