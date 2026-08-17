package translog

// The RFC 6962 Merkle tree over one pool's event-log entry_hash sequence —
// pure functions and one small incremental accumulator, no database, no clock, no I/O, matching
// this package's charter (see canonical.go's header). cmd/staking-verify and the production
// publisher both run EXACTLY these functions; there is no second implementation to drift.
//
// Shapes (RFC 6962 §2.1, domain-separated so a leaf hash, an interior node hash, and a P2 chain
// hash can never be confused for one another — chain.go's 0x00 prefix is over a DIFFERENT
// preimage layout, prev_hash||canonical, never 32-byte||32-byte):
//
//	MTH({})     = SHA-256()                       // the empty tree: hash of the empty string
//	leaf(e)     = SHA-256(0x00 || e)              // e = one event-log entry_hash
//	node(l, r)  = SHA-256(0x01 || l || r)
//
// An odd node at any level is PROMOTED UNCHANGED to the next level — never paired with itself.
// Self-pairing (Bitcoin's duplicate-the-last-node) is exactly CVE-2012-2459: two distinct leaf
// lists produce one root, so an attacker can present a "different" log with the same head. RFC
// 6962's largest-power-of-two split admits no such collision, and every function here follows it.
//
// Proof GENERATION follows RFC 6962 §2.1.1 (PATH) and §2.1.2 (PROOF/SUBPROOF) literally, as
// recursion over the leaf list. Proof VERIFICATION follows RFC 9162 §2.1.3.2 and §2.1.4.2's
// iterative algorithms. Deliberately two independent formulations of the same spec: the tests
// round-trip every generator through its verifier across exhaustive small trees, so a bug in
// either formulation breaks the round trip instead of hiding in a shared helper.

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/bits"
)

// merkleLeafPrefix / merkleNodePrefix are RFC 6962's domain separators.
const (
	merkleLeafPrefix byte = 0x00
	merkleNodePrefix byte = 0x01
)

// ErrMerkleRange guards out-of-range proof requests (index/size outside the leaf list).
var ErrMerkleRange = errors.New("translog: merkle index/size out of range")

// EmptyRoot returns MTH({}): SHA-256 of the empty string. Defined (rather than nil) so an empty
// tree has exactly one canonical head; the producer never publishes an STH over an empty tree,
// but the verifier still needs the value to be unambiguous.
func EmptyRoot() []byte {
	h := sha256.Sum256(nil)
	return h[:]
}

// LeafHash computes leaf(entryHash) = SHA-256(0x00 || entryHash).
func LeafHash(entryHash []byte) []byte {
	h := sha256.New()
	h.Write([]byte{merkleLeafPrefix})
	h.Write(entryHash)
	return h.Sum(nil)
}

// nodeHash computes node(l, r) = SHA-256(0x01 || l || r).
func nodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{merkleNodePrefix})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// MerkleRoot computes MTH over the given entry hashes (leaf INPUTS — LeafHash is applied here).
// Empty input returns EmptyRoot().
func MerkleRoot(entryHashes [][]byte) []byte {
	if len(entryHashes) == 0 {
		return EmptyRoot()
	}
	return mth(leafHashes(entryHashes))
}

// leafHashes maps entry hashes to their leaf hashes.
func leafHashes(entryHashes [][]byte) [][]byte {
	out := make([][]byte, len(entryHashes))
	for i, e := range entryHashes {
		out[i] = LeafHash(e)
	}
	return out
}

// mth is RFC 6962 §2.1's MTH over ALREADY-LEAF-HASHED nodes: split at the largest power of two
// smaller than n, never self-pair. Callers guarantee len(d) >= 1.
func mth(d [][]byte) []byte {
	if len(d) == 1 {
		return d[0]
	}
	k := largestPowerOfTwoBelow(len(d))
	return nodeHash(mth(d[:k]), mth(d[k:]))
}

// largestPowerOfTwoBelow returns the largest power of two STRICTLY smaller than n (n >= 2).
func largestPowerOfTwoBelow(n int) int {
	return 1 << (bits.Len(uint(n-1)) - 1)
}

// InclusionProof returns RFC 6962 §2.1.1's PATH(index, D[n]) — the audit path proving
// entryHashes[index] is in the tree over all of entryHashes. The proof carries interior/leaf
// hashes bottom-up; verify with VerifyInclusion(LeafHash(entryHashes[index]), index, n, proof,
// MerkleRoot(entryHashes)).
func InclusionProof(entryHashes [][]byte, index int) ([][]byte, error) {
	if index < 0 || index >= len(entryHashes) {
		return nil, fmt.Errorf("%w: index %d, tree size %d", ErrMerkleRange, index, len(entryHashes))
	}
	return path(leafHashes(entryHashes), index), nil
}

// path is PATH(m, D[n]) over leaf-hashed nodes.
func path(d [][]byte, m int) [][]byte {
	if len(d) == 1 {
		return [][]byte{}
	}
	k := largestPowerOfTwoBelow(len(d))
	if m < k {
		return append(path(d[:k], m), mth(d[k:]))
	}
	return append(path(d[k:], m-k), mth(d[:k]))
}

// VerifyInclusion checks an audit path: recomputes the root from leafHash (the LEAF hash —
// LeafHash(entry_hash), not the raw entry hash) at index in a tree of treeSize and compares it
// to root. RFC 9162 §2.1.3.2's iterative algorithm.
func VerifyInclusion(leafHash []byte, index int, treeSize int, proof [][]byte, root []byte) bool {
	if index < 0 || treeSize <= 0 || index >= treeSize {
		return false
	}
	if len(leafHash) != HashSize || len(root) != HashSize {
		return false
	}
	fn, sn := uint64(index), uint64(treeSize-1) //nolint:gosec // both checked non-negative above
	r := leafHash
	for _, p := range proof {
		if len(p) != HashSize || sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			r = nodeHash(p, r)
			for fn != 0 && fn&1 == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = nodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && bytes.Equal(r, root)
}

// ConsistencyProof returns RFC 6962 §2.1.2's PROOF(oldSize, D[newSize]) — the proof that the
// tree over entryHashes[:newSize] is a strict append-only extension of the tree over
// entryHashes[:oldSize]. oldSize must be >= 1 (RFC 6962 does not define consistency FROM the
// empty tree, and the producer never publishes an empty STH to be consistent from); oldSize ==
// newSize yields the empty proof (verified against equal roots).
func ConsistencyProof(entryHashes [][]byte, oldSize, newSize int) ([][]byte, error) {
	if oldSize < 1 || oldSize > newSize || newSize > len(entryHashes) {
		return nil, fmt.Errorf("%w: consistency %d -> %d over %d leaves", ErrMerkleRange, oldSize, newSize, len(entryHashes))
	}
	if oldSize == newSize {
		return [][]byte{}, nil
	}
	return subProof(leafHashes(entryHashes[:newSize]), oldSize, true), nil
}

// subProof is SUBPROOF(m, D[n], b) over leaf-hashed nodes, 1 <= m <= n.
func subProof(d [][]byte, m int, completeSubtree bool) [][]byte {
	if m == len(d) {
		if completeSubtree {
			return [][]byte{}
		}
		return [][]byte{mth(d)}
	}
	k := largestPowerOfTwoBelow(len(d))
	if m <= k {
		return append(subProof(d[:k], m, completeSubtree), mth(d[k:]))
	}
	return append(subProof(d[k:], m-k, false), mth(d[:k]))
}

// VerifyConsistency checks that the tree of newSize/newRoot is a strict append-only extension
// of the tree of oldSize/oldRoot, given PROOF(oldSize, D[newSize]). RFC 9162 §2.1.4.2's
// iterative algorithm. oldSize must be >= 1 (see ConsistencyProof); oldSize == newSize requires
// an empty proof and equal roots.
func VerifyConsistency(oldRoot []byte, oldSize int, newRoot []byte, newSize int, proof [][]byte) bool {
	if oldSize < 1 || newSize < oldSize {
		return false
	}
	if len(oldRoot) != HashSize || len(newRoot) != HashSize {
		return false
	}
	if oldSize == newSize {
		return len(proof) == 0 && bytes.Equal(oldRoot, newRoot)
	}
	for _, p := range proof {
		if len(p) != HashSize {
			return false
		}
	}
	// RFC 9162 step 1: when the old tree is a perfect subtree of the new one, its root is not in
	// the proof (the generator's SUBPROOF(m, D[m], true) = {}) — prepend it.
	nodes := proof
	if oldSize&(oldSize-1) == 0 {
		nodes = append([][]byte{oldRoot}, proof...)
	}
	if len(nodes) == 0 {
		return false
	}
	fn, sn := uint64(oldSize-1), uint64(newSize-1) //nolint:gosec // both checked positive above
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr := nodes[0], nodes[0]
	for _, c := range nodes[1:] {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			fr = nodeHash(c, fr)
			sr = nodeHash(c, sr)
			for fn != 0 && fn&1 == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = nodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && bytes.Equal(fr, oldRoot) && bytes.Equal(sr, newRoot)
}

// Frontier is the incremental form of MerkleRoot: the O(log n) "compact range" of perfect
// subtree roots (one per set bit of the size, tallest first). Appending one leaf touches only
// the O(log n) merge path, and Root() folds the range right-to-left — by construction identical
// to MerkleRoot over the same leaves (asserted exhaustively by the tests). The production STH
// publisher keeps one Frontier per pool so the steady-state publish reads only the events
// appended since the last one, instead of rebuilding the whole tree.
//
// Not safe for concurrent use; callers serialize (the publisher holds its own lock).
type Frontier struct {
	// roots[i] is the root of a perfect subtree; sizes[i] its leaf count. sizes is strictly
	// decreasing, each a power of two — the binary decomposition of size.
	roots [][]byte
	sizes []uint64
	size  int64
}

// NewFrontier returns an empty Frontier.
func NewFrontier() *Frontier { return &Frontier{} }

// Size returns how many leaves have been appended.
func (f *Frontier) Size() int64 { return f.size }

// Append absorbs one more entry hash (leaf input — LeafHash is applied here).
func (f *Frontier) Append(entryHash []byte) {
	node := LeafHash(entryHash)
	f.roots = append(f.roots, node)
	f.sizes = append(f.sizes, 1)
	// Binary carry: merge equal-sized neighbours until sizes is strictly decreasing again.
	for n := len(f.roots); n >= 2 && f.sizes[n-1] == f.sizes[n-2]; n = len(f.roots) {
		f.roots[n-2] = nodeHash(f.roots[n-2], f.roots[n-1])
		f.sizes[n-2] *= 2
		f.roots = f.roots[:n-1]
		f.sizes = f.sizes[:n-1]
	}
	f.size++
}

// Root returns the current MTH: the right-to-left fold of the range (the rightmost — smallest —
// subtree is the deepest promoted node, exactly RFC 6962's split). Empty frontier returns
// EmptyRoot().
func (f *Frontier) Root() []byte {
	if len(f.roots) == 0 {
		return EmptyRoot()
	}
	acc := f.roots[len(f.roots)-1]
	for i := len(f.roots) - 2; i >= 0; i-- {
		acc = nodeHash(f.roots[i], acc)
	}
	return append([]byte(nil), acc...)
}

// Clone returns an independent deep copy — the publisher's cache hands out clones so a failed
// catch-up can never leave the cached frontier half-advanced.
func (f *Frontier) Clone() *Frontier {
	out := &Frontier{
		roots: make([][]byte, len(f.roots)),
		sizes: append([]uint64(nil), f.sizes...),
		size:  f.size,
	}
	for i, r := range f.roots {
		out.roots[i] = append([]byte(nil), r...)
	}
	return out
}
