package translog

// STAKING-P3 Merkle tests, four independent anchors so no single formulation can vouch for
// itself:
//
//  1. The published RFC 6962 known-answer vectors (Google Certificate Transparency's
//     merkletree test inputs — the de-facto official KATs for the RFC's tree shape).
//  2. RFC 6962 §2.1.3's worked 7-leaf example, with every interior node hand-derived and the
//     PATH/PROOF node sequences asserted literally.
//  3. Exhaustive generator<->verifier round-trips over small trees (generation is the RFC 6962
//     recursion, verification the RFC 9162 iteration — two formulations that must agree).
//  4. A leaf-promoting iterative fold (the same shape this platform's RNG service uses for its
//     own transparency Merkle roots, reimplemented here as a test oracle, NOT imported)
//     cross-checked against the recursive MerkleRoot on random inputs.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"testing"
)

// ctVectorInputs are the RFC 6962 / Certificate Transparency known-answer leaf inputs.
func ctVectorInputs(t *testing.T) [][]byte {
	t.Helper()
	hexes := []string{"", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"}
	out := make([][]byte, len(hexes))
	for i, h := range hexes {
		b, err := hex.DecodeString(h)
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		out[i] = b
	}
	return out
}

// ctVectorRoots[n-1] is MTH over the first n vector inputs.
var ctVectorRoots = []string{
	"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
	"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
	"aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
	"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
	"4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
	"76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
	"ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
	"5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
}

func TestMerkleRoot_RFC6962KnownAnswerVectors(t *testing.T) {
	inputs := ctVectorInputs(t)
	for n := 1; n <= len(inputs); n++ {
		got := hex.EncodeToString(MerkleRoot(inputs[:n]))
		if got != ctVectorRoots[n-1] {
			t.Fatalf("MTH over %d vector leaves = %s, want %s", n, got, ctVectorRoots[n-1])
		}
	}
}

func TestMerkleRoot_EmptyTreeIsHashOfNothing(t *testing.T) {
	// RFC 6962: MTH({}) = SHA-256 of the empty string.
	want := sha256.Sum256(nil)
	if !bytes.Equal(EmptyRoot(), want[:]) {
		t.Fatalf("EmptyRoot = %x, want %x", EmptyRoot(), want)
	}
	if !bytes.Equal(MerkleRoot(nil), want[:]) {
		t.Fatalf("MerkleRoot(nil) = %x, want the empty root", MerkleRoot(nil))
	}
	const wantHex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if hex.EncodeToString(EmptyRoot()) != wantHex {
		t.Fatalf("EmptyRoot = %x, want the published SHA-256(\"\") %s", EmptyRoot(), wantHex)
	}
}

func TestMerkleRoot_SingleLeaf(t *testing.T) {
	e := []byte("one-entry-hash")
	if !bytes.Equal(MerkleRoot([][]byte{e}), LeafHash(e)) {
		t.Fatalf("single-leaf root must be the leaf hash itself")
	}
}

// TestMerkle_RFC6962WorkedExample hand-builds the RFC 6962 §2.1.3 example tree over 7 leaves,
//
//	     hash
//	    /    \
//	   k      l
//	  / \    / \
//	 g   h  i   j
//	/ \ / \ / \  \
//	a b c d e f  d6
//
// and asserts the RFC's literal PATH and PROOF node sequences.
func TestMerkle_RFC6962WorkedExample(t *testing.T) {
	d := make([][]byte, 7)
	for i := range d {
		d[i] = []byte(fmt.Sprintf("d%d", i))
	}
	a, b, c2, d2 := LeafHash(d[0]), LeafHash(d[1]), LeafHash(d[2]), LeafHash(d[3])
	e, f, j := LeafHash(d[4]), LeafHash(d[5]), LeafHash(d[6])
	g, h := nodeHash(a, b), nodeHash(c2, d2)
	i := nodeHash(e, f)
	k, l := nodeHash(g, h), nodeHash(i, j)
	root := nodeHash(k, l)

	if got := MerkleRoot(d); !bytes.Equal(got, root) {
		t.Fatalf("root = %x, hand-built %x", got, root)
	}

	assertPath := func(index int, want ...[]byte) {
		t.Helper()
		got, err := InclusionProof(d, index)
		if err != nil {
			t.Fatalf("InclusionProof(%d): %v", index, err)
		}
		if len(got) != len(want) {
			t.Fatalf("PATH(%d) has %d nodes, want %d", index, len(got), len(want))
		}
		for n := range want {
			if !bytes.Equal(got[n], want[n]) {
				t.Fatalf("PATH(%d)[%d] = %x, want %x", index, n, got[n], want[n])
			}
		}
	}
	// RFC 6962 §2.1.3: "The audit path for d0 is [b, h, l]. The audit path for d3 is [c, g, l].
	// The audit path for d4 is [f, j, k]. The audit path for d6 is [i, k]."
	assertPath(0, b, h, l)
	assertPath(3, c2, g, l)
	assertPath(4, f, j, k)
	assertPath(6, i, k)

	assertProof := func(oldSize int, want ...[]byte) {
		t.Helper()
		got, err := ConsistencyProof(d, oldSize, 7)
		if err != nil {
			t.Fatalf("ConsistencyProof(%d, 7): %v", oldSize, err)
		}
		if len(got) != len(want) {
			t.Fatalf("PROOF(%d, 7) has %d nodes, want %d", oldSize, len(got), len(want))
		}
		for n := range want {
			if !bytes.Equal(got[n], want[n]) {
				t.Fatalf("PROOF(%d, 7)[%d] = %x, want %x", oldSize, n, got[n], want[n])
			}
		}
	}
	// RFC 6962 §2.1.3: "The consistency proof between hash0 and hash is PROOF(3, D[7]) = [c, d,
	// g, l]. ... between hash1 and hash is PROOF(4, D[7]) = [l]. ... between hash2 and hash is
	// PROOF(6, D[7]) = [i, j, k]."
	assertProof(3, c2, d2, g, l)
	assertProof(4, l)
	assertProof(6, i, j, k)
}

// synthetic returns n distinct fake entry hashes.
func synthetic(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		h := sha256.Sum256([]byte(fmt.Sprintf("entry-%d", i)))
		out[i] = h[:]
	}
	return out
}

func TestMerkle_InclusionRoundTripExhaustive(t *testing.T) {
	for size := 1; size <= 12; size++ {
		leaves := synthetic(size)
		root := MerkleRoot(leaves)
		for index := 0; index < size; index++ {
			proof, err := InclusionProof(leaves, index)
			if err != nil {
				t.Fatalf("size %d index %d: %v", size, index, err)
			}
			if !VerifyInclusion(LeafHash(leaves[index]), index, size, proof, root) {
				t.Fatalf("size %d index %d: valid proof rejected", size, index)
			}
			// Wrong index must fail.
			if VerifyInclusion(LeafHash(leaves[index]), (index+1)%size, size, proof, root) && size > 1 {
				t.Fatalf("size %d index %d: proof verified under the WRONG index", size, index)
			}
			// A corrupted proof node must fail.
			if len(proof) > 0 {
				tampered := make([][]byte, len(proof))
				copy(tampered, proof)
				bad := append([]byte(nil), tampered[0]...)
				bad[0] ^= 0xff
				tampered[0] = bad
				if VerifyInclusion(LeafHash(leaves[index]), index, size, tampered, root) {
					t.Fatalf("size %d index %d: corrupted proof accepted", size, index)
				}
			}
			// A corrupted leaf must fail.
			badLeaf := append([]byte(nil), LeafHash(leaves[index])...)
			badLeaf[5] ^= 0x01
			if VerifyInclusion(badLeaf, index, size, proof, root) {
				t.Fatalf("size %d index %d: corrupted leaf accepted", size, index)
			}
			// A corrupted root must fail.
			badRoot := append([]byte(nil), root...)
			badRoot[31] ^= 0x80
			if VerifyInclusion(LeafHash(leaves[index]), index, size, proof, badRoot) {
				t.Fatalf("size %d index %d: corrupted root accepted", size, index)
			}
		}
	}
	if _, err := InclusionProof(synthetic(3), 3); err == nil {
		t.Fatalf("index == size must be out of range")
	}
	if _, err := InclusionProof(synthetic(3), -1); err == nil {
		t.Fatalf("negative index must be out of range")
	}
}

func TestMerkle_ConsistencyRoundTripExhaustive(t *testing.T) {
	const maxSize = 12
	leaves := synthetic(maxSize)
	roots := make([][]byte, maxSize+1)
	for n := 1; n <= maxSize; n++ {
		roots[n] = MerkleRoot(leaves[:n])
	}
	for oldSize := 1; oldSize <= maxSize; oldSize++ {
		for newSize := oldSize; newSize <= maxSize; newSize++ {
			proof, err := ConsistencyProof(leaves, oldSize, newSize)
			if err != nil {
				t.Fatalf("proof %d->%d: %v", oldSize, newSize, err)
			}
			if !VerifyConsistency(roots[oldSize], oldSize, roots[newSize], newSize, proof) {
				t.Fatalf("valid consistency %d->%d rejected", oldSize, newSize)
			}
			// The proof must NOT verify against a DIFFERENT old root (the rewritten-history
			// case this whole construction exists to catch).
			forged := append([]byte(nil), roots[oldSize]...)
			forged[7] ^= 0x22
			if VerifyConsistency(forged, oldSize, roots[newSize], newSize, proof) {
				t.Fatalf("consistency %d->%d accepted a forged OLD root", oldSize, newSize)
			}
			forgedNew := append([]byte(nil), roots[newSize]...)
			forgedNew[9] ^= 0x22
			if VerifyConsistency(roots[oldSize], oldSize, forgedNew, newSize, proof) {
				t.Fatalf("consistency %d->%d accepted a forged NEW root", oldSize, newSize)
			}
			if len(proof) > 0 {
				tampered := make([][]byte, len(proof))
				copy(tampered, proof)
				bad := append([]byte(nil), tampered[len(tampered)-1]...)
				bad[16] ^= 0x0f
				tampered[len(tampered)-1] = bad
				if VerifyConsistency(roots[oldSize], oldSize, roots[newSize], newSize, tampered) {
					t.Fatalf("consistency %d->%d accepted a corrupted proof", oldSize, newSize)
				}
			}
		}
	}
	// Same-size: empty proof + equal roots verifies; a non-empty proof or unequal roots do not.
	if !VerifyConsistency(roots[5], 5, roots[5], 5, nil) {
		t.Fatalf("same-size consistency with equal roots rejected")
	}
	if VerifyConsistency(roots[5], 5, roots[6], 6, nil) {
		t.Fatalf("empty proof accepted across different sizes")
	}
	// From size 0 is undefined and refused.
	if _, err := ConsistencyProof(leaves, 0, 5); err == nil {
		t.Fatalf("consistency FROM size 0 must be refused")
	}
	if VerifyConsistency(EmptyRoot(), 0, roots[5], 5, nil) {
		t.Fatalf("VerifyConsistency from size 0 must be false")
	}
}

// TestMerkle_ConsistencyAcrossManyAppends pins the "several appends apart" case at a larger,
// non-power-of-two pair than the exhaustive sweep covers.
func TestMerkle_ConsistencyAcrossManyAppends(t *testing.T) {
	leaves := synthetic(1000)
	oldSize, newSize := 137, 941
	proof, err := ConsistencyProof(leaves, oldSize, newSize)
	if err != nil {
		t.Fatalf("proof: %v", err)
	}
	if !VerifyConsistency(MerkleRoot(leaves[:oldSize]), oldSize, MerkleRoot(leaves[:newSize]), newSize, proof) {
		t.Fatalf("valid consistency %d->%d rejected", oldSize, newSize)
	}
}

// oracleIterativeRoot is a REIMPLEMENTATION of the promote-unchanged iterative fold (the shape
// this platform's RNG service uses for its own transparency Merkle roots) as an independent
// oracle: level by level, pair neighbours, promote an odd node unchanged. It must agree with the
// recursive RFC 6962 MerkleRoot on every input — the two are equivalent formulations of the same
// tree.
func oracleIterativeRoot(entryHashes [][]byte) []byte {
	if len(entryHashes) == 0 {
		return EmptyRoot()
	}
	level := make([][]byte, len(entryHashes))
	for i, e := range entryHashes {
		level[i] = LeafHash(e)
	}
	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				next = append(next, level[i]) // odd node: promoted unchanged, NEVER self-paired
				continue
			}
			next = append(next, nodeHash(level[i], level[i+1]))
		}
		level = next
	}
	return level[0]
}

func TestMerkle_RecursiveEqualsIterativePromotion(t *testing.T) {
	rng := rand.New(rand.NewSource(0x6962))
	for size := 0; size <= 130; size++ {
		leaves := make([][]byte, size)
		for i := range leaves {
			b := make([]byte, 32)
			rng.Read(b)
			leaves[i] = b
		}
		if !bytes.Equal(MerkleRoot(leaves), oracleIterativeRoot(leaves)) {
			t.Fatalf("size %d: recursive root != iterative promote-unchanged root", size)
		}
	}
}

func TestMerkle_FrontierMatchesFullRebuild(t *testing.T) {
	leaves := synthetic(64)
	f := NewFrontier()
	if !bytes.Equal(f.Root(), EmptyRoot()) {
		t.Fatalf("empty frontier root != EmptyRoot")
	}
	for n := 1; n <= len(leaves); n++ {
		f.Append(leaves[n-1])
		if f.Size() != int64(n) {
			t.Fatalf("frontier size = %d, want %d", f.Size(), n)
		}
		if !bytes.Equal(f.Root(), MerkleRoot(leaves[:n])) {
			t.Fatalf("frontier root at size %d != full rebuild", n)
		}
	}
}

func TestMerkle_FrontierCloneIsIndependent(t *testing.T) {
	leaves := synthetic(10)
	f := NewFrontier()
	for _, l := range leaves[:5] {
		f.Append(l)
	}
	snap := f.Clone()
	snapRoot := snap.Root()
	for _, l := range leaves[5:] {
		f.Append(l)
	}
	if !bytes.Equal(snap.Root(), snapRoot) || snap.Size() != 5 {
		t.Fatalf("advancing the original mutated the clone")
	}
	if !bytes.Equal(snap.Root(), MerkleRoot(leaves[:5])) {
		t.Fatalf("clone root != rebuild at its size")
	}
	if !bytes.Equal(f.Root(), MerkleRoot(leaves)) {
		t.Fatalf("original root != rebuild after further appends")
	}
}
