package translog

// STAKING-P4 summation-tree tests. The two load-bearing ones are the FORGED-SUM tests
// (TestLiabilitySumTree_MaxwellForgedInternalSum_UnderstatedLeavesRejected and
// TestLiabilityProof_CompensatingForgedSums_HashBindingRejects) — they construct the actual
// Maxwell/Todd attack shapes against this verifier and assert rejection. Everything else is the
// honest-path/round-trip scaffolding around them.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/google/uuid"
	"github.com/wasabi-gaming/staking-verify/internal/money"
)

// tlLeaf builds a test leaf with a deterministic salt (tests that need real randomness use
// GenerateLiabilityLeaves instead).
func tlLeaf(saltByte byte, id string, balance string) LiabilityLeaf {
	salt := bytes.Repeat([]byte{saltByte}, LiabilitySaltSize)
	return LiabilityLeaf{Salt: salt, PublicID: uuid.MustParse(id), Balance: money.MustParse(balance)}
}

var (
	tlIDA = "11111111-1111-1111-1111-111111111111"
	tlIDB = "22222222-2222-2222-2222-222222222222"
	tlIDC = "33333333-3333-3333-3333-333333333333"
	tlIDD = "44444444-4444-4444-4444-444444444444"
)

// tlNodePreimageHash re-implements the node hash INDEPENDENTLY of liabilityNodeHash so the
// forged-sum tests can build attacker trees from raw bytes — a bug shared between generator and
// verifier can't hide behind a shared helper.
func tlNodePreimageHash(sumL string, hashL []byte, sumR string, hashR []byte) []byte {
	var lenBuf [2]byte
	h := sha256.New()
	h.Write([]byte{0x01})
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(sumL)))
	h.Write(lenBuf[:])
	h.Write([]byte(sumL))
	h.Write(hashL)
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(sumR)))
	h.Write(lenBuf[:])
	h.Write([]byte(sumR))
	h.Write(hashR)
	return h.Sum(nil)
}

// TestLiabilitySumTree_HonestRoundTrip: every leaf of trees of size 1..9 proves against the
// root and total; the root sum equals the exact Σ of the balances.
func TestLiabilitySumTree_HonestRoundTrip(t *testing.T) {
	ids := []string{tlIDA, tlIDB, tlIDC, tlIDD}
	for n := 1; n <= 9; n++ {
		leaves := make([]LiabilityLeaf, n)
		want := money.Zero
		for i := range leaves {
			leaves[i] = tlLeaf(byte(i+1), ids[i%len(ids)], money.String(money.FromInt(int64(i*37+11)).Add(money.MustParse("0.000000000000000001"))))
			want = want.Add(leaves[i].Balance)
		}
		tree, err := BuildLiabilityTree(leaves)
		if err != nil {
			t.Fatalf("n=%d BuildLiabilityTree: %v", n, err)
		}
		if got := tree.Total(); !got.Equal(want) {
			t.Fatalf("n=%d Total() = %s, want %s", n, money.String(got), money.String(want))
		}
		if tree.LeafCount() != n {
			t.Fatalf("n=%d LeafCount() = %d", n, tree.LeafCount())
		}
		for i := range leaves {
			proof, err := tree.ProofFor(i)
			if err != nil {
				t.Fatalf("n=%d ProofFor(%d): %v", n, i, err)
			}
			ok, err := VerifyLiabilityProof(leaves[i], proof, tree.Root(), tree.Total())
			if err != nil || !ok {
				t.Fatalf("n=%d leaf %d honest proof rejected: ok=%v err=%v", n, i, ok, err)
			}
			// A wrong expected total must reject even with the right hash chain.
			ok, err = VerifyLiabilityProof(leaves[i], proof, tree.Root(), tree.Total().Add(money.MustParse("1")))
			if err != nil || ok {
				t.Fatalf("n=%d leaf %d verified against a WRONG total: ok=%v err=%v", n, i, ok, err)
			}
			// A wrong root must reject.
			badRoot := tree.Root()
			badRoot[0] ^= 0xFF
			ok, err = VerifyLiabilityProof(leaves[i], proof, badRoot, tree.Total())
			if err != nil || ok {
				t.Fatalf("n=%d leaf %d verified against a WRONG root: ok=%v err=%v", n, i, ok, err)
			}
		}
	}
}

// TestLiabilitySumTree_NegativeLeafRejected: BuildLiabilityTree refuses ANY negative balance —
// never clamps, never skips — and the verifier refuses a negative leaf and a negative sibling
// sum outright. A negative leaf cancels real liabilities out of the sum while the total still
// "balances"; refusing to build at all is the specified response.
func TestLiabilitySumTree_NegativeLeafRejected(t *testing.T) {
	leaves := []LiabilityLeaf{
		tlLeaf(1, tlIDA, "100"),
		tlLeaf(2, tlIDB, "-0.000000000000000001"),
	}
	if _, err := BuildLiabilityTree(leaves); err == nil {
		t.Fatalf("BuildLiabilityTree accepted a negative leaf balance")
	}

	// Verifier side: negative leaf.
	tree, err := BuildLiabilityTree([]LiabilityLeaf{tlLeaf(1, tlIDA, "100"), tlLeaf(2, tlIDB, "50")})
	if err != nil {
		t.Fatalf("BuildLiabilityTree: %v", err)
	}
	proof, _ := tree.ProofFor(0)
	negLeaf := tlLeaf(1, tlIDA, "-100")
	if ok, err := VerifyLiabilityProof(negLeaf, proof, tree.Root(), tree.Total()); ok || err == nil {
		t.Fatalf("VerifyLiabilityProof accepted a negative leaf: ok=%v err=%v", ok, err)
	}

	// Verifier side: negative SIBLING sum — the smuggled-cancellation variant.
	forged := proof
	forged.Steps = append([]LiabilityProofStep(nil), proof.Steps...)
	forged.Steps[0].Sum = money.MustParse("-50")
	if ok, err := VerifyLiabilityProof(tree.leaves[0], forged, tree.Root(), tree.Total()); ok || err == nil {
		t.Fatalf("VerifyLiabilityProof accepted a negative sibling sum: ok=%v err=%v", ok, err)
	}
}

// TestLiabilitySumTree_MaxwellForgedInternalSum_UnderstatedLeavesRejected is THE load-bearing
// test of this phase: the Maxwell/Todd attack, constructed for real against this verifier.
//
// The attacker builds a 4-leaf tree over balances (100, 200, 50, 70) but, when hashing the ROOT,
// declares the right subtree's sum as max(50, 70) = 70 instead of 50 + 70 = 120 — publishing
// total' = 300 + 70 = 370 instead of the true 420, understating liabilities by 50.
//
// What the verifier must guarantee (walked by hand):
//   - Leaves OUTSIDE the forged subtree (0, 1) receive proofs whose sibling steps carry exactly
//     the values the attacker hashed — those proofs DO verify against (root', total'). That is
//     expected and sound: a passing proof only attests "my balance is counted in this total".
//   - Leaves INSIDE the forged subtree (2, 3) can be given NO passing proof: the verifier
//     re-derives their parent's sum as 50 + 70 = 120 and feeds THAT into the root preimage, which
//     can never reproduce root' (whose preimage contains the forged 70) — and any alternative
//     sibling material that fixed the hash would change the accumulated total away from 370.
//     The understated stakers DETECT the theft; that is the scheme's guarantee.
func TestLiabilitySumTree_MaxwellForgedInternalSum_UnderstatedLeavesRejected(t *testing.T) {
	l0 := tlLeaf(1, tlIDA, "100")
	l1 := tlLeaf(2, tlIDB, "200")
	l2 := tlLeaf(3, tlIDC, "50")
	l3 := tlLeaf(4, tlIDD, "70")

	h0, _ := LiabilityLeafHash(l0)
	h1, _ := LiabilityLeafHash(l1)
	h2, _ := LiabilityLeafHash(l2)
	h3, _ := LiabilityLeafHash(l3)

	canon := func(s string) string { return CanonicalAmount(money.MustParse(s)) }

	// Honest internal nodes.
	nodeL := tlNodePreimageHash(canon("100"), h0, canon("200"), h1) // sum 300
	nodeR := tlNodePreimageHash(canon("50"), h2, canon("70"), h3)   // TRUE sum 120

	// THE FORGERY: the root preimage declares nodeR's sum as 70 (= max(50,70)), not 120.
	forgedRoot := tlNodePreimageHash(canon("300"), nodeL, canon("70"), nodeR)
	forgedTotal := money.MustParse("370") // true total is 420

	// Sanity: the attack understates a REAL tree — the honest root/total differ.
	honest, err := BuildLiabilityTree([]LiabilityLeaf{l0, l1, l2, l3})
	if err != nil {
		t.Fatalf("BuildLiabilityTree: %v", err)
	}
	if honest.Total().Equal(forgedTotal) || bytes.Equal(honest.Root(), forgedRoot) {
		t.Fatalf("attack construction broken: forged tree equals the honest one")
	}

	// Leaves 0 and 1 (outside the forged subtree): the attacker CAN serve passing proofs — their
	// paths contain the forged (70, nodeR) step exactly as hashed. Assert they pass, so the test
	// below is meaningful (the attack is "individual proofs still verify", not "nothing works").
	proof0 := LiabilityProof{LeafIndex: 0, Steps: []LiabilityProofStep{
		{Sum: money.MustParse("200"), Hash: h1, IsLeft: false},
		{Sum: money.MustParse("70"), Hash: nodeR, IsLeft: false}, // the forged declaration
	}}
	if ok, err := VerifyLiabilityProof(l0, proof0, forgedRoot, forgedTotal); err != nil || !ok {
		t.Fatalf("attack construction broken: leaf 0's crafted proof should pass against the forged head (ok=%v err=%v)", ok, err)
	}

	// Leaves 2 and 3 — the UNDERSTATED stakers. Their honest sibling material must be REJECTED
	// against the forged head: the verifier derives 50+70=120 into the root preimage, which
	// cannot reproduce forgedRoot.
	proof2 := LiabilityProof{LeafIndex: 2, Steps: []LiabilityProofStep{
		{Sum: money.MustParse("70"), Hash: h3, IsLeft: false},
		{Sum: money.MustParse("300"), Hash: nodeL, IsLeft: true},
	}}
	if ok, err := VerifyLiabilityProof(l2, proof2, forgedRoot, forgedTotal); err != nil || ok {
		t.Fatalf("FORGED-SUM ATTACK NOT CAUGHT: understated leaf 2 verified against the forged head (ok=%v err=%v)", ok, err)
	}
	proof3 := LiabilityProof{LeafIndex: 3, Steps: []LiabilityProofStep{
		{Sum: money.MustParse("50"), Hash: h2, IsLeft: true},
		{Sum: money.MustParse("300"), Hash: nodeL, IsLeft: true},
	}}
	if ok, err := VerifyLiabilityProof(l3, proof3, forgedRoot, forgedTotal); err != nil || ok {
		t.Fatalf("FORGED-SUM ATTACK NOT CAUGHT: understated leaf 3 verified against the forged head (ok=%v err=%v)", ok, err)
	}

	// And the attacker cannot instead patch leaf 2's SIBLING sum to make the arithmetic work:
	// accumulating to 370 requires the path sums to change, which changes the preimages, which
	// breaks the hash chain. Try the natural patch (declare sibling l3's sum as 70-50=20... any
	// value: the hash of nodeR was computed over the TRUE 70, so the chain breaks regardless).
	patched := LiabilityProof{LeafIndex: 2, Steps: []LiabilityProofStep{
		{Sum: money.MustParse("20"), Hash: h3, IsLeft: false},
		{Sum: money.MustParse("300"), Hash: nodeL, IsLeft: true},
	}}
	if ok, err := VerifyLiabilityProof(l2, patched, forgedRoot, forgedTotal); err != nil || ok {
		t.Fatalf("FORGED-SUM ATTACK NOT CAUGHT: patched sibling sum verified (ok=%v err=%v)", ok, err)
	}
}

// TestLiabilityProof_CompensatingForgedSums_HashBindingRejects isolates the HASH binding from
// the total-accumulation check: two sibling sums mutated in compensating directions (+10, -10)
// leave the accumulated total untouched, so ONLY the sums' participation in the node preimages
// can reject the proof. A verifier that hashed child hashes alone and merely tracked sums
// alongside would ACCEPT this proof.
func TestLiabilityProof_CompensatingForgedSums_HashBindingRejects(t *testing.T) {
	leaves := []LiabilityLeaf{
		tlLeaf(1, tlIDA, "100"),
		tlLeaf(2, tlIDB, "200"),
		tlLeaf(3, tlIDC, "50"),
		tlLeaf(4, tlIDD, "70"),
	}
	tree, err := BuildLiabilityTree(leaves)
	if err != nil {
		t.Fatalf("BuildLiabilityTree: %v", err)
	}
	proof, err := tree.ProofFor(0) // steps: sibling l1 (200), sibling nodeR (120)
	if err != nil {
		t.Fatalf("ProofFor: %v", err)
	}
	if len(proof.Steps) != 2 {
		t.Fatalf("expected 2 proof steps for a 4-leaf tree, got %d", len(proof.Steps))
	}
	forged := LiabilityProof{LeafIndex: 0, Steps: []LiabilityProofStep{
		{Sum: proof.Steps[0].Sum.Add(money.MustParse("10")), Hash: proof.Steps[0].Hash, IsLeft: proof.Steps[0].IsLeft},
		{Sum: proof.Steps[1].Sum.Sub(money.MustParse("10")), Hash: proof.Steps[1].Hash, IsLeft: proof.Steps[1].IsLeft},
	}}
	// Accumulated total is unchanged by construction…
	acc := leaves[0].Balance.Add(forged.Steps[0].Sum).Add(forged.Steps[1].Sum)
	if !acc.Equal(tree.Total()) {
		t.Fatalf("test construction broken: compensating mutation changed the accumulated total")
	}
	// …so only the sum-in-preimage binding can reject it. It must.
	if ok, err := VerifyLiabilityProof(leaves[0], forged, tree.Root(), tree.Total()); err != nil || ok {
		t.Fatalf("compensating forged sums verified — sums are NOT bound into the node hashes (ok=%v err=%v)", ok, err)
	}
}

// TestLiabilitySumTree_TamperedLeafRejected: a server serving a different balance than what was
// committed (leaf mutated after publication) fails against the original root.
func TestLiabilitySumTree_TamperedLeafRejected(t *testing.T) {
	leaves := []LiabilityLeaf{tlLeaf(1, tlIDA, "100"), tlLeaf(2, tlIDB, "50"), tlLeaf(3, tlIDC, "25")}
	tree, err := BuildLiabilityTree(leaves)
	if err != nil {
		t.Fatalf("BuildLiabilityTree: %v", err)
	}
	proof, err := tree.ProofFor(1)
	if err != nil {
		t.Fatalf("ProofFor: %v", err)
	}
	tampered := leaves[1]
	tampered.Balance = money.MustParse("49") // one unit less than committed
	if ok, err := VerifyLiabilityProof(tampered, proof, tree.Root(), tree.Total()); err != nil || ok {
		t.Fatalf("tampered leaf balance verified against the original root (ok=%v err=%v)", ok, err)
	}
	// Tampered salt equally rejects (the salt is in the preimage).
	tampered = leaves[1]
	tampered.Salt = bytes.Repeat([]byte{0x99}, LiabilitySaltSize)
	if ok, err := VerifyLiabilityProof(tampered, proof, tree.Root(), tree.Total()); err != nil || ok {
		t.Fatalf("tampered leaf salt verified against the original root (ok=%v err=%v)", ok, err)
	}
}

// TestGenerateLiabilityLeaves_SplitAndPaddingPreserveTotal: splitting + house padding never
// change what the total represents — Total() == Σ input balances exactly, per-account leaf sums
// reproduce each input balance exactly, and house accounts carry the padding-heavy multiplicity.
func TestGenerateLiabilityLeaves_SplitAndPaddingPreserveTotal(t *testing.T) {
	accounts := []LiabilityAccountInput{
		{PublicID: uuid.MustParse(tlIDA), Balance: money.MustParse("123.456789012345678901")}, // deliberately > 18dp… parse normalizes
		{PublicID: uuid.MustParse(tlIDB), Balance: money.MustParse("0.000000000000000003")},
		{PublicID: uuid.MustParse(tlIDC), Balance: money.MustParse("999999.999999999999999999")},
		{PublicID: uuid.MustParse(tlIDD), Balance: money.MustParse("5000"), House: true},
	}
	want := money.Zero
	for _, a := range accounts {
		want = want.Add(a.Balance)
	}
	gen, err := GenerateLiabilityLeaves(accounts, nil)
	if err != nil {
		t.Fatalf("GenerateLiabilityLeaves: %v", err)
	}
	perAccount := make([]money.Amount, len(accounts))
	counts := make([]int, len(accounts))
	for i := range perAccount {
		perAccount[i] = money.Zero
	}
	leaves := make([]LiabilityLeaf, len(gen))
	for i, g := range gen {
		leaves[i] = g.Leaf
		perAccount[g.AccountIndex] = perAccount[g.AccountIndex].Add(g.Leaf.Balance)
		counts[g.AccountIndex]++
		if g.Leaf.PublicID != accounts[g.AccountIndex].PublicID {
			t.Fatalf("leaf %d attributed to account %d but carries a different public id", i, g.AccountIndex)
		}
		if g.IsPadding != accounts[g.AccountIndex].House {
			t.Fatalf("leaf %d IsPadding=%v for account House=%v", i, g.IsPadding, accounts[g.AccountIndex].House)
		}
	}
	for i, a := range accounts {
		if !perAccount[i].Equal(a.Balance) {
			t.Fatalf("account %d leaf sum = %s, want its exact balance %s", i, money.String(perAccount[i]), money.String(a.Balance))
		}
		lo, hi := 1, 4
		if a.House {
			lo, hi = 8, 16
		}
		if counts[i] < lo || counts[i] > hi {
			t.Fatalf("account %d (house=%v) split into %d leaves, want %d..%d", i, a.House, counts[i], lo, hi)
		}
	}
	tree, err := BuildLiabilityTree(leaves)
	if err != nil {
		t.Fatalf("BuildLiabilityTree over generated leaves: %v", err)
	}
	if !tree.Total().Equal(want) {
		t.Fatalf("Total() over split+padded leaves = %s, want the exact Σ of input balances %s — padding must never inflate the total",
			money.String(tree.Total()), money.String(want))
	}
	// Every generated leaf proves against the tree.
	for i := range leaves {
		proof, err := tree.ProofFor(i)
		if err != nil {
			t.Fatalf("ProofFor(%d): %v", i, err)
		}
		if ok, err := VerifyLiabilityProof(leaves[i], proof, tree.Root(), tree.Total()); err != nil || !ok {
			t.Fatalf("generated leaf %d rejected: ok=%v err=%v", i, ok, err)
		}
	}
}

// TestGenerateLiabilityLeaves_ZeroBalanceHousePadding: a house account with zero balance still
// pads (8..16 zero-valued leaves) without touching the total.
func TestGenerateLiabilityLeaves_ZeroBalanceHousePadding(t *testing.T) {
	accounts := []LiabilityAccountInput{
		{PublicID: uuid.MustParse(tlIDA), Balance: money.MustParse("42")},
		{PublicID: uuid.MustParse(tlIDD), Balance: money.Zero, House: true},
	}
	gen, err := GenerateLiabilityLeaves(accounts, nil)
	if err != nil {
		t.Fatalf("GenerateLiabilityLeaves: %v", err)
	}
	houseLeaves := 0
	for _, g := range gen {
		if g.IsPadding {
			houseLeaves++
			if !g.Leaf.Balance.IsZero() {
				t.Fatalf("zero-balance house account emitted a non-zero leaf %s", money.String(g.Leaf.Balance))
			}
		}
	}
	if houseLeaves < 8 || houseLeaves > 16 {
		t.Fatalf("zero-balance house account emitted %d padding leaves, want 8..16", houseLeaves)
	}
}

// TestGenerateLiabilityLeaves_NonDeterministicAcrossCalls: two generations over the SAME
// accounts must not reproduce the same salts (and thus the same leaves/shuffle) — a stable
// pattern across epochs would itself leak account correlation.
func TestGenerateLiabilityLeaves_NonDeterministicAcrossCalls(t *testing.T) {
	accounts := []LiabilityAccountInput{
		{PublicID: uuid.MustParse(tlIDA), Balance: money.MustParse("1000")},
		{PublicID: uuid.MustParse(tlIDB), Balance: money.MustParse("2500")},
		{PublicID: uuid.MustParse(tlIDD), Balance: money.MustParse("5000"), House: true},
	}
	genA, err := GenerateLiabilityLeaves(accounts, nil)
	if err != nil {
		t.Fatalf("GenerateLiabilityLeaves (A): %v", err)
	}
	genB, err := GenerateLiabilityLeaves(accounts, nil)
	if err != nil {
		t.Fatalf("GenerateLiabilityLeaves (B): %v", err)
	}
	saltsA := map[string]struct{}{}
	for _, g := range genA {
		saltsA[string(g.Leaf.Salt)] = struct{}{}
	}
	for _, g := range genB {
		if _, dup := saltsA[string(g.Leaf.Salt)]; dup {
			t.Fatalf("a salt repeated across two independent generations — 16 random bytes colliding means the randomness source is broken")
		}
	}
	// The two trees must publish different roots (salts alone guarantee it).
	build := func(gen []GeneratedLiabilityLeaf) *LiabilityTree {
		leaves := make([]LiabilityLeaf, len(gen))
		for i, g := range gen {
			leaves[i] = g.Leaf
		}
		tr, err := BuildLiabilityTree(leaves)
		if err != nil {
			t.Fatalf("BuildLiabilityTree: %v", err)
		}
		return tr
	}
	if bytes.Equal(build(genA).Root(), build(genB).Root()) {
		t.Fatalf("two independent generations produced the SAME root")
	}
}

// TestGenerateLiabilityLeaves_NegativeBalanceRejected mirrors the build-side refusal at the
// generation layer.
func TestGenerateLiabilityLeaves_NegativeBalanceRejected(t *testing.T) {
	_, err := GenerateLiabilityLeaves([]LiabilityAccountInput{
		{PublicID: uuid.MustParse(tlIDA), Balance: money.MustParse("-1")},
	}, nil)
	if err == nil {
		t.Fatalf("GenerateLiabilityLeaves accepted a negative balance")
	}
}
