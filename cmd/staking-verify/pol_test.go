package main

// STAKING-P4 -pol tests: a synthetic tree rendered through the EXACT wire shape the authed
// proof endpoint serves (a documented contract between that endpoint and this parser), verified
// by ParsePoLProofFile + VerifyPoLProof, then tampered in every way a dishonest server could try.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/wasabi-gaming/staking-verify/internal/money"
	"github.com/wasabi-gaming/staking-verify/pkg/translog"
)

// polFixture builds a 5-leaf tree and renders leaves ownIdxs in the wire format.
func polFixture(t *testing.T, ownIdxs []int, mutate func(map[string]interface{})) []byte {
	t.Helper()
	balances := []string{"100", "250.5", "0.000000000000000001", "70", "42"}
	leaves := make([]translog.LiabilityLeaf, len(balances))
	for i, b := range balances {
		leaves[i] = translog.LiabilityLeaf{
			Salt:     bytes.Repeat([]byte{byte(i + 1)}, translog.LiabilitySaltSize),
			PublicID: uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa" + string(rune('0'+i))),
			Balance:  money.MustParse(b),
		}
	}
	tree, err := translog.BuildLiabilityTree(leaves)
	if err != nil {
		t.Fatalf("BuildLiabilityTree: %v", err)
	}
	own := money.Zero
	wireLeaves := make([]interface{}, 0, len(ownIdxs))
	for _, idx := range ownIdxs {
		proof, err := tree.ProofFor(idx)
		if err != nil {
			t.Fatalf("ProofFor(%d): %v", idx, err)
		}
		steps := make([]interface{}, 0, len(proof.Steps))
		for _, st := range proof.Steps {
			steps = append(steps, map[string]interface{}{
				"sum":    translog.CanonicalAmount(st.Sum),
				"hash":   hex.EncodeToString(st.Hash),
				"isLeft": st.IsLeft,
			})
		}
		wireLeaves = append(wireLeaves, map[string]interface{}{
			"leafIndex": idx,
			"salt":      hex.EncodeToString(leaves[idx].Salt),
			"publicId":  leaves[idx].PublicID.String(),
			"balance":   translog.CanonicalAmount(leaves[idx].Balance),
			"proof":     steps,
		})
		own = own.Add(leaves[idx].Balance)
	}
	body := map[string]interface{}{
		"epochId":     int64(7),
		"epochDate":   "2026-08-11",
		"poolId":      "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
		"rootHash":    hex.EncodeToString(tree.Root()),
		"totalAmount": translog.CanonicalAmount(tree.Total()),
		"leafCount":   tree.LeafCount(),
		"ownBalance":  translog.CanonicalAmount(own),
		"leaves":      wireLeaves,
	}
	if mutate != nil {
		mutate(body)
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	return raw
}

// TestPoLVerify_HonestRoundTrip: a faithful response verifies, and the summary reports the
// recomputed own balance.
func TestPoLVerify_HonestRoundTrip(t *testing.T) {
	raw := polFixture(t, []int{1, 3}, nil)
	sum, err := VerifyPoLStream(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("VerifyPoLStream: %v", err)
	}
	if sum.OwnLeaves != 2 {
		t.Fatalf("OwnLeaves = %d, want 2", sum.OwnLeaves)
	}
	if want := money.MustParse("320.5"); !sum.OwnBalance.Equal(want) {
		t.Fatalf("OwnBalance = %s, want %s", money.String(sum.OwnBalance), money.String(want))
	}
	var out bytes.Buffer
	WritePoLSummary(&out, sum)
	if !strings.Contains(out.String(), "2 own leaf/leaves verified") {
		t.Fatalf("summary missing leaf count: %q", out.String())
	}
}

// TestPoLVerify_TamperedTotalRejected: a server understating the published total (the whole
// point of the attack class) is caught — the accumulated path sum no longer matches.
func TestPoLVerify_TamperedTotalRejected(t *testing.T) {
	raw := polFixture(t, []int{0}, func(body map[string]interface{}) {
		body["totalAmount"] = "100.000000000000000000" // true total is 462.5…
	})
	if _, err := VerifyPoLStream(bytes.NewReader(raw)); err == nil {
		t.Fatalf("VerifyPoLStream accepted a tampered total")
	}
}

// TestPoLVerify_TamperedRootRejected: a different root cannot be verified against.
func TestPoLVerify_TamperedRootRejected(t *testing.T) {
	raw := polFixture(t, []int{0}, func(body map[string]interface{}) {
		root := body["rootHash"].(string)
		body["rootHash"] = "00" + root[2:]
	})
	if _, err := VerifyPoLStream(bytes.NewReader(raw)); err == nil {
		t.Fatalf("VerifyPoLStream accepted a tampered root")
	}
}

// TestPoLVerify_ForgedSiblingSumRejected: a mutated sibling sum in the served proof — the
// Maxwell forgery surface — breaks the hash walk.
func TestPoLVerify_ForgedSiblingSumRejected(t *testing.T) {
	raw := polFixture(t, []int{0}, func(body map[string]interface{}) {
		leaves := body["leaves"].([]interface{})
		leaf := leaves[0].(map[string]interface{})
		steps := leaf["proof"].([]interface{})
		step := steps[0].(map[string]interface{})
		step["sum"] = "0.000000000000000000"
	})
	if _, err := VerifyPoLStream(bytes.NewReader(raw)); err == nil {
		t.Fatalf("VerifyPoLStream accepted a forged sibling sum")
	}
}

// TestPoLVerify_InconsistentOwnBalanceRejected: the server's display aggregate must match the
// material it served.
func TestPoLVerify_InconsistentOwnBalanceRejected(t *testing.T) {
	raw := polFixture(t, []int{0, 4}, func(body map[string]interface{}) {
		body["ownBalance"] = "999.000000000000000000"
	})
	if _, err := VerifyPoLStream(bytes.NewReader(raw)); err == nil {
		t.Fatalf("VerifyPoLStream accepted an ownBalance the served leaves do not sum to")
	}
}

// TestPoLVerify_NegativeLeafRejected: a negative balance smuggled into the wire form is refused
// (the primitive's rule, re-asserted through the CLI path).
func TestPoLVerify_NegativeLeafRejected(t *testing.T) {
	raw := polFixture(t, []int{0}, func(body map[string]interface{}) {
		leaves := body["leaves"].([]interface{})
		leaf := leaves[0].(map[string]interface{})
		leaf["balance"] = "-100.000000000000000000"
	})
	if _, err := VerifyPoLStream(bytes.NewReader(raw)); err == nil {
		t.Fatalf("VerifyPoLStream accepted a negative leaf balance")
	}
}
