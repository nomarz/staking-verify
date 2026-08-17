package attest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// wireDocFixture builds one attested Doc holding a REAL signed wallet record, produced through
// the same path the HTTP handler uses (WalletAttestor -> NewWireRecord).
func wireDocFixture(t *testing.T) *Doc {
	t.Helper()
	att, err := NewWalletAttestor(&fakeWalletClient{priv: katSeed()})
	if err != nil {
		t.Fatalf("NewWalletAttestor: %v", err)
	}
	op := uuid.New()
	challenge := bytes.Repeat([]byte{0x42}, ChallengeSize)
	a, err := att.Attest(context.Background(), op, 150, challenge)
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	return &Doc{
		EpochID: 7, EpochDate: "2026-08-11", PoolID: uuid.NewString(), Currency: 150,
		PolRootHash: strings.Repeat("ab", 32), PolTotalAmount: "700.000000000000000000",
		PolPublishedAt: time.Now().UTC().Format(time.RFC3339),
		Coverage:       CoverageAttested,
		AttestedTotal:  a.Balance.StringFixed(WalletStatementAmountScale),
		Attestations:   []WireRecord{NewWireRecord(a, time.Now())},
	}
}

func TestWireDocRoundTripAndReverify(t *testing.T) {
	doc := wireDocFixture(t)
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	parsed, err := ParseDoc(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("ParseDoc: %v", err)
	}
	if len(parsed.Attestations) != 1 {
		t.Fatalf("records: %d", len(parsed.Attestations))
	}
	st, err := WalletStatementFromRecord(parsed.Attestations[0])
	if err != nil {
		t.Fatalf("WalletStatementFromRecord: %v", err)
	}
	if err := VerifyWalletStatement(*st); err != nil {
		t.Fatalf("re-verify after wire round trip: %v", err)
	}
}

func TestWireDocEditBreaksSignature(t *testing.T) {
	doc := wireDocFixture(t)
	// An operator quietly inflating the served balance must break the wallet's signature on
	// re-verification — the verifier re-canonicalizes parsed fields, never trusts the wrapper.
	doc.Attestations[0].AttestedBalance = "999999.000000000000000000"
	raw, _ := json.Marshal(doc)
	parsed, err := ParseDoc(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("ParseDoc: %v", err)
	}
	st, err := WalletStatementFromRecord(parsed.Attestations[0])
	if err != nil {
		t.Fatalf("WalletStatementFromRecord: %v", err)
	}
	if err := VerifyWalletStatement(*st); err == nil {
		t.Fatal("edited balance still verified")
	}
}

func TestParseDocRefusesInconsistentCoverage(t *testing.T) {
	doc := wireDocFixture(t)
	doc.Coverage = CoverageNone // records present but coverage claims none
	raw, _ := json.Marshal(doc)
	if _, err := ParseDoc(bytes.NewReader(raw)); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("want ErrInvalidAttestation, got %v", err)
	}

	empty := &Doc{EpochID: 1, EpochDate: "2026-08-11", PoolID: uuid.NewString(), Currency: 150,
		PolRootHash: strings.Repeat("ab", 32), PolTotalAmount: "1.000000000000000000",
		PolPublishedAt: time.Now().UTC().Format(time.RFC3339),
		Coverage:       CoverageAttested} // claims attested but has no records
	raw, _ = json.Marshal(empty)
	if _, err := ParseDoc(bytes.NewReader(raw)); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("want ErrInvalidAttestation, got %v", err)
	}

	unknown := wireDocFixture(t)
	unknown.Coverage = "totally-fine"
	raw, _ = json.Marshal(unknown)
	if _, err := ParseDoc(bytes.NewReader(raw)); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("want ErrInvalidAttestation for unknown coverage, got %v", err)
	}
}

func TestCoverageNoneOmitsAttestedTotal(t *testing.T) {
	doc := &Doc{EpochID: 1, EpochDate: "2026-08-11", PoolID: uuid.NewString(), Currency: 150,
		PolRootHash: strings.Repeat("ab", 32), PolTotalAmount: "1.000000000000000000",
		PolPublishedAt: time.Now().UTC().Format(time.RFC3339),
		Coverage:       CoverageNone}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// The "none" state must not render an attestedTotal at all: a served 0 would be
	// indistinguishable from an attested zero balance, which is a DIFFERENT statement.
	if bytes.Contains(raw, []byte("attestedTotal")) {
		t.Fatalf("coverage none rendered an attestedTotal: %s", raw)
	}
	if _, err := ParseDoc(bytes.NewReader(raw)); err != nil {
		t.Fatalf("ParseDoc: %v", err)
	}
}
