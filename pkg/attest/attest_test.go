package attest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/wasabi-gaming/staking-verify/internal/money"
)

func TestRegistryRegisterGetKinds(t *testing.T) {
	r := NewRegistry()
	stub := NewOnchainAddressControlAttestor()
	if err := r.Register(stub); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := r.Register(stub); !errors.Is(err, ErrDuplicateKind) {
		t.Fatalf("duplicate register: want ErrDuplicateKind, got %v", err)
	}
	if _, ok := r.Get(KindOnchainAddressControl); !ok {
		t.Fatal("registered attestor not resolvable")
	}
	if _, ok := r.Get(KindWalletAttested); ok {
		t.Fatal("unregistered kind resolved")
	}
	if kinds := r.Kinds(); len(kinds) != 1 || kinds[0] != KindOnchainAddressControl {
		t.Fatalf("kinds: %v", kinds)
	}
}

func TestOnchainStubAlwaysRefuses(t *testing.T) {
	stub := NewOnchainAddressControlAttestor()
	if stub.Kind() != KindOnchainAddressControl {
		t.Fatalf("kind: %s", stub.Kind())
	}
	_, err := stub.Attest(context.Background(), uuid.New(), 150, bytes.Repeat([]byte{0x42}, ChallengeSize))
	if !errors.Is(err, ErrOnchainUnsupported) {
		t.Fatalf("want ErrOnchainUnsupported, got %v", err)
	}
	// The refusal is total: even a second call with different inputs refuses identically.
	_, err = stub.Attest(context.Background(), uuid.New(), 999, nil)
	if !errors.Is(err, ErrOnchainUnsupported) {
		t.Fatalf("want ErrOnchainUnsupported, got %v", err)
	}
}

func validAuditorStatement() AuditorStatement {
	return AuditorStatement{
		DocumentSHA256: HashDocument([]byte("signed auditor statement bytes")),
		AuditorRef:     "ExampleAudit LLP report 2026-Q3 #17",
		Balance:        money.MustParse("50000"),
		AsOf:           time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
		SubmittedBy:    "test-actor",
		Reason:         "quarterly custodial statement",
	}
}

func TestAuditorAttestorRecordsStatement(t *testing.T) {
	stmt := validAuditorStatement()
	stmt.AuditorSignature = []byte{0xde, 0xad}
	stmt.SignatureScheme = "pgp"
	a, err := NewAuditorAttestor(stmt)
	if err != nil {
		t.Fatalf("NewAuditorAttestor: %v", err)
	}
	op := uuid.New()
	challenge := bytes.Repeat([]byte{0x42}, ChallengeSize)
	att, err := a.Attest(context.Background(), op, 150, challenge)
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if att.Kind != KindAuditor {
		t.Fatalf("kind: %s", att.Kind)
	}
	if !bytes.Equal(att.Signature, stmt.AuditorSignature) {
		t.Fatal("auditor signature must be stored verbatim")
	}
	if att.Payload["documentSha256"] == "" || att.Payload["auditorRef"] == "" ||
		att.Payload["submittedBy"] == "" || att.Payload["reason"] == "" {
		t.Fatalf("payload missing provenance: %v", att.Payload)
	}
	if att.Payload["signatureScheme"] != "pgp" {
		t.Fatalf("payload missing signature scheme: %v", att.Payload)
	}
	if err := att.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestAuditorStatementValidation(t *testing.T) {
	cases := map[string]func(*AuditorStatement){
		"short hash":         func(s *AuditorStatement) { s.DocumentSHA256 = s.DocumentSHA256[:sha256.Size-1] },
		"blank ref":          func(s *AuditorStatement) { s.AuditorRef = "" },
		"negative balance":   func(s *AuditorStatement) { s.Balance = money.MustParse("-1") },
		"zero as_of":         func(s *AuditorStatement) { s.AsOf = time.Time{} },
		"sig without scheme": func(s *AuditorStatement) { s.AuditorSignature = []byte{1}; s.SignatureScheme = "" },
		"blank actor":        func(s *AuditorStatement) { s.SubmittedBy = "" },
		"blank reason":       func(s *AuditorStatement) { s.Reason = "" },
	}
	for name, mutate := range cases {
		stmt := validAuditorStatement()
		mutate(&stmt)
		if _, err := NewAuditorAttestor(stmt); !errors.Is(err, ErrInvalidAttestation) {
			t.Fatalf("%s: want ErrInvalidAttestation, got %v", name, err)
		}
	}
}

func TestAttestationValidateChallengeSize(t *testing.T) {
	att := &Attestation{
		Kind: KindAuditor, OperatorID: uuid.New(), Currency: 150,
		Balance: money.MustParse("1"), AsOf: time.Now(),
		Challenge: []byte{0x01}, // wrong size
	}
	if err := att.Validate(); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("want ErrInvalidAttestation for short challenge, got %v", err)
	}
}

// TestNoForbiddenClaimWording pins the wording constraint: the package's published string
// constants must never assert "proof of reserves"/"proof of assets".
func TestNoForbiddenClaimWording(t *testing.T) {
	for _, s := range []string{
		KindWalletAttested, KindAuditor, KindOnchainAddressControl,
		CoverageNone, CoverageAttested,
		ErrOnchainUnsupported.Error(), ErrInvalidAttestation.Error(),
		ErrWalletStatementInvalid.Error(), ErrWalletStatementSignature.Error(),
		ErrWalletStatementMismatch.Error(),
	} {
		lower := strings.ToLower(s)
		if strings.Contains(lower, "proof of reserves") || strings.Contains(lower, "proof of assets") {
			t.Fatalf("forbidden claim wording in published string: %q", s)
		}
	}
}
