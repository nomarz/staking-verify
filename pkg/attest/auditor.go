package attest

// The "auditor" attestor: a RECORDING mechanism for a third party's signed statement — the only
// attestation option for fiat and delegated custody. Staff present the auditor's document
// out-of-band; what this attestor records is the document's SHA-256 hash, the auditor's own
// (opaque, scheme-tagged) signature bytes when provided, and the balance/as-of the statement
// asserts, all bound to the pool's current STH root challenge.
//
// What this proves: "THIS exact document, asserting THIS balance, was recorded against THIS
// already-published log state." Whether the document itself is trustworthy is the auditor's
// reputation — the platform verifies nothing about the document's content and says so plainly.
// The auditor's signature is stored VERBATIM (scheme-tagged, never interpreted): verifying it
// is the relying party's job with the auditor's published key material, outside this system.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/wasabi-gaming/staking-verify/internal/money"
)

// AuditorStatement is one staff-submitted third-party statement: the document hash plus the
// balance/as-of it asserts and its provenance.
type AuditorStatement struct {
	// DocumentSHA256 is the SHA-256 of the auditor's statement document, exactly 32 bytes.
	DocumentSHA256 []byte
	// AuditorRef names the statement's origin (firm, report id, URL) — required, free text.
	AuditorRef string
	// Balance is the custodial balance the statement asserts.
	Balance money.Amount
	// AsOf is the instant the statement asserts the balance for (the document's own date).
	AsOf time.Time
	// AuditorSignature optionally carries the auditor's own signature bytes over the document —
	// opaque to this system, stored verbatim.
	AuditorSignature []byte
	// SignatureScheme tags AuditorSignature's format when present (e.g. "pgp", "pades") so a
	// relying party knows how to check it. Required iff AuditorSignature is set.
	SignatureScheme string
	// SubmittedBy is the staff actor recording the statement — required; this row is the only
	// audit trail the submission leaves.
	SubmittedBy string
	// Reason is the staff-supplied why — required, same audit-trail role as SubmittedBy.
	Reason string
}

// HashDocument is the convenience hasher for callers holding the raw statement bytes.
func HashDocument(doc []byte) []byte {
	h := sha256.Sum256(doc)
	return h[:]
}

// Validate checks the statement is recordable.
func (s AuditorStatement) Validate() error {
	if len(s.DocumentSHA256) != sha256.Size {
		return fmt.Errorf("%w: document sha-256 is %d bytes, want %d", ErrInvalidAttestation, len(s.DocumentSHA256), sha256.Size)
	}
	if s.AuditorRef == "" {
		return fmt.Errorf("%w: auditor ref is required", ErrInvalidAttestation)
	}
	if s.Balance.IsNegative() {
		return fmt.Errorf("%w: attested balance must not be negative", ErrInvalidAttestation)
	}
	if s.AsOf.IsZero() {
		return fmt.Errorf("%w: as_of is required", ErrInvalidAttestation)
	}
	if len(s.AuditorSignature) > 0 && s.SignatureScheme == "" {
		return fmt.Errorf("%w: signature scheme is required when an auditor signature is supplied", ErrInvalidAttestation)
	}
	if s.SubmittedBy == "" || s.Reason == "" {
		return fmt.Errorf("%w: submitted_by and reason are required (they are the only audit trail this submission leaves)", ErrInvalidAttestation)
	}
	return nil
}

// AuditorAttestor implements AssetAttestor kind "auditor" for ONE statement: it is constructed
// per submission (there is no standing auditor connection to poll), which is why it never sits
// in the long-lived Registry the epoch hook sweeps — staff submit, the service records, done.
type AuditorAttestor struct {
	stmt AuditorStatement
}

// NewAuditorAttestor validates and wraps one statement.
func NewAuditorAttestor(stmt AuditorStatement) (*AuditorAttestor, error) {
	if err := stmt.Validate(); err != nil {
		return nil, err
	}
	return &AuditorAttestor{stmt: stmt}, nil
}

// Kind returns "auditor".
func (a *AuditorAttestor) Kind() string { return KindAuditor }

// Attest records the wrapped statement for (operatorID, currency) bound to challenge. The
// Signature column carries the auditor's OWN opaque bytes (possibly none); the payload carries
// the document hash and provenance.
func (a *AuditorAttestor) Attest(_ context.Context, operatorID uuid.UUID, currency int, challenge []byte) (*Attestation, error) {
	if operatorID == uuid.Nil {
		return nil, fmt.Errorf("%w: operator id is required", ErrInvalidAttestation)
	}
	if currency <= 0 {
		return nil, fmt.Errorf("%w: currency must be positive, got %d", ErrInvalidAttestation, currency)
	}
	if len(challenge) != ChallengeSize {
		return nil, fmt.Errorf("%w: challenge is %d bytes, want %d", ErrInvalidAttestation, len(challenge), ChallengeSize)
	}
	payload := map[string]string{
		"documentSha256": hex.EncodeToString(a.stmt.DocumentSHA256),
		"auditorRef":     a.stmt.AuditorRef,
		"submittedBy":    a.stmt.SubmittedBy,
		"reason":         a.stmt.Reason,
	}
	if len(a.stmt.AuditorSignature) > 0 {
		payload["signatureScheme"] = a.stmt.SignatureScheme
	}
	att := &Attestation{
		Kind:       KindAuditor,
		OperatorID: operatorID,
		Currency:   currency,
		Balance:    a.stmt.Balance,
		AsOf:       a.stmt.AsOf.UTC(),
		Challenge:  append([]byte(nil), challenge...),
		Signature:  append([]byte(nil), a.stmt.AuditorSignature...),
		Payload:    payload,
	}
	if err := att.Validate(); err != nil {
		return nil, err
	}
	return att, nil
}
