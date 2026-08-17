// Package attest holds the STAKING-P5 asset-ATTESTATION primitives: interfaces and
// implementations for recording that some party ASSERTS custodial assets of at least X existed
// as of a moment bound to an already-published transparency-log head.
//
// WORDING DISCIPLINE (a hard product/legal constraint, not style): nothing in this package —
// type names, doc strings, log text, wire fields — may claim "proof of reserves" or "proof of
// assets" as an absolute. What this package records is an ATTESTATION: "the wallet service
// asserts X" or "an auditor asserts X", verifiable only by trusting THAT party's key or
// signature. The published surfaces say "Proof of Liabilities" (that one IS a cryptographic
// commitment, pkg/translog's sumtree) and "Attested Reserves" — never more.
//
// Like pkg/translog, this package knows NOTHING about the casino domain: no pools, no epochs,
// no repositories. Callers (the producer's attestation service) map attestations onto pools
// and persistence.
//
// CHALLENGE BINDING: every Attest call carries a challenge — by contract the pool's CURRENT
// published Signed-Tree-Head root (pkg/translog, STAKING-P3). Producers MUST refuse to record an
// attestation whose challenge no longer equals the pool's latest published root. What that
// binding PROVES differs per kind (P2-P5 review L3 — do not overstate it):
//
//   - kind "wallet_attested": the wallet SIGNS the challenge as part of its own statement, so
//     the signed figure cannot be pre-computed before the head existed and cannot be replayed
//     later as if it were fresh — a verifier checks the challenge inside the signed preimage
//     against the published STH stream.
//   - kind "auditor": the auditor's own signature covers only the recorded document; the
//     challenge binds THE ACT OF RECORDING it, not the document's own freshness. Staff could
//     record an old signed statement against a freshly published root and the challenge check
//     would pass. For auditor records, freshness rests on the document's own asOf date — which
//     IS published beside the record, so it is visible to every reader, just not
//     cryptographically bound to the head the way a wallet statement's is.
package attest

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/wasabi-gaming/staking-verify/internal/money"
)

// The attestor kinds this phase defines. The string values are persisted
// (staking_attestations.kind) and published — never renumber or rename.
const (
	// KindWalletAttested: the wallet service signs its OWN custodial total with its OWN
	// key. Proves "the wallet service asserts X" — an integrity attestation, not proof the
	// funds exist.
	KindWalletAttested = "wallet_attested"
	// KindAuditor: the hash (and optionally the opaque signature) of a third party's signed
	// statement, recorded by staff. Proves "this exact document was presented and recorded
	// against this challenge" — the document's own trustworthiness is the auditor's.
	KindAuditor = "auditor"
	// KindOnchainAddressControl: signing a challenge with an address's own private key. NOT
	// implementable while custody is delegated to the payment processor (the platform holds no
	// address keys) — see onchain.go's permanently-refusing stub.
	KindOnchainAddressControl = "onchain_address_control"
)

// ChallengeSize is the required challenge length: a SHA-256 Signed-Tree-Head root hash.
const ChallengeSize = 32

// ErrInvalidAttestation guards malformed attestor inputs/outputs.
var ErrInvalidAttestation = errors.New("attest: invalid attestation")

// ErrDuplicateKind is returned by Registry.Register for a kind already registered.
var ErrDuplicateKind = errors.New("attest: attestor kind already registered")

// Attestation is one recorded assertion: some attestor of the given Kind asserts that custodial
// assets of at least Balance existed for (OperatorID, Currency) as of AsOf, bound to Challenge.
// Signature carries the ASSERTING party's own signature bytes (the wallet service's Ed25519
// signature, or an auditor's opaque signature) — the recording platform never re-signs or
// vouches for the number itself. Payload is flat supporting material (key ids, document hashes,
// audit stamps) the caller persists alongside.
type Attestation struct {
	Kind       string
	OperatorID uuid.UUID
	Currency   int
	Balance    money.Amount
	AsOf       time.Time
	Challenge  []byte
	Signature  []byte
	Payload    map[string]string
}

// Validate checks the fields every recorded attestation must carry.
func (a *Attestation) Validate() error {
	if a == nil {
		return fmt.Errorf("%w: nil attestation", ErrInvalidAttestation)
	}
	if a.Kind == "" {
		return fmt.Errorf("%w: kind is required", ErrInvalidAttestation)
	}
	if a.OperatorID == uuid.Nil {
		return fmt.Errorf("%w: operator id is required", ErrInvalidAttestation)
	}
	if a.Currency <= 0 {
		return fmt.Errorf("%w: currency must be positive, got %d", ErrInvalidAttestation, a.Currency)
	}
	if a.Balance.IsNegative() {
		return fmt.Errorf("%w: attested balance must not be negative", ErrInvalidAttestation)
	}
	if a.AsOf.IsZero() {
		return fmt.Errorf("%w: as_of is required", ErrInvalidAttestation)
	}
	if len(a.Challenge) != ChallengeSize {
		return fmt.Errorf("%w: challenge is %d bytes, want %d (an STH root hash)", ErrInvalidAttestation, len(a.Challenge), ChallengeSize)
	}
	return nil
}

// AssetAttestor is one source of asset attestations. Kind is stable and persisted; Attest
// produces one attestation for (operatorID, currency) bound to challenge — the pool's current
// STH root, supplied by the caller. Implementations MUST echo the exact challenge into the
// returned Attestation (callers verify this) and MUST NOT fabricate a balance they were not
// given or did not observe.
type AssetAttestor interface {
	Kind() string // "wallet_attested" | "auditor" | "onchain_address_control"
	Attest(ctx context.Context, operatorID uuid.UUID, currency int, challenge []byte) (*Attestation, error)
}

// Registry maps kind -> AssetAttestor. Registration happens once at wiring time (cmd/api);
// lookups are read-mostly.
type Registry struct {
	mu     sync.RWMutex
	byKind map[string]AssetAttestor
}

// NewRegistry builds an empty registry.
func NewRegistry() *Registry {
	return &Registry{byKind: map[string]AssetAttestor{}}
}

// Register adds one attestor, refusing duplicates and nil/blank kinds.
func (r *Registry) Register(a AssetAttestor) error {
	if a == nil || a.Kind() == "" {
		return fmt.Errorf("%w: nil attestor or empty kind", ErrInvalidAttestation)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.byKind[a.Kind()]; dup {
		return fmt.Errorf("%w: %s", ErrDuplicateKind, a.Kind())
	}
	r.byKind[a.Kind()] = a
	return nil
}

// Get resolves one attestor by kind.
func (r *Registry) Get(kind string) (AssetAttestor, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.byKind[kind]
	return a, ok
}

// Kinds returns the registered kinds, sorted — a stable order for logs and sweeps.
func (r *Registry) Kinds() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.byKind))
	for k := range r.byKind {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
