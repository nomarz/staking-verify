package attest

// STAKING-P5's Anchorer SEAM — interface and registry only, no implementation, on purpose.
//
// Anchoring commits a published Signed Tree Head to some EXTERNAL, independently-timestamped
// medium (OpenTimestamps, an RFC 3161 TSA, witness co-signing). Without anchoring, a signed
// head only proves the operator did not rewrite history relative to a head YOU already hold —
// it cannot prove to a newcomer that today's log is the one that existed last month. That gap
// is worth stating plainly, and it is exactly what a future Anchorer implementation closes.
//
// This phase ships the seam and nothing else: staking_sth.anchor_kind / anchor_ref (migration
// 083) stay unwritten until a REAL Anchorer exists — an interface with no implementation must
// not put values in a published table. When one lands, it registers here exactly like an
// AssetAttestor registers in Registry, and the STH publisher gains a post-publish anchor step.

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/wasabi-gaming/staking-verify/pkg/translog"
)

// AnchorReceipt is the opaque evidence one Anchorer produced for one STH: Kind names the
// anchoring scheme (persisted to staking_sth.anchor_kind), Ref is the scheme's own receipt
// reference (staking_sth.anchor_ref), AnchoredAt is when the anchor was obtained.
type AnchorReceipt struct {
	Kind       string
	Ref        string
	AnchoredAt time.Time
}

// Anchorer commits a Signed Tree Head to an external timestamping medium and later verifies a
// receipt against the same head. Implementations are future work (OpenTimestamps / RFC 3161 /
// witness co-signing) — none exist in this phase, by scope decision.
type Anchorer interface {
	Kind() string
	Anchor(ctx context.Context, sth *translog.STH) (*AnchorReceipt, error)
	Verify(ctx context.Context, sth *translog.STH, r *AnchorReceipt) error
}

// AnchorRegistry maps kind -> Anchorer, mirroring Registry so a future implementation drops in
// without touching the interface. Empty in every deployment this phase ships.
type AnchorRegistry struct {
	mu     sync.RWMutex
	byKind map[string]Anchorer
}

// NewAnchorRegistry builds an empty anchor registry.
func NewAnchorRegistry() *AnchorRegistry {
	return &AnchorRegistry{byKind: map[string]Anchorer{}}
}

// Register adds one anchorer, refusing duplicates and nil/blank kinds.
func (r *AnchorRegistry) Register(a Anchorer) error {
	if a == nil || a.Kind() == "" {
		return fmt.Errorf("%w: nil anchorer or empty kind", ErrInvalidAttestation)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.byKind[a.Kind()]; dup {
		return fmt.Errorf("%w: %s", ErrDuplicateKind, a.Kind())
	}
	r.byKind[a.Kind()] = a
	return nil
}

// Get resolves one anchorer by kind.
func (r *AnchorRegistry) Get(kind string) (Anchorer, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.byKind[kind]
	return a, ok
}

// Kinds returns the registered kinds, sorted.
func (r *AnchorRegistry) Kinds() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.byKind))
	for k := range r.byKind {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
