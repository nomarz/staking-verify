package attest

// The "onchain_address_control" SEAM — a registered-but-refusing stub, on an explicit product
// decision.
//
// Address-control attestation means signing the challenge with an on-chain address's OWN
// private key — the one attestation kind an outsider could verify without trusting any platform
// party. It is NOT IMPLEMENTABLE today, full stop: crypto custody is fully delegated to the
// platform's payment-processor integration, the platform never
// holds address keys and therefore CANNOT sign for any address, regardless of engineering
// effort. Faking it (signing with some platform key and calling it address control) would be
// exactly the misrepresentation the package header forbids.
//
// What ships instead is the seam: the kind constant, this stub, and a config knob
// (configs.StakingConfig.AttestOnchainEnabled) that defaults to NOT REGISTERING it at all. The
// day custody changes, a real implementation replaces this file's Attest body — the interface,
// the registry, the persistence and the published wire format all already fit it.

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// ErrOnchainUnsupported is the typed refusal every call to the stub returns. Callers branch on
// it to render "unsupported under current custody", never a generic failure.
var ErrOnchainUnsupported = errors.New(
	"attest: onchain_address_control is not supported: custody is delegated to the payment processor and the platform holds no address keys; this attestor is a seam for a future custody change")

// OnchainAddressControlAttestor is the permanently-refusing stub for kind
// "onchain_address_control".
type OnchainAddressControlAttestor struct{}

// NewOnchainAddressControlAttestor constructs the stub. Constructing it is always allowed —
// REGISTERING it is what the config knob gates, and even registered it refuses every call.
func NewOnchainAddressControlAttestor() *OnchainAddressControlAttestor {
	return &OnchainAddressControlAttestor{}
}

// Kind returns "onchain_address_control".
func (a *OnchainAddressControlAttestor) Kind() string { return KindOnchainAddressControl }

// Attest always refuses with ErrOnchainUnsupported. There is deliberately no partial path here.
func (a *OnchainAddressControlAttestor) Attest(_ context.Context, operatorID uuid.UUID, currency int, _ []byte) (*Attestation, error) {
	return nil, fmt.Errorf("%w (operator %s, currency %d)", ErrOnchainUnsupported, operatorID, currency)
}
