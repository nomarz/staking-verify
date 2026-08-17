package attest

// The "wallet_attested" attestor: the wallet service signs a statement of its OWN
// custodial total for (operator, currency), bound to the caller-supplied challenge, with a key
// ONLY the wallet service holds. The producer RELAYS that signed statement into its attestation log —
// it never re-signs, never vouches for the number, and stores the wallet's raw signature and
// key id. The TRUST ANCHOR is not this file: VerifyWalletStatement alone establishes only that
// the statement is internally consistent with its own embedded key. What makes the key "the
// wallet service's" is its entry in the published, append-only key registry
// (the producer's signing-key registry, purpose 'wallet-attest' — registered by the recording service on each
// verified attestation, served at GET /staking/transparency/key) — a verifier MUST cross-check
// the embedded key against that registry entry (cmd/staking-verify does, via -registry or
// -wallet-key) or the statement proves nothing about WHO signed it.
//
// CROSS-SERVICE CONTRACT (mirrored in the wallet service's own attestation-signing code — keep
// the two in lockstep, each side's known-answer test pins the identical canonical bytes):
//
//	message   = "nomarz-wallet-v1:asset-attestation:" || canonical(statement)
//	signature = Ed25519(wallet_sk, message)
//
// canonical(statement) is a fixed, versioned field set in RFC 8785 (JCS) key order:
//
//	{"as_of":"<TSFormat UTC>","challenge":"<hex>","currency":N,
//	 "custodial_balance":"<18-dp decimal>","operator_id":"<uuid>","schema_version":1}
//
// The signing context is DISTINCT from every pkg/translog context ("...:receipt:", "...:sth:")
// and namespaced to the wallet service ("nomarz-wallet-v1:") — the wallet's attestation key
// must never produce bytes that verify as a staking receipt or STH, and vice versa.
//
// The verifier re-canonicalizes PARSED fields (the pkg/translog STH discipline): the wire
// wrapper is never the signed preimage, so any value edit breaks the signature check.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/wasabi-gaming/staking-verify/internal/money"
)

// WalletStatementContext is the domain-separation prefix for wallet custodial-balance
// attestation signatures. MUST stay distinct from every pkg/translog context forever.
const WalletStatementContext = "nomarz-wallet-v1:asset-attestation:"

// WalletStatementSchemaVersion1 is the only canonicalization schema this phase defines.
const WalletStatementSchemaVersion1 = 1

// WalletStatementTSFormat matches pkg/translog's TSFormat: microsecond UTC, fixed width — the
// DB round-trip-safe timestamp form both repos canonicalize with.
const WalletStatementTSFormat = "2006-01-02T15:04:05.000000Z"

// WalletStatementAmountScale is the fixed fractional-digit count of the canonical balance.
const WalletStatementAmountScale = 18

// ErrWalletStatementInvalid guards malformed statements.
var ErrWalletStatementInvalid = errors.New("attest: invalid wallet statement")

// ErrWalletStatementSignature is returned when a statement's signature does not verify, or its
// key id does not derive from its public key.
var ErrWalletStatementSignature = errors.New("attest: wallet statement signature does not verify")

// ErrWalletStatementMismatch is returned when the wallet's response does not echo the exact
// request (operator, currency, challenge) it was asked to attest.
var ErrWalletStatementMismatch = errors.New("attest: wallet statement does not match the request")

// WalletKeyID derives the canonical key id for a wallet attestation public key — the SAME
// derivation as pkg/translog.KeyIDFor ("ed25519:" + first 8 bytes of SHA-256(pub), hex), so a
// registry row claiming one id but carrying another key's bytes is detectable on either side.
func WalletKeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return "ed25519:" + hex.EncodeToString(h[:8])
}

// WalletStatement is the wallet service's signed custodial-balance assertion, as returned by
// the AttestCustodialBalance RPC. KeyID/PublicKey/Signature authenticate the canonical payload;
// they are not part of it.
type WalletStatement struct {
	SchemaVersion int
	OperatorID    string // uuid string, lowercased on canonicalization
	Currency      int
	Balance       money.Amount
	AsOf          time.Time
	Challenge     []byte
	KeyID         string
	PublicKey     ed25519.PublicKey
	Signature     []byte
}

// Validate checks the statement can be canonicalized.
func (s WalletStatement) Validate() error {
	if s.SchemaVersion != WalletStatementSchemaVersion1 {
		return fmt.Errorf("%w: unsupported schema_version %d", ErrWalletStatementInvalid, s.SchemaVersion)
	}
	if _, err := uuid.Parse(s.OperatorID); err != nil {
		return fmt.Errorf("%w: operator_id %q is not a uuid", ErrWalletStatementInvalid, s.OperatorID)
	}
	if s.Currency <= 0 {
		return fmt.Errorf("%w: currency must be positive, got %d", ErrWalletStatementInvalid, s.Currency)
	}
	if s.Balance.IsNegative() {
		return fmt.Errorf("%w: custodial_balance must not be negative", ErrWalletStatementInvalid)
	}
	if s.AsOf.IsZero() {
		return fmt.Errorf("%w: as_of is required", ErrWalletStatementInvalid)
	}
	if len(s.Challenge) != ChallengeSize {
		return fmt.Errorf("%w: challenge is %d bytes, want %d", ErrWalletStatementInvalid, len(s.Challenge), ChallengeSize)
	}
	return nil
}

// CanonicalJSON returns the signed payload. Keys appear in their JCS (byte, all-ASCII) order
// for this fixed set: as_of < challenge < currency < custodial_balance < operator_id <
// schema_version. Every value is plain ASCII by construction (fixed-format timestamp, hex,
// digits, 18-dp decimal, uuid), so no JSON escaping can ever apply.
func (s WalletStatement) CanonicalJSON() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	op, _ := uuid.Parse(s.OperatorID) // validated above; re-render for canonical lowercase
	buf := make([]byte, 0, 256)
	buf = append(buf, `{"as_of":"`...)
	buf = append(buf, s.AsOf.UTC().Format(WalletStatementTSFormat)...)
	buf = append(buf, `","challenge":"`...)
	buf = append(buf, hex.EncodeToString(s.Challenge)...)
	buf = append(buf, `","currency":`...)
	buf = append(buf, strconv.Itoa(s.Currency)...)
	buf = append(buf, `,"custodial_balance":"`...)
	buf = append(buf, s.Balance.StringFixed(WalletStatementAmountScale)...)
	buf = append(buf, `","operator_id":"`...)
	buf = append(buf, op.String()...)
	buf = append(buf, `","schema_version":`...)
	buf = append(buf, strconv.Itoa(s.SchemaVersion)...)
	buf = append(buf, '}')
	return buf, nil
}

// walletSigningMessage builds the domain-separated message for one canonical statement.
func walletSigningMessage(canonical []byte) []byte {
	msg := make([]byte, 0, len(WalletStatementContext)+len(canonical))
	msg = append(msg, WalletStatementContext...)
	return append(msg, canonical...)
}

// VerifyWalletStatement re-canonicalizes the statement and verifies it against its OWN embedded
// key material: the key id must derive from the public key, and the signature must verify under
// the domain-separated context. This establishes INTERNAL CONSISTENCY ONLY — any fresh keypair
// can produce a statement that passes this check. It says nothing about WHO holds the key:
// callers needing "signed by the wallet service" must ADDITIONALLY match the embedded key
// against an independently published anchor — the purpose='wallet-attest' entry of the key
// registry, or an out-of-band pin (see the file header).
func VerifyWalletStatement(s WalletStatement) error {
	if len(s.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: public key is %d bytes, want %d", ErrWalletStatementInvalid, len(s.PublicKey), ed25519.PublicKeySize)
	}
	if s.KeyID != WalletKeyID(s.PublicKey) {
		return fmt.Errorf("%w: key id %q does not derive from the embedded public key (want %q)",
			ErrWalletStatementSignature, s.KeyID, WalletKeyID(s.PublicKey))
	}
	if len(s.Signature) == 0 {
		return fmt.Errorf("%w: unsigned statement", ErrWalletStatementSignature)
	}
	canonical, err := s.CanonicalJSON()
	if err != nil {
		return err
	}
	if !ed25519.Verify(s.PublicKey, walletSigningMessage(canonical), s.Signature) {
		return ErrWalletStatementSignature
	}
	return nil
}

// SignWalletStatement canonicalizes and signs a statement in place, stamping KeyID, PublicKey
// and Signature. Exported for tests and for any same-repo producer; the PRODUCTION signer of
// this statement is the wallet service itself, never this codebase.
func SignWalletStatement(priv ed25519.PrivateKey, s *WalletStatement) error {
	canonical, err := s.CanonicalJSON()
	if err != nil {
		return err
	}
	pub := priv.Public().(ed25519.PublicKey)
	s.Signature = ed25519.Sign(priv, walletSigningMessage(canonical))
	s.PublicKey = append(ed25519.PublicKey(nil), pub...)
	s.KeyID = WalletKeyID(pub)
	return nil
}

// WalletStatementClient is the transport this attestor drives — implemented by
// the producer's adapter over the existing mTLS wallet gRPC channel. Kept as an interface
// here so this package stays free of proto/transport knowledge and tests can fake the wallet.
type WalletStatementClient interface {
	AttestCustodialBalance(ctx context.Context, operatorID string, currency int, challenge []byte) (*WalletStatement, error)
}

// WalletAttestor implements AssetAttestor kind "wallet_attested".
type WalletAttestor struct {
	client WalletStatementClient
}

// NewWalletAttestor wires the attestor over its transport.
func NewWalletAttestor(client WalletStatementClient) (*WalletAttestor, error) {
	if client == nil {
		return nil, fmt.Errorf("%w: nil wallet statement client", ErrInvalidAttestation)
	}
	return &WalletAttestor{client: client}, nil
}

// Kind returns "wallet_attested".
func (a *WalletAttestor) Kind() string { return KindWalletAttested }

// Attest asks the wallet service to sign its custodial total for (operatorID, currency) bound
// to challenge, then verifies — BEFORE anything is recorded — that the response echoes the
// exact request and that the wallet's signature verifies over the re-canonicalized statement.
// The returned Attestation carries the wallet's RAW signature and key material; the producer adds
// nothing of its own beyond the payload's bookkeeping fields.
func (a *WalletAttestor) Attest(ctx context.Context, operatorID uuid.UUID, currency int, challenge []byte) (*Attestation, error) {
	if operatorID == uuid.Nil {
		return nil, fmt.Errorf("%w: operator id is required", ErrInvalidAttestation)
	}
	if currency <= 0 {
		return nil, fmt.Errorf("%w: currency must be positive, got %d", ErrInvalidAttestation, currency)
	}
	if len(challenge) != ChallengeSize {
		return nil, fmt.Errorf("%w: challenge is %d bytes, want %d", ErrInvalidAttestation, len(challenge), ChallengeSize)
	}
	st, err := a.client.AttestCustodialBalance(ctx, operatorID.String(), currency, challenge)
	if err != nil {
		return nil, fmt.Errorf("attest: wallet attestation call failed: %w", err)
	}
	if st == nil {
		return nil, fmt.Errorf("%w: wallet returned no statement", ErrWalletStatementInvalid)
	}
	// The wallet must attest EXACTLY what it was asked: same operator, same currency, same
	// challenge. A mismatch is refused here, never recorded.
	if !bytes.Equal(st.Challenge, challenge) {
		return nil, fmt.Errorf("%w: challenge not echoed (asked %s, got %s)",
			ErrWalletStatementMismatch, hex.EncodeToString(challenge), hex.EncodeToString(st.Challenge))
	}
	if op, perr := uuid.Parse(st.OperatorID); perr != nil || op != operatorID {
		return nil, fmt.Errorf("%w: operator not echoed (asked %s, got %q)", ErrWalletStatementMismatch, operatorID, st.OperatorID)
	}
	if st.Currency != currency {
		return nil, fmt.Errorf("%w: currency not echoed (asked %d, got %d)", ErrWalletStatementMismatch, currency, st.Currency)
	}
	if err := VerifyWalletStatement(*st); err != nil {
		return nil, err
	}
	return &Attestation{
		Kind:       KindWalletAttested,
		OperatorID: operatorID,
		Currency:   currency,
		Balance:    st.Balance,
		AsOf:       st.AsOf.UTC(),
		Challenge:  append([]byte(nil), challenge...),
		Signature:  append([]byte(nil), st.Signature...),
		Payload: map[string]string{
			"keyId":     st.KeyID,
			"publicKey": hex.EncodeToString(st.PublicKey),
			// The aggregate the wallet signed over, stated so a reader of the stored row knows
			// WHAT was summed without reading the wallet's source — including what that total is
			// NOT (review M2): custodial balances the wallet ledger holds for its own account
			// holders are a different liability pot than staking, so this figure must never be
			// read as coverage of the PoL total it is published beside.
			"basis": "sum of wallet balances for this operator and currency in the wallet service's own ledger — custodial balances held for the wallet's own account holders, not funds earmarked for staking liabilities",
		},
	}, nil
}
