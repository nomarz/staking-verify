package attest

// The published wire form of one epoch's attestation record set + solvency statement — ONE
// contract shared by the HTTP handler (GET /staking/transparency/attestations/:epoch) and
// cmd/staking-verify's -attest input, following the LiabilityProofDoc / MarshalSTHLine rule:
// what the API serves is byte-compatible with what the verifier consumes, no drift.
//
// MATERIAL, NEVER A VERDICT: there is no "solvent" or "verified" field anywhere here, by
// design. Coverage describes WHAT was attested ("none" vs "attested" — data about record
// existence, not a solvency judgment); the totals are published side by side and the READER
// (or the CLI) does the arithmetic. The one distinction this format is careful to make:
// CoverageNone means "nothing was attested for this pool's currency in this epoch window" —
// which is NOT the same statement as "attested to be insolvent", and must never render in a
// way that could be misread as one.

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/wasabi-gaming/staking-verify/internal/money"
)

// Coverage states of one epoch's solvency statement. String values are published — never
// rename.
const (
	// CoverageNone: NO attestor recorded anything for this pool's currency in this epoch's
	// window. The pool is named with this state explicitly rather than omitted — unattested
	// is a first-class, visible condition, never assumed solvent and never conflated with a
	// low attested balance.
	CoverageNone = "none"
	// CoverageAttested: at least one attestation exists in the window. Says nothing about
	// sufficiency — the totals next to it carry the numbers.
	CoverageAttested = "attested"
)

// WireRecord is one published attestation record. Bytes are hex, amounts 18-dp decimal
// strings, timestamps the transparency stack's usual forms — matching every other byte/amount
// this subsystem publishes. A verifier REBUILDS the wallet statement's canonical preimage from
// these parsed fields (never trusts a served blob), so any value edit breaks the signature.
type WireRecord struct {
	Kind            string            `json:"kind"`
	OperatorID      string            `json:"operatorId"`
	Currency        int               `json:"currency"`
	AttestedBalance string            `json:"attestedBalance"`
	AsOf            string            `json:"asOf"`      // WalletStatementTSFormat
	Challenge       string            `json:"challenge"` // hex: the STH root the attestor was bound to
	Signature       string            `json:"signature,omitempty"`
	Payload         map[string]string `json:"payload,omitempty"`
	RecordedAt      string            `json:"recordedAt"` // RFC 3339
}

// Doc is one epoch's full published attestation surface: the PoL commitment context, the
// recorded attestations (newest per kind — see the service's selection contract), and the
// aggregate attested total when any exist.
type Doc struct {
	EpochID   int64  `json:"epochId"`
	EpochDate string `json:"epochDate"`
	PoolID    string `json:"poolId"`
	Currency  int    `json:"currency"`
	// The epoch's published Proof-of-Liabilities commitment — what the attested balances are
	// read AGAINST. Served here so the arithmetic needs no second fetch.
	PolRootHash    string `json:"polRootHash"`
	PolTotalAmount string `json:"polTotalAmount"`
	PolPublishedAt string `json:"polPublishedAt"`
	// Coverage: CoverageNone | CoverageAttested. Data about record existence, not a verdict.
	Coverage string `json:"coverage"`
	// AttestedTotal is Σ attestedBalance over the served records — present ONLY when coverage
	// is "attested". Its absence under "none" is deliberate: rendering 0 there would be
	// indistinguishable from an attested zero balance.
	AttestedTotal string `json:"attestedTotal,omitempty"`
	// BasisNotes surfaces each served record's own "basis" payload note (deduplicated,
	// "<kind>: <basis>") NEXT TO the totals above, so a consumer reading the comparison sees
	// what each attested figure actually sums — e.g. the wallet's number is its custodial
	// ledger total (money held for the wallet's own account holders), NOT funds earmarked for
	// the PoL liabilities beside it. The comparison shows scale, not coverage (review M2).
	BasisNotes   []string     `json:"basisNotes,omitempty"`
	Attestations []WireRecord `json:"attestations"`
}

// NewWireRecord renders one attestation into its published form.
func NewWireRecord(a *Attestation, recordedAt time.Time) WireRecord {
	rec := WireRecord{
		Kind:            a.Kind,
		OperatorID:      a.OperatorID.String(),
		Currency:        a.Currency,
		AttestedBalance: a.Balance.StringFixed(WalletStatementAmountScale),
		AsOf:            a.AsOf.UTC().Format(WalletStatementTSFormat),
		Challenge:       hex.EncodeToString(a.Challenge),
		RecordedAt:      recordedAt.UTC().Format(time.RFC3339),
	}
	if len(a.Signature) > 0 {
		rec.Signature = hex.EncodeToString(a.Signature)
	}
	if len(a.Payload) > 0 {
		rec.Payload = a.Payload
	}
	return rec
}

// ParseDoc parses one saved attestation document (a GET .../attestations/:epoch response body).
func ParseDoc(r io.Reader) (*Doc, error) {
	var doc Doc
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("attest: unparseable attestation document: %w", err)
	}
	switch doc.Coverage {
	case CoverageNone, CoverageAttested:
	default:
		return nil, fmt.Errorf("%w: unknown coverage state %q", ErrInvalidAttestation, doc.Coverage)
	}
	if doc.Coverage == CoverageNone && len(doc.Attestations) > 0 {
		return nil, fmt.Errorf("%w: coverage \"none\" with %d attestation records", ErrInvalidAttestation, len(doc.Attestations))
	}
	if doc.Coverage == CoverageAttested && len(doc.Attestations) == 0 {
		return nil, fmt.Errorf("%w: coverage \"attested\" with no attestation records", ErrInvalidAttestation)
	}
	return &doc, nil
}

// WalletStatementFromRecord rebuilds the canonical statement a "wallet_attested" record claims
// the wallet signed — from the PARSED fields, never from any served blob — ready for
// VerifyWalletStatement.
func WalletStatementFromRecord(rec WireRecord) (*WalletStatement, error) {
	if rec.Kind != KindWalletAttested {
		return nil, fmt.Errorf("%w: record kind %q is not %q", ErrInvalidAttestation, rec.Kind, KindWalletAttested)
	}
	asOf, err := time.Parse(WalletStatementTSFormat, rec.AsOf)
	if err != nil {
		return nil, fmt.Errorf("%w: asOf %q is not %q-formatted: %v", ErrWalletStatementInvalid, rec.AsOf, WalletStatementTSFormat, err)
	}
	balance, err := money.Parse(rec.AttestedBalance)
	if err != nil {
		return nil, fmt.Errorf("%w: attestedBalance %q is not a decimal: %v", ErrWalletStatementInvalid, rec.AttestedBalance, err)
	}
	challenge, err := hex.DecodeString(rec.Challenge)
	if err != nil {
		return nil, fmt.Errorf("%w: challenge is not hex: %v", ErrWalletStatementInvalid, err)
	}
	sig, err := hex.DecodeString(rec.Signature)
	if err != nil {
		return nil, fmt.Errorf("%w: signature is not hex: %v", ErrWalletStatementInvalid, err)
	}
	pubHex := rec.Payload["publicKey"]
	pub, err := hex.DecodeString(pubHex)
	if err != nil {
		return nil, fmt.Errorf("%w: payload publicKey is not hex: %v", ErrWalletStatementInvalid, err)
	}
	return &WalletStatement{
		SchemaVersion: WalletStatementSchemaVersion1,
		OperatorID:    rec.OperatorID,
		Currency:      rec.Currency,
		Balance:       balance,
		AsOf:          asOf,
		Challenge:     challenge,
		KeyID:         rec.Payload["keyId"],
		PublicKey:     pub,
		Signature:     sig,
	}, nil
}
