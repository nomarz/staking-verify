package attest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/wasabi-gaming/staking-verify/internal/money"
)

// katSeed/katStatement pin the CROSS-SERVICE known-answer vector. The wallet service's own
// attestation-signing code carries the IDENTICAL vector (same seed, same fields, same expected
// canonical bytes) — if either side's canonicalization drifts, its copy of this test breaks.
func katSeed() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func katStatement() WalletStatement {
	return WalletStatement{
		SchemaVersion: WalletStatementSchemaVersion1,
		OperatorID:    "11111111-1111-1111-1111-111111111111",
		Currency:      150,
		Balance:       money.MustParse("12345.6789"),
		AsOf:          time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC),
		Challenge:     bytes.Repeat([]byte{0xab}, ChallengeSize),
	}
}

// katCanonical is the expected canonical bytes of katStatement — the cross-repo contract,
// byte for byte.
const katCanonical = `{"as_of":"2026-08-11T00:00:00.000000Z",` +
	`"challenge":"abababababababababababababababababababababababababababababababab",` +
	`"currency":150,` +
	`"custodial_balance":"12345.678900000000000000",` +
	`"operator_id":"11111111-1111-1111-1111-111111111111",` +
	`"schema_version":1}`

func TestWalletStatementCanonicalKnownAnswer(t *testing.T) {
	got, err := katStatement().CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	if string(got) != katCanonical {
		t.Fatalf("canonical drift:\n got %s\nwant %s", got, katCanonical)
	}
}

func TestWalletStatementSignVerifyRoundTrip(t *testing.T) {
	priv := katSeed()
	st := katStatement()
	if err := SignWalletStatement(priv, &st); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if st.KeyID != WalletKeyID(priv.Public().(ed25519.PublicKey)) {
		t.Fatalf("key id not stamped from the signing key: %s", st.KeyID)
	}
	if err := VerifyWalletStatement(st); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestWalletStatementTamperBreaksSignature(t *testing.T) {
	priv := katSeed()
	tamper := map[string]func(*WalletStatement){
		"balance":   func(s *WalletStatement) { s.Balance = money.MustParse("99999") },
		"operator":  func(s *WalletStatement) { s.OperatorID = uuid.NewString() },
		"currency":  func(s *WalletStatement) { s.Currency = 151 },
		"as_of":     func(s *WalletStatement) { s.AsOf = s.AsOf.Add(time.Microsecond) },
		"challenge": func(s *WalletStatement) { s.Challenge[0] ^= 0x01 },
		"key_id":    func(s *WalletStatement) { s.KeyID = "ed25519:0000000000000000" },
	}
	for name, mutate := range tamper {
		st := katStatement()
		st.Challenge = append([]byte(nil), st.Challenge...)
		if err := SignWalletStatement(priv, &st); err != nil {
			t.Fatalf("%s: sign: %v", name, err)
		}
		mutate(&st)
		if err := VerifyWalletStatement(st); err == nil {
			t.Fatalf("%s: tampered statement verified", name)
		}
	}
}

func TestWalletStatementContextDomainSeparation(t *testing.T) {
	// A signature over the raw canonical bytes (no context) must NOT verify: the context
	// prefix is what keeps this key's attestation signatures from being replayed as anything
	// else, and vice versa.
	priv := katSeed()
	st := katStatement()
	canonical, err := st.CanonicalJSON()
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	st.Signature = ed25519.Sign(priv, canonical) // deliberately unprefixed
	st.PublicKey = priv.Public().(ed25519.PublicKey)
	st.KeyID = WalletKeyID(st.PublicKey)
	if err := VerifyWalletStatement(st); err == nil {
		t.Fatal("context-free signature verified — domain separation broken")
	}
	if !strings.HasPrefix(WalletStatementContext, "nomarz-wallet-v1:") {
		t.Fatalf("context %q lost its wallet-service namespace", WalletStatementContext)
	}
}

// fakeWalletClient scripts one AttestCustodialBalance response, with optional mutation after
// signing — the mock-the-boundary convention of this repo's wallet-dependent tests.
type fakeWalletClient struct {
	priv   ed25519.PrivateKey
	mutate func(*WalletStatement)
	err    error
}

func (f *fakeWalletClient) AttestCustodialBalance(_ context.Context, operatorID string, currency int, challenge []byte) (*WalletStatement, error) {
	if f.err != nil {
		return nil, f.err
	}
	st := &WalletStatement{
		SchemaVersion: WalletStatementSchemaVersion1,
		OperatorID:    operatorID,
		Currency:      currency,
		Balance:       money.MustParse("777.5"),
		AsOf:          time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC),
		Challenge:     append([]byte(nil), challenge...),
	}
	if err := SignWalletStatement(f.priv, st); err != nil {
		return nil, err
	}
	if f.mutate != nil {
		f.mutate(st)
	}
	return st, nil
}

func TestWalletAttestorHappyPath(t *testing.T) {
	att, err := NewWalletAttestor(&fakeWalletClient{priv: katSeed()})
	if err != nil {
		t.Fatalf("NewWalletAttestor: %v", err)
	}
	op := uuid.New()
	challenge := bytes.Repeat([]byte{0x42}, ChallengeSize)
	got, err := att.Attest(context.Background(), op, 150, challenge)
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if got.Kind != KindWalletAttested || att.Kind() != KindWalletAttested {
		t.Fatalf("kind: got %s / %s", got.Kind, att.Kind())
	}
	if !bytes.Equal(got.Challenge, challenge) {
		t.Fatal("challenge not carried through")
	}
	if !got.Balance.Equal(money.MustParse("777.5")) {
		t.Fatalf("balance: %s", got.Balance.StringFixed(WalletStatementAmountScale))
	}
	if got.Payload["keyId"] == "" || got.Payload["publicKey"] == "" {
		t.Fatal("payload must carry the wallet's key material (key id + public key)")
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestWalletAttestorRefusesUnechoedChallenge(t *testing.T) {
	// The wallet answering with a DIFFERENT challenge than asked (a replay of an older signed
	// statement, or a bug) must be refused, never recorded.
	stale := bytes.Repeat([]byte{0x01}, ChallengeSize)
	att, _ := NewWalletAttestor(&fakeWalletClient{priv: katSeed(), mutate: func(s *WalletStatement) {
		s.Challenge = stale // signature stays valid over the STALE bytes — the echo check must catch it
		_ = SignWalletStatement(katSeed(), s)
	}})
	_, err := att.Attest(context.Background(), uuid.New(), 150, bytes.Repeat([]byte{0x42}, ChallengeSize))
	if !errors.Is(err, ErrWalletStatementMismatch) {
		t.Fatalf("want ErrWalletStatementMismatch, got %v", err)
	}
}

func TestWalletAttestorRefusesMismatchedEcho(t *testing.T) {
	op := uuid.New()
	cases := map[string]func(*WalletStatement){
		"operator": func(s *WalletStatement) { s.OperatorID = uuid.NewString(); _ = SignWalletStatement(katSeed(), s) },
		"currency": func(s *WalletStatement) { s.Currency = 999; _ = SignWalletStatement(katSeed(), s) },
	}
	for name, mutate := range cases {
		att, _ := NewWalletAttestor(&fakeWalletClient{priv: katSeed(), mutate: mutate})
		_, err := att.Attest(context.Background(), op, 150, bytes.Repeat([]byte{0x42}, ChallengeSize))
		if !errors.Is(err, ErrWalletStatementMismatch) {
			t.Fatalf("%s: want ErrWalletStatementMismatch, got %v", name, err)
		}
	}
}

func TestWalletAttestorRefusesBadSignature(t *testing.T) {
	att, _ := NewWalletAttestor(&fakeWalletClient{priv: katSeed(), mutate: func(s *WalletStatement) {
		s.Signature[0] ^= 0x01
	}})
	_, err := att.Attest(context.Background(), uuid.New(), 150, bytes.Repeat([]byte{0x42}, ChallengeSize))
	if !errors.Is(err, ErrWalletStatementSignature) {
		t.Fatalf("want ErrWalletStatementSignature, got %v", err)
	}
}
