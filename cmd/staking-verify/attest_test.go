package main

// STAKING-P5 verifier tests: a synthetic attestation document produced through pkg/attest's own
// producer path (the same code the HTTP handler uses), then verified — and broken — through
// VerifyAttestDoc, including the challenge-freshness binding against published tree heads.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/wasabi-gaming/staking-verify/internal/money"
	"github.com/wasabi-gaming/staking-verify/pkg/attest"
	"github.com/wasabi-gaming/staking-verify/pkg/translog"
)

// attestFakeWallet signs scripted statements with a fixed test key.
type attestFakeWallet struct {
	priv    ed25519.PrivateKey
	balance money.Amount
}

func (f *attestFakeWallet) AttestCustodialBalance(_ context.Context, operatorID string, currency int, challenge []byte) (*attest.WalletStatement, error) {
	st := &attest.WalletStatement{
		SchemaVersion: attest.WalletStatementSchemaVersion1,
		OperatorID:    operatorID,
		Currency:      currency,
		Balance:       f.balance,
		AsOf:          time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC),
		Challenge:     append([]byte(nil), challenge...),
	}
	if err := attest.SignWalletStatement(f.priv, st); err != nil {
		return nil, err
	}
	return st, nil
}

// attestFixturePriv is the fixture's deterministic "genuine wallet" signing key — tests that
// pin the wallet key derive the expected public key from it.
func attestFixturePriv() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 100)
	}
	return ed25519.NewKeyFromSeed(seed)
}

// buildAttestFixture returns a doc (as bytes) whose one wallet record is bound to root, plus
// the STH list publishing that root for the doc's pool. Signed by attestFixturePriv.
func buildAttestFixture(t *testing.T, balance, polTotal string) ([]byte, []*translog.STH, string) {
	t.Helper()
	return buildAttestFixtureWithKey(t, attestFixturePriv(), balance, polTotal)
}

// buildAttestFixtureWithKey is buildAttestFixture under an arbitrary signing key — how the pin
// tests construct a FORGED document: a fresh keypair yields a record that is internally
// self-consistent (it passes every no-pin check by construction) but matches no published
// wallet key.
func buildAttestFixtureWithKey(t *testing.T, priv ed25519.PrivateKey, balance, polTotal string) ([]byte, []*translog.STH, string) {
	t.Helper()
	op := uuid.New()
	poolID := uuid.NewString()
	root := bytes.Repeat([]byte{0x5a}, attest.ChallengeSize)

	attestor, err := attest.NewWalletAttestor(&attestFakeWallet{priv: priv, balance: money.MustParse(balance)})
	if err != nil {
		t.Fatalf("NewWalletAttestor: %v", err)
	}
	a, err := attestor.Attest(context.Background(), op, 150, root)
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	doc := &attest.Doc{
		EpochID: 3, EpochDate: "2026-08-11", PoolID: poolID, Currency: 150,
		PolRootHash:    strings.Repeat("cd", 32),
		PolTotalAmount: money.MustParse(polTotal).StringFixed(attest.WalletStatementAmountScale),
		PolPublishedAt: time.Now().UTC().Format(time.RFC3339),
		Coverage:       attest.CoverageAttested,
		AttestedTotal:  a.Balance.StringFixed(attest.WalletStatementAmountScale),
		Attestations:   []attest.WireRecord{attest.NewWireRecord(a, time.Now())},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	sths := []*translog.STH{{
		SchemaVersion: translog.SchemaVersion1, OperatorID: op.String(), PoolID: poolID,
		TreeSize: 9, RootHash: root, TS: time.Now().UTC().Truncate(time.Microsecond),
	}}
	return raw, sths, poolID
}

func TestVerifyAttestDocHappyPath(t *testing.T) {
	raw, sths, poolID := buildAttestFixture(t, "500", "400")
	sum, err := VerifyAttestDoc(bytes.NewReader(raw), sths, AttestOptions{})
	if err != nil {
		t.Fatalf("VerifyAttestDoc: %v", err)
	}
	if sum.WalletVerified != 1 || sum.PoolID != poolID || !sum.ChallengeChecked {
		t.Fatalf("summary: %+v", sum)
	}
	if sum.AttestedTotal == nil || !sum.AttestedTotal.Equal(money.MustParse("500")) {
		t.Fatalf("attested total: %+v", sum.AttestedTotal)
	}
	// The summary reports the arithmetic as data; no field of it is a solvency verdict.
	var out bytes.Buffer
	WriteAttestSummary(&out, sum)
	rendered := strings.ToLower(out.String())
	if strings.Contains(rendered, "proof of reserves") || strings.Contains(rendered, "proof of assets") {
		t.Fatalf("forbidden claim wording in CLI output:\n%s", out.String())
	}
	if !strings.Contains(rendered, "cannot verify the assets exist") {
		t.Fatalf("CLI output must state the trust boundary:\n%s", out.String())
	}
	// Review M2: the comparison must name what the figure IS ("attested custodial balance
	// (wallet ledger)", never "attested assets"), surface the record's own basis note beside
	// it, and state the scale-not-coverage caveat with the number.
	if strings.Contains(rendered, "attested assets") {
		t.Fatalf("comparison wording implies asset coverage:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "attested custodial balance (wallet ledger)") {
		t.Fatalf("comparison must name the custodial-balance basis:\n%s", out.String())
	}
	if len(sum.WalletBases) != 1 || !strings.Contains(out.String(), "attest: basis of the attested figure — "+sum.WalletBases[0]) {
		t.Fatalf("the record's basis note must print next to the comparison (bases %v):\n%s", sum.WalletBases, out.String())
	}
	if !strings.Contains(out.String(), "scale, not coverage") {
		t.Fatalf("the scale-not-coverage caveat must accompany the comparison:\n%s", out.String())
	}
}

func TestVerifyAttestDocRefusesForeignChallenge(t *testing.T) {
	// A challenge matching NO published head of the pool = an attestation not bound to the
	// pool's public log state — the freshness check must fail it.
	raw, sths, _ := buildAttestFixture(t, "500", "400")
	sths[0].RootHash = bytes.Repeat([]byte{0x77}, attest.ChallengeSize) // published set no longer contains it
	if _, err := VerifyAttestDoc(bytes.NewReader(raw), sths, AttestOptions{}); err == nil {
		t.Fatal("challenge matching no published head verified")
	}
	// Without -sth material the check is skipped but REPORTED as skipped.
	sum, err := VerifyAttestDoc(bytes.NewReader(raw), nil, AttestOptions{})
	if err != nil {
		t.Fatalf("VerifyAttestDoc without sths: %v", err)
	}
	if sum.ChallengeChecked {
		t.Fatal("ChallengeChecked must be false without -sth material")
	}
	var out bytes.Buffer
	WriteAttestSummary(&out, sum)
	if !strings.Contains(out.String(), "WARNING") {
		t.Fatalf("skipped challenge check must warn:\n%s", out.String())
	}
}

func TestVerifyAttestDocRefusesEditedBalance(t *testing.T) {
	raw, sths, _ := buildAttestFixture(t, "500", "400")
	edited := bytes.Replace(raw,
		[]byte(`"attestedBalance":"500.000000000000000000"`),
		[]byte(`"attestedBalance":"999.000000000000000000"`), 1)
	if bytes.Equal(edited, raw) {
		t.Fatal("fixture edit did not apply")
	}
	if _, err := VerifyAttestDoc(bytes.NewReader(edited), sths, AttestOptions{}); err == nil {
		t.Fatal("edited balance verified — the wallet signature check is not binding the figure")
	}
}

func TestVerifyAttestDocRefusesTotalMismatch(t *testing.T) {
	raw, sths, _ := buildAttestFixture(t, "500", "400")
	edited := bytes.Replace(raw,
		[]byte(`"attestedTotal":"500.000000000000000000"`),
		[]byte(`"attestedTotal":"600.000000000000000000"`), 1)
	if bytes.Equal(edited, raw) {
		t.Fatal("fixture edit did not apply")
	}
	if _, err := VerifyAttestDoc(bytes.NewReader(edited), sths, AttestOptions{}); err == nil {
		t.Fatal("served attestedTotal != Σ records verified")
	}
}

// TestVerifyAttestDocForgedKeyRejectedByWalletKeyPin is THE regression test for the P5
// trust-anchor gap: a forged attestation — fresh Ed25519 keypair, internally self-consistent,
// signature valid under its own embedded key — passed every check this tool ran before the pin
// existed. With the wallet key pinned, the forgery must be REJECTED and the genuine document
// must still pass, with the stronger claim in the output.
func TestVerifyAttestDocForgedKeyRejectedByWalletKeyPin(t *testing.T) {
	genuinePub := attestFixturePriv().Public().(ed25519.PublicKey)

	// The forgery: a fresh keypair nobody published, run through the SAME producer path.
	forgedSeed := make([]byte, ed25519.SeedSize)
	for i := range forgedSeed {
		forgedSeed[i] = byte(200 - i)
	}
	forgedPriv := ed25519.NewKeyFromSeed(forgedSeed)
	forgedRaw, forgedSTHs, _ := buildAttestFixtureWithKey(t, forgedPriv, "999999", "400")

	// Without a pin the forgery VERIFIES — that is the gap: internal self-consistency is all
	// today's embedded-key check can establish. Asserted here so this test breaks loudly if the
	// fixture ever stops modeling the attack.
	if _, err := VerifyAttestDoc(bytes.NewReader(forgedRaw), forgedSTHs, AttestOptions{}); err != nil {
		t.Fatalf("forged doc must be internally self-consistent (the attack's premise): %v", err)
	}

	// With the genuine wallet key pinned, the forgery is rejected…
	pinned := AttestOptions{WalletKey: genuinePub}
	if _, err := VerifyAttestDoc(bytes.NewReader(forgedRaw), forgedSTHs, pinned); err == nil {
		t.Fatal("FORGED attestation (fresh keypair) verified despite a pinned wallet key")
	} else if !strings.Contains(err.Error(), "does NOT match the -wallet-key pin") {
		t.Fatalf("rejection must name the pin mismatch, got: %v", err)
	}

	// …and the genuine document still passes, now with the stronger, true claim.
	genuineRaw, genuineSTHs, _ := buildAttestFixture(t, "500", "400")
	sum, err := VerifyAttestDoc(bytes.NewReader(genuineRaw), genuineSTHs, pinned)
	if err != nil {
		t.Fatalf("genuine doc under the correct pin: %v", err)
	}
	if !sum.WalletKeyPinned || sum.WalletVerified != 1 {
		t.Fatalf("pinned summary: %+v", sum)
	}
	var out bytes.Buffer
	WriteAttestSummary(&out, sum)
	if !strings.Contains(out.String(), "under the wallet service's published attestation key") {
		t.Fatalf("pinned output must carry the (now true) published-key claim:\n%s", out.String())
	}
}

// TestVerifyAttestDocForgedKeyRejectedByRegistryPin: the same forged-vs-genuine matrix through
// the registry-file mechanism — a purpose:"wallet-attest" entry pins the key; entries with
// other purposes (the producer's own translog key) pin nothing and can never be matched as wallet keys.
func TestVerifyAttestDocForgedKeyRejectedByRegistryPin(t *testing.T) {
	genuinePub := attestFixturePriv().Public().(ed25519.PublicKey)
	genuineKeyID := attest.WalletKeyID(genuinePub)
	validFrom := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) // covers the fixture's asOf (2026-08-11)

	forgedSeed := make([]byte, ed25519.SeedSize)
	for i := range forgedSeed {
		forgedSeed[i] = byte(150 + i)
	}
	forgedPriv := ed25519.NewKeyFromSeed(forgedSeed)
	forgedPub := forgedPriv.Public().(ed25519.PublicKey)
	forgedRaw, forgedSTHs, _ := buildAttestFixtureWithKey(t, forgedPriv, "77777", "400")
	genuineRaw, genuineSTHs, _ := buildAttestFixture(t, "500", "400")

	registryWith := func(keys ...translog.RegistryKey) *translog.KeyRegistry {
		t.Helper()
		reg, err := translog.NewKeyRegistry(keys)
		if err != nil {
			t.Fatalf("NewKeyRegistry: %v", err)
		}
		return reg
	}
	walletEntry := translog.RegistryKey{
		KeyID: genuineKeyID, PublicKey: genuinePub,
		Purpose: translog.KeyPurposeWalletAttest, ValidFrom: validFrom,
	}

	// Genuine doc + registry carrying the wallet-attest entry: pinned, passes.
	sum, err := VerifyAttestDoc(bytes.NewReader(genuineRaw), genuineSTHs, AttestOptions{Registry: registryWith(walletEntry)})
	if err != nil {
		t.Fatalf("genuine doc under the registry pin: %v", err)
	}
	if !sum.WalletKeyPinned {
		t.Fatalf("registry wallet-attest entry must count as pin material: %+v", sum)
	}

	// Forged doc + the same registry: its key is not published there — rejected.
	if _, err := VerifyAttestDoc(bytes.NewReader(forgedRaw), forgedSTHs, AttestOptions{Registry: registryWith(walletEntry)}); err == nil {
		t.Fatal("FORGED attestation verified despite a registry wallet-attest pin")
	} else if !strings.Contains(err.Error(), "NOT in the supplied registry") {
		t.Fatalf("rejection must name the missing registry entry, got: %v", err)
	}

	// The forged key REGISTERED — but under the translog purpose (e.g. the producer's own chain key
	// being passed off as the wallet's): purpose mismatch, rejected. The registry still carries
	// a real wallet-attest entry, so pin material exists and the check is armed.
	forgedAsTranslog := translog.RegistryKey{
		KeyID: attest.WalletKeyID(forgedPub), PublicKey: forgedPub,
		Purpose: translog.KeyPurposeTranslog, ValidFrom: validFrom,
	}
	if _, err := VerifyAttestDoc(bytes.NewReader(forgedRaw), forgedSTHs, AttestOptions{Registry: registryWith(walletEntry, forgedAsTranslog)}); err == nil {
		t.Fatal("a translog-purpose registry entry anchored a wallet attestation")
	} else if !strings.Contains(err.Error(), "purpose") {
		t.Fatalf("rejection must name the purpose mismatch, got: %v", err)
	}

	// A registry with NO wallet-attest entry (pre-purpose document, or the wallet key never
	// registered) supplies no anchor: verification passes but MUST NOT report pinned.
	sum, err = VerifyAttestDoc(bytes.NewReader(forgedRaw), forgedSTHs, AttestOptions{Registry: registryWith(forgedAsTranslog)})
	if err != nil {
		t.Fatalf("no-anchor registry must fall back to unpinned verification: %v", err)
	}
	if sum.WalletKeyPinned {
		t.Fatal("a registry with no wallet-attest entry must not report the key as pinned")
	}
}

// TestVerifyAttestDocUnpinnedWordingNeverOverclaims: the golden-output guard for the no-pin
// case — the tool must state, verbatim, that the embedded key was checked against nothing
// independently published, and must never emit the old "wallet service's own key" overclaim.
func TestVerifyAttestDocUnpinnedWordingNeverOverclaims(t *testing.T) {
	raw, sths, _ := buildAttestFixture(t, "500", "400")
	sum, err := VerifyAttestDoc(bytes.NewReader(raw), sths, AttestOptions{})
	if err != nil {
		t.Fatalf("VerifyAttestDoc: %v", err)
	}
	if sum.WalletKeyPinned {
		t.Fatalf("no pin material was supplied, summary claims pinned: %+v", sum)
	}
	var out bytes.Buffer
	WriteAttestSummary(&out, sum)
	const unpinnedLine = "attest: 1 wallet-attested record(s): signature valid over the re-canonicalized statement under the record's OWN embedded key — NOT checked against any independently published wallet key (supply -wallet-key or a registry with a wallet-attest purpose entry to pin it)\n"
	if !strings.Contains(out.String(), unpinnedLine) {
		t.Fatalf("unpinned output must carry the exact honest wording, got:\n%s", out.String())
	}
	for _, overclaim := range []string{"wallet service's own key", "wallet service's published attestation key"} {
		if strings.Contains(out.String(), overclaim) {
			t.Fatalf("unpinned output overclaims (%q):\n%s", overclaim, out.String())
		}
	}
}

func TestVerifyAttestDocCoverageNone(t *testing.T) {
	doc := &attest.Doc{
		EpochID: 4, EpochDate: "2026-08-12", PoolID: uuid.NewString(), Currency: 150,
		PolRootHash:    strings.Repeat("ef", 32),
		PolTotalAmount: "250.000000000000000000",
		PolPublishedAt: time.Now().UTC().Format(time.RFC3339),
		Coverage:       attest.CoverageNone,
	}
	raw, _ := json.Marshal(doc)
	sum, err := VerifyAttestDoc(bytes.NewReader(raw), nil, AttestOptions{})
	if err != nil {
		t.Fatalf("VerifyAttestDoc: %v", err)
	}
	if sum.Coverage != attest.CoverageNone || sum.AttestedTotal != nil {
		t.Fatalf("coverage-none summary: %+v", sum)
	}
	var out bytes.Buffer
	WriteAttestSummary(&out, sum)
	// The "none" report must name the unattested state distinctly — never render it as an
	// attested zero or as insolvency.
	if !strings.Contains(out.String(), "coverage NONE") || !strings.Contains(out.String(), "absence of any claim") {
		t.Fatalf("coverage-none report must state the distinction:\n%s", out.String())
	}
	if hexTotal := hex.EncodeToString([]byte("0.000000000000000000")); strings.Contains(out.String(), hexTotal) {
		t.Fatalf("unexpected zero rendering:\n%s", out.String())
	}
}
