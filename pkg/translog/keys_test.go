package translog

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"
)

func testSigner(t *testing.T) *Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	s, err := NewSigner(priv)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return s
}

func TestKeys_SignVerifyRoundTrip(t *testing.T) {
	s := testSigner(t)
	hash := Genesis()
	hash[0] = 0xab
	sig := s.Sign(hash)
	if !VerifyEntryHash(s.PublicKey(), hash, sig) {
		t.Fatalf("signature does not verify")
	}
	other := Genesis()
	other[0] = 0xcd
	if VerifyEntryHash(s.PublicKey(), other, sig) {
		t.Fatalf("signature verified against a different hash")
	}
}

// TestKeys_DomainSeparation: the signature is over the CONTEXT-PREFIXED message, never the raw
// hash — a raw-hash verification must fail, so these signatures can never be replayed into
// another protocol that signs bare 32-byte digests with the same key.
func TestKeys_DomainSeparation(t *testing.T) {
	s := testSigner(t)
	hash := Genesis()
	hash[31] = 0x77
	sig := s.Sign(hash)
	if ed25519.Verify(s.PublicKey(), hash, sig) {
		t.Fatalf("signature verifies over the RAW hash — the domain-separation prefix is missing")
	}
	if !ed25519.Verify(s.PublicKey(), append([]byte(SignatureContext), hash...), sig) {
		t.Fatalf("signature does not verify over the prefixed message")
	}
}

func TestKeys_SignerFromSeedAndPrivateKeyAgree(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	fromPriv, err := NewSigner(priv)
	if err != nil {
		t.Fatalf("NewSigner(priv): %v", err)
	}
	fromSeed, err := NewSigner(priv.Seed())
	if err != nil {
		t.Fatalf("NewSigner(seed): %v", err)
	}
	if fromPriv.KeyID() != fromSeed.KeyID() {
		t.Fatalf("seed and private-key forms derive different key ids: %s vs %s", fromPriv.KeyID(), fromSeed.KeyID())
	}
	if _, err := NewSigner([]byte("short")); err == nil {
		t.Fatalf("NewSigner accepted garbage key material")
	}
}

// TestKeys_RegistryRotation: a receipt signed while key A was valid STILL verifies against A
// after rotation (Resolve at the entry's own timestamp answers A), and the NEW key B can never
// retroactively validate it — Resolve(B, oldTs) refuses, and B's public key rejects the old
// signature anyway.
func TestKeys_RegistryRotation(t *testing.T) {
	oldSigner := testSigner(t)
	newSigner := testSigner(t)

	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC) // rotation instant
	oldTs := t0.AddDate(0, 2, 0)                      // signed during A's era
	newTs := t1.AddDate(0, 1, 0)

	reg, err := NewKeyRegistry([]RegistryKey{
		{KeyID: oldSigner.KeyID(), PublicKey: oldSigner.PublicKey(), ValidFrom: t0, ValidTo: &t1},
		{KeyID: newSigner.KeyID(), PublicKey: newSigner.PublicKey(), ValidFrom: t1},
	})
	if err != nil {
		t.Fatalf("NewKeyRegistry: %v", err)
	}

	hash := Genesis()
	hash[5] = 0x42
	oldSig := oldSigner.Sign(hash)

	// The old receipt verifies against the key valid at ITS time.
	pub, err := reg.Resolve(oldSigner.KeyID(), oldTs)
	if err != nil {
		t.Fatalf("Resolve(old key at its own era): %v", err)
	}
	if !VerifyEntryHash(pub, hash, oldSig) {
		t.Fatalf("old receipt no longer verifies after rotation")
	}

	// The old key does NOT resolve for a post-rotation timestamp…
	if _, err := reg.Resolve(oldSigner.KeyID(), newTs); err == nil {
		t.Fatalf("rotated-out key resolved for a post-rotation timestamp")
	}
	// …and the NEW key neither resolves for the old era nor validates the old signature.
	if _, err := reg.Resolve(newSigner.KeyID(), oldTs); err == nil {
		t.Fatalf("new key resolved retroactively for a pre-rotation timestamp")
	}
	if VerifyEntryHash(newSigner.PublicKey(), hash, oldSig) {
		t.Fatalf("new key cryptographically validated the old key's signature")
	}
}

// TestKeys_RegistryPurposeRoundTrip: a registry holding both a chain-signing key and a
// wallet-attestation key resolves each by its own key id, keeps the purposes distinct through
// the published-document round trip, and answers KeysWithPurpose per job — the discriminator
// the STAKING-P5 wallet-key pin anchors on.
func TestKeys_RegistryPurposeRoundTrip(t *testing.T) {
	chainKey := testSigner(t)
	walletKey := testSigner(t)
	reg, err := NewKeyRegistry([]RegistryKey{
		{KeyID: chainKey.KeyID(), PublicKey: chainKey.PublicKey(), Purpose: KeyPurposeTranslog, ValidFrom: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
		{KeyID: walletKey.KeyID(), PublicKey: walletKey.PublicKey(), Purpose: KeyPurposeWalletAttest, ValidFrom: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)},
	})
	if err != nil {
		t.Fatalf("NewKeyRegistry: %v", err)
	}
	doc, err := reg.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	parsed, err := ParseKeyRegistry(doc)
	if err != nil {
		t.Fatalf("ParseKeyRegistry: %v", err)
	}
	for _, want := range []struct {
		keyID, purpose string
	}{
		{chainKey.KeyID(), KeyPurposeTranslog},
		{walletKey.KeyID(), KeyPurposeWalletAttest},
	} {
		entry, ok := parsed.Lookup(want.keyID)
		if !ok {
			t.Fatalf("key %s lost in round trip", want.keyID)
		}
		if entry.Purpose != want.purpose {
			t.Fatalf("key %s purpose %q after round trip, want %q", want.keyID, entry.Purpose, want.purpose)
		}
	}
	walletKeys := parsed.KeysWithPurpose(KeyPurposeWalletAttest)
	if len(walletKeys) != 1 || walletKeys[0].KeyID != walletKey.KeyID() {
		t.Fatalf("KeysWithPurpose(wallet-attest): %+v", walletKeys)
	}
	// A pre-purpose document (no purpose field) parses with Purpose empty — "unstated", which
	// purpose-pinned checks must treat as no anchor, never as a wildcard match.
	legacy, err := ParseKeyRegistry([]byte(`{"keys":[{"keyId":"` + chainKey.KeyID() + `","publicKey":"` + hex.EncodeToString(chainKey.PublicKey()) + `","validFrom":"2026-01-01T00:00:00Z"}]}`))
	if err != nil {
		t.Fatalf("ParseKeyRegistry (legacy doc): %v", err)
	}
	if entry, _ := legacy.Lookup(chainKey.KeyID()); entry.Purpose != "" {
		t.Fatalf("legacy entry invented a purpose: %q", entry.Purpose)
	}
	if got := legacy.KeysWithPurpose(KeyPurposeWalletAttest); len(got) != 0 {
		t.Fatalf("legacy no-purpose entry matched wallet-attest: %+v", got)
	}
}

func TestKeys_RegistryJSONRoundTrip(t *testing.T) {
	a := testSigner(t)
	b := testSigner(t)
	t1 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	reg, err := NewKeyRegistry([]RegistryKey{
		{KeyID: a.KeyID(), PublicKey: a.PublicKey(), ValidFrom: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), ValidTo: &t1},
		{KeyID: b.KeyID(), PublicKey: b.PublicKey(), ValidFrom: t1},
	})
	if err != nil {
		t.Fatalf("NewKeyRegistry: %v", err)
	}
	doc, err := reg.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	parsed, err := ParseKeyRegistry(doc)
	if err != nil {
		t.Fatalf("ParseKeyRegistry: %v", err)
	}
	hash := Genesis()
	hash[9] = 0x99
	sig := a.Sign(hash)
	pub, err := parsed.Resolve(a.KeyID(), time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Resolve after round trip: %v", err)
	}
	if !VerifyEntryHash(pub, hash, sig) {
		t.Fatalf("signature does not verify through the round-tripped registry")
	}
}
