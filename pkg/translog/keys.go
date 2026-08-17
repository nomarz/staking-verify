package translog

// Ed25519 receipt signing + the published key registry.
//
//	signature = Ed25519(sk, "nomarz-staking-v1:receipt:" || entry_hash)
//
// The context prefix is domain separation: a signature over a raw 32-byte hash could be replayed
// as a signature over anything else that hashes to those bytes in some other protocol sharing
// the key. With the prefix, a receipt signature verifies as a receipt signature and nothing
// else. Never sign an unprefixed hash with these keys.
//
// KEY MATERIAL DISCIPLINE (enforced by the callers, stated here because this is the API they
// call): the PRIVATE key is loaded from the environment only — never from a config file, never
// written to any database. The registry (the producer's signing-key table, and the published
// /staking/transparency/key document) holds ONLY public keys with validity windows, so a receipt
// signed years ago still verifies against the key that was valid AT ITS TIMESTAMP even after
// rotation — and a NEW key can never retroactively validate an old receipt.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SignatureContext is the domain-separation prefix prepended to the entry hash before signing.
const SignatureContext = "nomarz-staking-v1:receipt:"

// Registry key purposes: WHICH job a published key does. Persisted (the producer's signing-key table, purpose column)
// and published (GET /staking/transparency/key) — never rename. The purpose tag is what lets a
// verifier pin "the wallet service's attestation key" as a distinct trust anchor from the producer's own
// chain-signing key; without it, any registry entry looks interchangeable with any other.
const (
	// KeyPurposeTranslog: the producer's own chain/STH signing keys (the registry's historical
	// content — every pre-purpose row IS this).
	KeyPurposeTranslog = "staking-translog"
	// KeyPurposeWalletAttest: the wallet service's custodial-attestation keys
	// (pkg/attest wallet_attested), registered by the producer on each verified attestation.
	KeyPurposeWalletAttest = "wallet-attest"
)

// ErrKeyNotFound is returned by KeyRegistry.Resolve for an unknown key id.
var ErrKeyNotFound = errors.New("translog: key id not in registry")

// ErrKeyNotValidAt is returned by KeyRegistry.Resolve when the key exists but its validity
// window does not cover the requested instant.
var ErrKeyNotValidAt = errors.New("translog: key not valid at that time")

// ErrInvalidKey guards malformed key material.
var ErrInvalidKey = errors.New("translog: invalid key material")

// signingMessage builds the domain-separated message for one entry hash.
func signingMessage(entryHash []byte) []byte {
	msg := make([]byte, 0, len(SignatureContext)+len(entryHash))
	msg = append(msg, SignatureContext...)
	return append(msg, entryHash...)
}

// SignEntryHash signs one entry hash with the domain-separated context.
func SignEntryHash(priv ed25519.PrivateKey, entryHash []byte) []byte {
	return ed25519.Sign(priv, signingMessage(entryHash))
}

// VerifyEntryHash verifies a domain-separated entry-hash signature.
func VerifyEntryHash(pub ed25519.PublicKey, entryHash, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(pub, signingMessage(entryHash), sig)
}

// KeyIDFor derives the canonical key id for a public key: "ed25519:" + the first 8 bytes of
// SHA-256(pub), hex. Deriving the id from the key (rather than letting an operator name it)
// makes a registry row that claims one key id but carries another key's bytes detectable, and
// makes rotation automatic: a new key IS a new id.
func KeyIDFor(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return "ed25519:" + hex.EncodeToString(h[:8])
}

// Signer holds one Ed25519 private key plus its derived key id.
type Signer struct {
	priv  ed25519.PrivateKey
	keyID string
}

// NewSigner builds a Signer from raw key material: either a 32-byte Ed25519 seed or a 64-byte
// private key.
func NewSigner(key []byte) (*Signer, error) {
	var priv ed25519.PrivateKey
	switch len(key) {
	case ed25519.SeedSize:
		priv = ed25519.NewKeyFromSeed(key)
	case ed25519.PrivateKeySize:
		priv = ed25519.PrivateKey(append([]byte(nil), key...))
	default:
		return nil, fmt.Errorf("%w: want a %d-byte seed or %d-byte private key, got %d bytes",
			ErrInvalidKey, ed25519.SeedSize, ed25519.PrivateKeySize, len(key))
	}
	return &Signer{priv: priv, keyID: KeyIDFor(priv.Public().(ed25519.PublicKey))}, nil
}

// NewSignerFromBase64 builds a Signer from a base64 (std) encoded seed or private key — the
// encoding used by the environment variable the caller loads the key from.
func NewSignerFromBase64(s string) (*Signer, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("%w: not valid base64: %v", ErrInvalidKey, err)
	}
	return NewSigner(raw)
}

// KeyID returns the signer's derived key id.
func (s *Signer) KeyID() string { return s.keyID }

// PublicKey returns the signer's public key (32 bytes).
func (s *Signer) PublicKey() ed25519.PublicKey {
	return s.priv.Public().(ed25519.PublicKey)
}

// Sign signs one entry hash.
func (s *Signer) Sign(entryHash []byte) []byte {
	return SignEntryHash(s.priv, entryHash)
}

// RegistryKey is one published key with its validity window. ValidTo nil = still valid.
// Purpose says which job the key does (KeyPurposeTranslog | KeyPurposeWalletAttest); empty on
// entries parsed from a pre-purpose registry document, which verifiers treat as "unstated" —
// an unstated purpose never satisfies a purpose-pinned check.
type RegistryKey struct {
	KeyID     string
	PublicKey ed25519.PublicKey
	Purpose   string
	ValidFrom time.Time
	ValidTo   *time.Time
}

// KeyRegistry resolves key_id -> public key with validity windows.
type KeyRegistry struct {
	byID map[string]RegistryKey
}

// NewKeyRegistry builds a registry, refusing malformed or duplicate entries.
func NewKeyRegistry(keys []RegistryKey) (*KeyRegistry, error) {
	byID := make(map[string]RegistryKey, len(keys))
	for _, k := range keys {
		if k.KeyID == "" {
			return nil, fmt.Errorf("%w: empty key id", ErrInvalidKey)
		}
		if len(k.PublicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: key %s public key is %d bytes, want %d", ErrInvalidKey, k.KeyID, len(k.PublicKey), ed25519.PublicKeySize)
		}
		if _, dup := byID[k.KeyID]; dup {
			return nil, fmt.Errorf("%w: duplicate key id %s", ErrInvalidKey, k.KeyID)
		}
		byID[k.KeyID] = k
	}
	return &KeyRegistry{byID: byID}, nil
}

// Resolve returns the public key for keyID iff its validity window covers `at` — the instant the
// receipt being verified was signed (its entry's ts). A rotated-out key keeps validating the
// receipts from its own era; a key minted after `at` never validates them retroactively.
func (r *KeyRegistry) Resolve(keyID string, at time.Time) (ed25519.PublicKey, error) {
	k, ok := r.byID[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, keyID)
	}
	if at.Before(k.ValidFrom) {
		return nil, fmt.Errorf("%w: key %s valid from %s, entry at %s", ErrKeyNotValidAt, keyID, k.ValidFrom.UTC().Format(time.RFC3339), at.UTC().Format(time.RFC3339))
	}
	if k.ValidTo != nil && !at.Before(*k.ValidTo) {
		return nil, fmt.Errorf("%w: key %s valid until %s, entry at %s", ErrKeyNotValidAt, keyID, k.ValidTo.UTC().Format(time.RFC3339), at.UTC().Format(time.RFC3339))
	}
	return k.PublicKey, nil
}

// Lookup returns the registry entry for keyID with no validity-window check — the accessor a
// purpose-pinned cross-check uses to inspect Purpose and the raw key bytes before (separately)
// enforcing the window via Resolve.
func (r *KeyRegistry) Lookup(keyID string) (RegistryKey, bool) {
	k, ok := r.byID[keyID]
	return k, ok
}

// KeysWithPurpose returns the registry entries carrying exactly the given purpose, key-id
// ordered. An empty result means the registry publishes no key for that job.
func (r *KeyRegistry) KeysWithPurpose(purpose string) []RegistryKey {
	out := make([]RegistryKey, 0, len(r.byID))
	for _, k := range r.Keys() {
		if k.Purpose == purpose {
			out = append(out, k)
		}
	}
	return out
}

// Keys returns every registry entry, key-id ordered — the published document's stable order.
func (r *KeyRegistry) Keys() []RegistryKey {
	out := make([]RegistryKey, 0, len(r.byID))
	for _, k := range r.byID {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].KeyID < out[j].KeyID })
	return out
}

// registryKeyJSON is the published wire form of one registry key. PublicKey is hex — consistent
// with every other byte field this subsystem publishes. Purpose is omitempty so pre-purpose
// registry documents round-trip byte-identically; the server always publishes it (the column is
// NOT NULL with a default).
type registryKeyJSON struct {
	KeyID     string     `json:"keyId"`
	PublicKey string     `json:"publicKey"`
	Purpose   string     `json:"purpose,omitempty"`
	ValidFrom time.Time  `json:"validFrom"`
	ValidTo   *time.Time `json:"validTo,omitempty"`
}

type registryJSON struct {
	Keys []registryKeyJSON `json:"keys"`
}

// MarshalJSON serializes the registry as the published document: {"keys":[...]}, key-id ordered.
func (r *KeyRegistry) MarshalJSON() ([]byte, error) {
	doc := registryJSON{Keys: make([]registryKeyJSON, 0, len(r.byID))}
	for _, k := range r.Keys() {
		doc.Keys = append(doc.Keys, registryKeyJSON{
			KeyID: k.KeyID, PublicKey: hex.EncodeToString(k.PublicKey), Purpose: k.Purpose,
			ValidFrom: k.ValidFrom.UTC(), ValidTo: k.ValidTo,
		})
	}
	return json.Marshal(doc)
}

// ParseKeyRegistry parses the published registry document — the verifier's entry point for a
// registry fetched from /staking/transparency/key or provided as a local file.
func ParseKeyRegistry(data []byte) (*KeyRegistry, error) {
	var doc registryJSON
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	keys := make([]RegistryKey, 0, len(doc.Keys))
	for _, k := range doc.Keys {
		raw, err := hex.DecodeString(k.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("%w: key %s public key is not hex: %v", ErrInvalidKey, k.KeyID, err)
		}
		keys = append(keys, RegistryKey{KeyID: k.KeyID, PublicKey: raw, Purpose: k.Purpose, ValidFrom: k.ValidFrom, ValidTo: k.ValidTo})
	}
	return NewKeyRegistry(keys)
}
