package translog

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func sthTestSigner(t *testing.T) *Signer {
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

func sampleSTH() STH {
	root := make([]byte, HashSize)
	for i := range root {
		root[i] = byte(i)
	}
	return STH{
		SchemaVersion: SchemaVersion1,
		OperatorID:    "0b6f9f74-3a5e-4f2b-9a58-6f7d2f6a1c11",
		PoolID:        "9f6e7f3a-1b2c-4d5e-8f90-a1b2c3d4e5f6",
		TreeSize:      42,
		RootHash:      root,
		TS:            time.Date(2026, 8, 11, 9, 30, 0, 123456000, time.UTC),
	}
}

// TestSTH_CanonicalJSONGolden pins the exact signed bytes: JCS field order over the fixed set,
// hex root, TSFormat timestamp. Any change to this string is a BREAKING change to every signed
// STH in existence.
func TestSTH_CanonicalJSONGolden(t *testing.T) {
	got, err := sampleSTH().CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	want := `{"operator_id":"0b6f9f74-3a5e-4f2b-9a58-6f7d2f6a1c11",` +
		`"pool_id":"9f6e7f3a-1b2c-4d5e-8f90-a1b2c3d4e5f6",` +
		`"root_hash":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",` +
		`"schema_version":1,"tree_size":42,"ts":"2026-08-11T09:30:00.123456Z"}`
	if string(got) != want {
		t.Fatalf("canonical STH:\n got %s\nwant %s", got, want)
	}
}

func TestSTH_ValidateRefusesMalformed(t *testing.T) {
	for name, mutate := range map[string]func(*STH){
		"wrong schema":  func(s *STH) { s.SchemaVersion = 2 },
		"no operator":   func(s *STH) { s.OperatorID = "" },
		"no pool":       func(s *STH) { s.PoolID = "" },
		"zero size":     func(s *STH) { s.TreeSize = 0 },
		"negative size": func(s *STH) { s.TreeSize = -3 },
		"short root":    func(s *STH) { s.RootHash = s.RootHash[:31] },
		"zero ts":       func(s *STH) { s.TS = time.Time{} },
	} {
		s := sampleSTH()
		mutate(&s)
		if _, err := s.CanonicalJSON(); err == nil {
			t.Fatalf("%s: canonicalized a malformed STH", name)
		}
	}
}

func TestSTH_SignVerifyRoundTrip(t *testing.T) {
	signer := sthTestSigner(t)
	s := sampleSTH()
	if err := signer.SignSTH(&s); err != nil {
		t.Fatalf("SignSTH: %v", err)
	}
	if s.KeyID != signer.KeyID() || len(s.Signature) != ed25519.SignatureSize {
		t.Fatalf("SignSTH stamped keyId %q / %d-byte signature", s.KeyID, len(s.Signature))
	}
	if !VerifySTH(signer.PublicKey(), s) {
		t.Fatalf("freshly signed STH does not verify")
	}
	// Any signed-field edit must break verification.
	for name, mutate := range map[string]func(*STH){
		"tree_size": func(x *STH) { x.TreeSize++ },
		"root_hash": func(x *STH) { x.RootHash = append([]byte(nil), x.RootHash...); x.RootHash[0] ^= 0x01 },
		"ts":        func(x *STH) { x.TS = x.TS.Add(time.Microsecond) },
		"pool":      func(x *STH) { x.PoolID = x.OperatorID }, // replay under another pool id
		"operator":  func(x *STH) { x.OperatorID = x.PoolID },
	} {
		mutated := s
		mutate(&mutated)
		if VerifySTH(signer.PublicKey(), mutated) {
			t.Fatalf("STH with edited %s still verifies", name)
		}
	}
	// Unsigned or wrong-key must not verify.
	unsigned := sampleSTH()
	if VerifySTH(signer.PublicKey(), unsigned) {
		t.Fatalf("unsigned STH verifies")
	}
	other := sthTestSigner(t)
	if VerifySTH(other.PublicKey(), s) {
		t.Fatalf("STH verifies under the WRONG key")
	}
}

// TestSTH_DomainSeparationFromReceipts is the cross-rejection guarantee: the SAME key signs both
// receipts (entry hashes) and STHs (canonical payloads), and the ONLY thing keeping the two
// artifact kinds apart is the context prefix. A signature produced under one context must never
// verify under the other over the same underlying bytes, in either direction.
func TestSTH_DomainSeparationFromReceipts(t *testing.T) {
	if STHSignatureContext == SignatureContext {
		t.Fatalf("STH and receipt signature contexts are IDENTICAL — domain separation is gone")
	}
	if strings.HasPrefix(STHSignatureContext, SignatureContext) || strings.HasPrefix(SignatureContext, STHSignatureContext) {
		t.Fatalf("one signature context is a prefix of the other (%q / %q) — a crafted payload could straddle them", STHSignatureContext, SignatureContext)
	}
	signer := sthTestSigner(t)
	s := sampleSTH()
	canonical, err := s.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}

	// Direction 1: a receipt signature over the canonical STH bytes must not verify as an STH
	// signature over those same bytes.
	receiptSig := signer.Sign(canonical) // Sign = the RECEIPT context
	forged := s
	forged.Signature = receiptSig
	forged.KeyID = signer.KeyID()
	if VerifySTH(signer.PublicKey(), forged) {
		t.Fatalf("a RECEIPT signature verified as an STH signature over the same bytes")
	}

	// Direction 2: a genuine STH signature must not verify as a receipt signature over the same
	// underlying bytes.
	if err := signer.SignSTH(&s); err != nil {
		t.Fatalf("SignSTH: %v", err)
	}
	if VerifyEntryHash(signer.PublicKey(), canonical, s.Signature) {
		t.Fatalf("an STH signature verified as a RECEIPT signature over the same bytes")
	}
}

func TestSTH_WireLineRoundTrip(t *testing.T) {
	signer := sthTestSigner(t)
	s := sampleSTH()
	if err := signer.SignSTH(&s); err != nil {
		t.Fatalf("SignSTH: %v", err)
	}
	line, err := s.MarshalSTHLine()
	if err != nil {
		t.Fatalf("MarshalSTHLine: %v", err)
	}
	parsed, err := ParseSTHLine(line)
	if err != nil {
		t.Fatalf("ParseSTHLine: %v", err)
	}
	if parsed.TreeSize != s.TreeSize || !bytes.Equal(parsed.RootHash, s.RootHash) ||
		!parsed.TS.Equal(s.TS) || parsed.KeyID != s.KeyID || !bytes.Equal(parsed.Signature, s.Signature) ||
		parsed.OperatorID != s.OperatorID || parsed.PoolID != s.PoolID {
		t.Fatalf("round trip mutated the STH:\n in %+v\nout %+v", s, parsed)
	}
	if !VerifySTH(signer.PublicKey(), *parsed) {
		t.Fatalf("round-tripped STH no longer verifies")
	}
	// A value edit on the wire is caught by re-verification.
	tampered := bytes.Replace(line, []byte(`"treeSize":42`), []byte(`"treeSize":43`), 1)
	if bytes.Equal(tampered, line) {
		t.Fatalf("tamper substitution did not apply")
	}
	parsedTampered, err := ParseSTHLine(tampered)
	if err != nil {
		t.Fatalf("ParseSTHLine(tampered): %v", err)
	}
	if VerifySTH(signer.PublicKey(), *parsedTampered) {
		t.Fatalf("tampered wire STH still verifies")
	}
	// Unknown fields are refused (DisallowUnknownFields, same as export lines).
	withExtra := append(bytes.TrimSuffix(line, []byte("}")), []byte(`,"x":1}`)...)
	if _, err := ParseSTHLine(withExtra); err == nil {
		t.Fatalf("sth line with an unknown field parsed")
	}
	// Unsigned wire form omits keyId/signature entirely and still round-trips.
	unsigned := sampleSTH()
	uline, err := unsigned.MarshalSTHLine()
	if err != nil {
		t.Fatalf("MarshalSTHLine(unsigned): %v", err)
	}
	if bytes.Contains(uline, []byte("keyId")) || bytes.Contains(uline, []byte("signature")) {
		t.Fatalf("unsigned wire line carries signature fields: %s", uline)
	}
	uparsed, err := ParseSTHLine(uline)
	if err != nil {
		t.Fatalf("ParseSTHLine(unsigned): %v", err)
	}
	if uparsed.KeyID != "" || uparsed.Signature != nil {
		t.Fatalf("unsigned round trip invented a signature")
	}
}

func TestSTH_WireLineGolden(t *testing.T) {
	s := sampleSTH()
	line, err := s.MarshalSTHLine()
	if err != nil {
		t.Fatalf("MarshalSTHLine: %v", err)
	}
	want := `{"operatorId":"0b6f9f74-3a5e-4f2b-9a58-6f7d2f6a1c11",` +
		`"poolId":"9f6e7f3a-1b2c-4d5e-8f90-a1b2c3d4e5f6",` +
		`"rootHash":"` + hex.EncodeToString(s.RootHash) + `",` +
		`"schemaVersion":1,"treeSize":42,"ts":"2026-08-11T09:30:00.123456Z"}`
	if string(line) != want {
		t.Fatalf("wire line:\n got %s\nwant %s", line, want)
	}
}

// TestSTH_WireLineEscapesNonUUIDIdentifiers (P2-P5 review L4): STH.Validate only requires
// operator_id/pool_id to be non-empty — not uuid-shaped — so the wire writer must never assume
// the value is safe to splice raw into a JSON string literal. A value carrying `"`/`\` must
// still yield one valid, parseable line that round-trips to the same field values.
func TestSTH_WireLineEscapesNonUUIDIdentifiers(t *testing.T) {
	s := sampleSTH()
	s.OperatorID = `evil"op\id`
	s.PoolID = "pool\twith\ncontrols"
	line, err := s.MarshalSTHLine()
	if err != nil {
		t.Fatalf("MarshalSTHLine: %v", err)
	}
	var generic map[string]interface{}
	if err := json.Unmarshal(line, &generic); err != nil {
		t.Fatalf("wire line is not valid JSON: %v\nline: %s", err, line)
	}
	parsed, err := ParseSTHLine(line)
	if err != nil {
		t.Fatalf("ParseSTHLine: %v", err)
	}
	if parsed.OperatorID != s.OperatorID || parsed.PoolID != s.PoolID {
		t.Fatalf("escaped ids did not round-trip: got op %q pool %q, want op %q pool %q",
			parsed.OperatorID, parsed.PoolID, s.OperatorID, s.PoolID)
	}
	// And a signed one still verifies after the round trip — the canonical (signed) form and the
	// wire form escape identically, so nothing drifts between them.
	signer := sthTestSigner(t)
	if err := signer.SignSTH(&s); err != nil {
		t.Fatalf("SignSTH: %v", err)
	}
	sline, err := s.MarshalSTHLine()
	if err != nil {
		t.Fatalf("MarshalSTHLine(signed): %v", err)
	}
	sparsed, err := ParseSTHLine(sline)
	if err != nil {
		t.Fatalf("ParseSTHLine(signed): %v", err)
	}
	if !VerifySTH(signer.PublicKey(), *sparsed) {
		t.Fatalf("signed wire STH with escaped ids does not verify after round trip")
	}
}
