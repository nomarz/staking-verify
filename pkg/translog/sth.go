package translog

// STAKING-P3: the Signed Tree Head (STH) — one Ed25519-signed statement "the Merkle tree over
// this pool's first tree_size entry hashes has this root, observed at this time".
//
//	signature = Ed25519(sk, "nomarz-staking-v1:sth:" || canonical(sth))
//
// The context prefix is DIFFERENT from keys.go's receipt prefix ("nomarz-staking-v1:receipt:"),
// so an STH signature can never verify as a receipt signature over the same underlying bytes or
// vice versa — the same key signs both artifact kinds, and only the context keeps them apart.
// The canonical payload rides canonical.go's primitives (JCS string escaping, fixed field order,
// TSFormat timestamps) rather than a second serialization scheme; the field set is fixed and
// versioned exactly like Entry's.
//
// Wire form (MarshalSTHLine / ParseSTHLine): one JSON object per STH, fixed alphabetical key
// order, hashes and signatures hex — the same conventions as export.go's line format. The wire
// wrapper is NOT the signed preimage; the verifier re-canonicalizes the parsed fields, so any
// value edit breaks the signature check.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

// STHSignatureContext is the domain-separation prefix for STH signatures. MUST stay distinct
// from SignatureContext (receipts) forever — see the file header.
const STHSignatureContext = "nomarz-staking-v1:sth:"

// STH is the fixed, versioned field set of one Signed Tree Head. KeyID/Signature are outside the
// canonical (signed) payload — they authenticate it.
type STH struct {
	// SchemaVersion is the canonicalization schema ("schema_version"), always SchemaVersion1.
	SchemaVersion int
	// OperatorID / PoolID bind the head to its tenant and pool ("operator_id", "pool_id") — an
	// STH signed for one pool must never replay as another's.
	OperatorID string
	PoolID     string
	// TreeSize is how many events the tree covers ("tree_size"), >= 1: the producer never
	// publishes a head over an empty tree (there is nothing to attest, and RFC 6962 consistency
	// is undefined from size 0).
	TreeSize int64
	// RootHash is the RFC 6962 MTH over the pool's first TreeSize entry hashes ("root_hash",
	// canonicalized as hex).
	RootHash []byte
	// TS is when this head was produced ("ts", TSFormat) — also the instant the key registry
	// resolves the signing key at. Truncate to microseconds before signing/storing, same DB
	// round-trip rule as Entry.TS.
	TS time.Time
	// KeyID / Signature — empty for an unsigned producer, same convention as ExportRecord.
	KeyID     string
	Signature []byte
}

// Validate checks the STH can be canonicalized.
func (s STH) Validate() error {
	if s.SchemaVersion != SchemaVersion1 {
		return fmt.Errorf("%w: unsupported schema_version %d", ErrInvalidEntry, s.SchemaVersion)
	}
	if s.OperatorID == "" || s.PoolID == "" {
		return fmt.Errorf("%w: operator_id and pool_id are required", ErrInvalidEntry)
	}
	if s.TreeSize < 1 {
		return fmt.Errorf("%w: tree_size must be >= 1, got %d", ErrInvalidEntry, s.TreeSize)
	}
	if len(s.RootHash) != HashSize {
		return fmt.Errorf("%w: root_hash is %d bytes, want %d", ErrInvalidEntry, len(s.RootHash), HashSize)
	}
	if s.TS.IsZero() {
		return fmt.Errorf("%w: ts is required", ErrInvalidEntry)
	}
	return nil
}

// CanonicalJSON returns the signed payload. Keys appear in their JCS (byte, all-ASCII) order for
// this fixed set: operator_id < pool_id < root_hash < schema_version < tree_size < ts.
func (s STH) CanonicalJSON() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	buf := make([]byte, 0, 256)
	buf = append(buf, '{')
	buf = appendJSONString(buf, "operator_id")
	buf = append(buf, ':')
	buf = appendJSONString(buf, s.OperatorID)
	buf = append(buf, ',')
	buf = appendJSONString(buf, "pool_id")
	buf = append(buf, ':')
	buf = appendJSONString(buf, s.PoolID)
	buf = append(buf, ',')
	buf = appendJSONString(buf, "root_hash")
	buf = append(buf, ':')
	buf = appendJSONString(buf, hex.EncodeToString(s.RootHash))
	buf = append(buf, ',')
	buf = appendJSONString(buf, "schema_version")
	buf = append(buf, ':')
	buf = appendJSONInt(buf, s.SchemaVersion)
	buf = append(buf, ',')
	buf = appendJSONString(buf, "tree_size")
	buf = append(buf, ':')
	buf = append(buf, []byte(strconv.FormatInt(s.TreeSize, 10))...)
	buf = append(buf, ',')
	buf = appendJSONString(buf, "ts")
	buf = append(buf, ':')
	buf = appendJSONString(buf, s.TS.UTC().Format(TSFormat))
	buf = append(buf, '}')
	return buf, nil
}

// sthSigningMessage builds the domain-separated message for one canonical STH payload.
func sthSigningMessage(canonical []byte) []byte {
	msg := make([]byte, 0, len(STHSignatureContext)+len(canonical))
	msg = append(msg, STHSignatureContext...)
	return append(msg, canonical...)
}

// SignSTH canonicalizes the STH and signs it, stamping KeyID and Signature in place.
func (sg *Signer) SignSTH(s *STH) error {
	canonical, err := s.CanonicalJSON()
	if err != nil {
		return err
	}
	s.Signature = ed25519.Sign(sg.priv, sthSigningMessage(canonical))
	s.KeyID = sg.keyID
	return nil
}

// VerifySTH re-canonicalizes the STH and verifies its signature under pub. False for an
// unsigned, malformed, or tampered STH.
func VerifySTH(pub ed25519.PublicKey, s STH) bool {
	if len(pub) != ed25519.PublicKeySize || len(s.Signature) == 0 {
		return false
	}
	canonical, err := s.CanonicalJSON()
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, sthSigningMessage(canonical), s.Signature)
}

// MarshalSTHLine renders one STH wire line (no trailing newline): fixed alphabetical key order,
// keyId/signature omitted when unsigned — the shape GET /staking/transparency/sth serves and
// cmd/staking-verify's -sth file carries, one per line.
//
// OperatorID/PoolID render through appendJSONString like KeyID does (P2-P5 review L4): they are
// uuid strings in every real producer, but STH.Validate only checks non-empty, and writing an
// unvalidated value raw inside an open JSON literal would let one stray `"` corrupt the whole
// line. Escaping (rather than tightening Validate to require uuid-shaped values) is the fix
// consistent with how this wire format already handles its other free-form string field.
func (s STH) MarshalSTHLine() ([]byte, error) {
	if _, err := s.CanonicalJSON(); err != nil { // validate exactly what a verifier will rebuild
		return nil, err
	}
	var buf bytes.Buffer
	if s.KeyID != "" {
		buf.WriteString(`{"keyId":`)
		buf.Write(appendJSONString(nil, s.KeyID))
		buf.WriteString(`,"operatorId":`)
	} else {
		buf.WriteString(`{"operatorId":`)
	}
	buf.Write(appendJSONString(nil, s.OperatorID))
	buf.WriteString(`,"poolId":`)
	buf.Write(appendJSONString(nil, s.PoolID))
	buf.WriteString(`,"rootHash":"`)
	buf.WriteString(hex.EncodeToString(s.RootHash))
	buf.WriteString(`","schemaVersion":`)
	buf.WriteString(strconv.Itoa(s.SchemaVersion))
	if len(s.Signature) > 0 {
		buf.WriteString(`,"signature":"`)
		buf.WriteString(hex.EncodeToString(s.Signature))
		buf.WriteString(`"`)
	}
	buf.WriteString(`,"treeSize":`)
	buf.WriteString(strconv.FormatInt(s.TreeSize, 10))
	buf.WriteString(`,"ts":"`)
	buf.WriteString(s.TS.UTC().Format(TSFormat))
	buf.WriteString(`"}`)
	return buf.Bytes(), nil
}

// sthLineJSON is the parse-side shape of MarshalSTHLine.
type sthLineJSON struct {
	KeyID         string `json:"keyId"`
	OperatorID    string `json:"operatorId"`
	PoolID        string `json:"poolId"`
	RootHash      string `json:"rootHash"`
	SchemaVersion int    `json:"schemaVersion"`
	Signature     string `json:"signature"`
	TreeSize      int64  `json:"treeSize"`
	TS            string `json:"ts"`
}

// ParseSTHLine parses one STH wire line back into an STH. The parsed value round-trips through
// CanonicalJSON to the exact signed bytes iff untampered — VerifySTH is what detects an edit.
func ParseSTHLine(line []byte) (*STH, error) {
	var raw sthLineJSON
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("translog: unparseable sth line: %w", err)
	}
	ts, err := time.Parse(TSFormat, raw.TS)
	if err != nil {
		return nil, fmt.Errorf("translog: sth ts %q is not %q-formatted: %w", raw.TS, TSFormat, err)
	}
	root, err := hex.DecodeString(raw.RootHash)
	if err != nil {
		return nil, fmt.Errorf("translog: sth rootHash is not hex: %w", err)
	}
	out := &STH{
		SchemaVersion: raw.SchemaVersion, OperatorID: raw.OperatorID, PoolID: raw.PoolID,
		TreeSize: raw.TreeSize, RootHash: root, TS: ts, KeyID: raw.KeyID,
	}
	if raw.Signature != "" {
		sig, serr := hex.DecodeString(raw.Signature)
		if serr != nil {
			return nil, fmt.Errorf("translog: sth signature is not hex: %w", serr)
		}
		out.Signature = sig
	}
	if err := out.Validate(); err != nil {
		return nil, err
	}
	return out, nil
}
