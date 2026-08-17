package translog

// The per-pool hash chain primitive:
//
//	entry_hash = SHA256(0x00 || prev_hash || canonical(entry))
//
// genesis prev_hash = 32 zero bytes. The leading 0x00 is a domain-separation byte reserving the
// rest of the prefix space for future constructions (an RFC 6962 Merkle tree over these hashes,
// STAKING-P3, uses 0x00/0x01 leaf/node prefixes of its own over a DIFFERENT preimage layout; the
// explicit prefix here means a chain entry hash can never be confused for either).
//
// Pure functions only — no database, no clock, no I/O — so the producer (the repository append)
// and the standalone verifier provably run the exact same computation.

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
)

// HashSize is the byte length of every chain hash (SHA-256).
const HashSize = sha256.Size

// chainDomainPrefix is the domain-separation byte prepended to every chain-hash preimage.
const chainDomainPrefix byte = 0x00

// ErrInvalidPrevHash is returned when a previous hash is not exactly HashSize bytes.
var ErrInvalidPrevHash = errors.New("translog: prev_hash must be exactly 32 bytes")

// Genesis returns the genesis prev_hash: 32 zero bytes. A fresh copy every call, so a caller
// mutating the slice cannot poison a shared value.
func Genesis() []byte {
	return make([]byte, HashSize)
}

// IsGenesis reports whether prev is the 32-zero-byte genesis marker.
func IsGenesis(prev []byte) bool {
	return bytes.Equal(prev, Genesis())
}

// NextHash computes the chain hash for one canonicalized entry appended after prevHash.
func NextHash(prevHash, canonical []byte) ([]byte, error) {
	if len(prevHash) != HashSize {
		return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidPrevHash, len(prevHash))
	}
	h := sha256.New()
	h.Write([]byte{chainDomainPrefix})
	h.Write(prevHash)
	h.Write(canonical)
	return h.Sum(nil), nil
}

// ChainEntry canonicalizes e and computes its entry hash after prevHash (pass Genesis() — or
// nil, accepted as shorthand for it — for a pool's first entry). Returns both the hash and the
// canonical bytes so a producer can store/export exactly what was hashed.
func ChainEntry(prevHash []byte, e Entry) (entryHash, canonical []byte, err error) {
	if prevHash == nil {
		prevHash = Genesis()
	}
	canonical, err = e.CanonicalJSON()
	if err != nil {
		return nil, nil, err
	}
	entryHash, err = NextHash(prevHash, canonical)
	if err != nil {
		return nil, nil, err
	}
	return entryHash, canonical, nil
}
