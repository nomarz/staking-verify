package translog

import (
	"bytes"
	"crypto/sha256"
	"testing"
	"time"
)

func chainTestEntry(t *testing.T, idem string, amount string) Entry {
	t.Helper()
	e := Entry{
		SchemaVersion:  SchemaVersion1,
		OperatorID:     "0b6f9f74-3a5e-4f2b-9a58-6f7d2f6a1c11",
		PoolID:         "9f6e7f3a-1b2c-4d5e-8f90-a1b2c3d4e5f6",
		Type:           "STAKE",
		TS:             time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC),
		IdempotencyKey: idem,
	}
	if amount != "" {
		e.Amount = amt(t, amount)
	}
	return e
}

func TestChain_GenesisAndDeterminism(t *testing.T) {
	g := Genesis()
	if len(g) != HashSize || !IsGenesis(g) {
		t.Fatalf("Genesis() = %x (len %d), want 32 zero bytes", g, len(g))
	}
	// Mutating the returned slice must not poison later calls.
	g[0] = 0xff
	if IsGenesis(g) || !IsGenesis(Genesis()) {
		t.Fatalf("Genesis() shares state across calls")
	}

	e := chainTestEntry(t, "k1", "10")
	h1, c1, err := ChainEntry(nil, e) // nil == genesis shorthand
	if err != nil {
		t.Fatalf("ChainEntry: %v", err)
	}
	h2, c2, err := ChainEntry(Genesis(), e)
	if err != nil {
		t.Fatalf("ChainEntry: %v", err)
	}
	if !bytes.Equal(h1, h2) || !bytes.Equal(c1, c2) {
		t.Fatalf("ChainEntry not deterministic: %x vs %x", h1, h2)
	}

	// The construction is exactly SHA256(0x00 || prev || canonical).
	want := sha256.New()
	want.Write([]byte{0x00})
	want.Write(Genesis())
	want.Write(c1)
	if !bytes.Equal(h1, want.Sum(nil)) {
		t.Fatalf("hash construction mismatch")
	}
}

func TestChain_RejectsBadPrevHash(t *testing.T) {
	if _, err := NextHash([]byte{1, 2, 3}, []byte("{}")); err == nil {
		t.Fatalf("NextHash accepted a 3-byte prev_hash")
	}
}

// TestChain_TamperDetection: build a 3-entry chain, then mutate ONE field of the middle entry.
// Recomputing entry 2's hash no longer matches the stored value, and — because entry 3's
// prev_hash commits to the ORIGINAL entry-2 hash — the chain linkage breaks downstream too.
func TestChain_TamperDetection(t *testing.T) {
	e1 := chainTestEntry(t, "k1", "10")
	e2 := chainTestEntry(t, "k2", "20")
	e3 := chainTestEntry(t, "k3", "30")

	h1, _, err := ChainEntry(nil, e1)
	if err != nil {
		t.Fatalf("chain e1: %v", err)
	}
	h2, _, err := ChainEntry(h1, e2)
	if err != nil {
		t.Fatalf("chain e2: %v", err)
	}
	h3, _, err := ChainEntry(h2, e3)
	if err != nil {
		t.Fatalf("chain e3: %v", err)
	}

	// Tamper: the attacker edits entry 2's amount in the stored/exported log.
	tampered := e2
	tampered.Amount = amt(t, "2000")
	th2, _, err := ChainEntry(h1, tampered)
	if err != nil {
		t.Fatalf("chain tampered e2: %v", err)
	}
	if bytes.Equal(th2, h2) {
		t.Fatalf("tampered entry produced the SAME hash — chain provides no integrity")
	}
	// And rebuilding entry 3 on top of the tampered hash diverges from the stored head.
	th3, _, err := ChainEntry(th2, e3)
	if err != nil {
		t.Fatalf("chain e3 after tamper: %v", err)
	}
	if bytes.Equal(th3, h3) {
		t.Fatalf("downstream hash unchanged despite upstream tamper")
	}
}
