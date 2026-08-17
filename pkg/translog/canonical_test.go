package translog

import (
	"testing"
	"time"

	"github.com/wasabi-gaming/staking-verify/internal/money"
)

func amt(t *testing.T, s string) *money.Amount {
	t.Helper()
	a, err := money.Parse(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return &a
}

func goldenEntry(t *testing.T) Entry {
	t.Helper()
	return Entry{
		SchemaVersion:  SchemaVersion1,
		OperatorID:     "0b6f9f74-3a5e-4f2b-9a58-6f7d2f6a1c11",
		PoolID:         "9f6e7f3a-1b2c-4d5e-8f90-a1b2c3d4e5f6",
		Account:        "c0ffee00-1111-2222-3333-444444444444",
		Type:           "STAKE",
		Amount:         amt(t, "60"),
		TS:             time.Date(2026, 8, 11, 12, 34, 56, 789012000, time.UTC),
		IdempotencyKey: "stake:abc",
		Payload:        map[string]string{"phase": "escrow", "b": "2", "a": "1"},
	}
}

// The golden vector: the EXACT canonical bytes for a fully-populated v1 entry. If this test ever
// needs its expected string edited, that is a SCHEMA CHANGE — it invalidates every receipt signed
// under v1 — and must ship as SchemaVersion2 instead.
const goldenCanonical = `{"account":"c0ffee00-1111-2222-3333-444444444444","amount":"60.000000000000000000","idempotency_key":"stake:abc","operator_id":"0b6f9f74-3a5e-4f2b-9a58-6f7d2f6a1c11","payload":{"a":"1","b":"2","phase":"escrow"},"pool_id":"9f6e7f3a-1b2c-4d5e-8f90-a1b2c3d4e5f6","schema_version":1,"ts":"2026-08-11T12:34:56.789012Z","type":"STAKE"}`

func TestCanonicalJSON_GoldenVector(t *testing.T) {
	got, err := goldenEntry(t).CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	if string(got) != goldenCanonical {
		t.Fatalf("canonical mismatch:\n got: %s\nwant: %s", got, goldenCanonical)
	}
}

// TestCanonicalJSON_StableAcrossFieldOrderings: payload maps populated in different insertion
// orders (Go map iteration order is deliberately randomized per run) and struct literals written
// field-by-field in a different order canonicalize to byte-identical output, and re-marshaling
// the same entry N times never drifts.
func TestCanonicalJSON_StableAcrossFieldOrderings(t *testing.T) {
	a := goldenEntry(t)

	b := Entry{}
	b.Payload = map[string]string{}
	b.Payload["a"] = "1"
	b.Payload["phase"] = "escrow"
	b.Payload["b"] = "2"
	b.IdempotencyKey = "stake:abc"
	b.Type = "STAKE"
	b.TS = time.Date(2026, 8, 11, 12, 34, 56, 789012000, time.UTC)
	b.Amount = amt(t, "60.000000000000000000") // same VALUE, different source formatting
	b.Account = "c0ffee00-1111-2222-3333-444444444444"
	b.PoolID = "9f6e7f3a-1b2c-4d5e-8f90-a1b2c3d4e5f6"
	b.OperatorID = "0b6f9f74-3a5e-4f2b-9a58-6f7d2f6a1c11"
	b.SchemaVersion = SchemaVersion1

	aJSON, err := a.CanonicalJSON()
	if err != nil {
		t.Fatalf("a.CanonicalJSON: %v", err)
	}
	bJSON, err := b.CanonicalJSON()
	if err != nil {
		t.Fatalf("b.CanonicalJSON: %v", err)
	}
	if string(aJSON) != string(bJSON) {
		t.Fatalf("canonicalization depends on construction order:\n a: %s\n b: %s", aJSON, bJSON)
	}
	for i := 0; i < 50; i++ {
		again, err := a.CanonicalJSON()
		if err != nil {
			t.Fatalf("re-marshal %d: %v", i, err)
		}
		if string(again) != string(aJSON) {
			t.Fatalf("re-marshal %d drifted:\n got: %s\nwant: %s", i, again, aJSON)
		}
	}
}

func TestCanonicalJSON_OmitsAbsentOptionalFields(t *testing.T) {
	e := goldenEntry(t)
	e.Account = ""
	e.Amount = nil
	e.Payload = nil // must render as {}, identical to an empty map
	got, err := e.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	want := `{"idempotency_key":"stake:abc","operator_id":"0b6f9f74-3a5e-4f2b-9a58-6f7d2f6a1c11","payload":{},"pool_id":"9f6e7f3a-1b2c-4d5e-8f90-a1b2c3d4e5f6","schema_version":1,"ts":"2026-08-11T12:34:56.789012Z","type":"STAKE"}`
	if string(got) != want {
		t.Fatalf("canonical mismatch:\n got: %s\nwant: %s", got, want)
	}

	e.Payload = map[string]string{}
	got2, err := e.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON (empty map): %v", err)
	}
	if string(got2) != want {
		t.Fatalf("nil payload and empty payload canonicalize differently:\n nil: %s\n {}: %s", got, got2)
	}
}

func TestCanonicalAmount_FixedEighteenPlaces(t *testing.T) {
	cases := map[string]string{
		"60":                    "60.000000000000000000",
		"0.1":                   "0.100000000000000000",
		"0.000000000000000001":  "0.000000000000000001",
		"1234567890.5":          "1234567890.500000000000000000",
		"1e2":                   "100.000000000000000000", // exponent input normalizes to plain form
		"-3.25":                 "-3.250000000000000000",
		"0":                     "0.000000000000000000",
		"0.000000000000000000":  "0.000000000000000000",
		"60.000000000000000000": "60.000000000000000000",
	}
	for in, want := range cases {
		a, err := money.Parse(in)
		if err != nil {
			t.Fatalf("parse %q: %v", in, err)
		}
		if got := CanonicalAmount(a); got != want {
			t.Fatalf("CanonicalAmount(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCanonicalJSON_EscapingAndUnicodeKeys(t *testing.T) {
	e := goldenEntry(t)
	e.Payload = map[string]string{
		"quote\"key": "back\\slash",
		"ctrl":       "line\nbreak\ttab",
		"é":          "café", // non-ASCII stays literal UTF-8 per JCS
	}
	got, err := e.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	wantPayload := `{"ctrl":"line\nbreak\ttab","quote\"key":"back\\slash","é":"café"}`
	if !contains(string(got), `"payload":`+wantPayload) {
		t.Fatalf("payload escaping mismatch: got %s, want to contain %s", got, wantPayload)
	}
}

func TestCanonicalJSON_RejectsUnknownSchemaVersion(t *testing.T) {
	e := goldenEntry(t)
	e.SchemaVersion = 3 // SchemaVersion2 shipped (cap_net on EPOCH's payload) — 3 is the still-unknown one
	if _, err := e.CanonicalJSON(); err == nil {
		t.Fatalf("CanonicalJSON accepted schema_version 3; a future format must be implemented, never guessed")
	}
}

// The v2 golden vector: field-set-IDENTICAL to v1 (SchemaVersion2 adds no new Entry struct field —
// only EPOCH producers additionally populate Payload["cap_net"], which is already part of the
// existing flat payload map's canonical form), so the ONLY byte that differs from goldenCanonical
// is schema_version itself.
const goldenCanonicalV2 = `{"account":"c0ffee00-1111-2222-3333-444444444444","amount":"60.000000000000000000","idempotency_key":"stake:abc","operator_id":"0b6f9f74-3a5e-4f2b-9a58-6f7d2f6a1c11","payload":{"a":"1","b":"2","phase":"escrow"},"pool_id":"9f6e7f3a-1b2c-4d5e-8f90-a1b2c3d4e5f6","schema_version":2,"ts":"2026-08-11T12:34:56.789012Z","type":"STAKE"}`

func TestCanonicalJSON_GoldenVectorV2(t *testing.T) {
	e := goldenEntry(t)
	e.SchemaVersion = SchemaVersion2
	got, err := e.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	if string(got) != goldenCanonicalV2 {
		t.Fatalf("canonical mismatch:\n got: %s\nwant: %s", got, goldenCanonicalV2)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
