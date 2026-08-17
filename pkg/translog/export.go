package translog

// The NDJSON export line format — the published contract between the producer
// (GET /staking/transparency/export) and the standalone verifier (cmd/staking-verify).
//
// One line per event:
//
//	{"entry":<canonical entry object>,"entryHash":"<hex>","keyId":"...","prevHash":"<hex>","seq":N,"signature":"<hex>"}
//
// The "entry" value is spliced in as the EXACT canonical bytes (Entry.CanonicalJSON) — the same
// bytes that were hashed and signed — so an export is byte-identical to the signed preimages and
// a verifier re-canonicalizing the parsed entry must land on the identical bytes or fail.
// signature/keyId are omitted for an unsigned entry (producer ran without a signing key); the
// verifier treats that as a failure unless explicitly told to allow it.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/wasabi-gaming/staking-verify/internal/money"
)

// ExportRecord is one export line, parsed.
type ExportRecord struct {
	Seq       int64
	Entry     Entry
	PrevHash  []byte
	EntryHash []byte
	Signature []byte // nil = unsigned
	KeyID     string // "" = unsigned
}

// MarshalLine renders one export line (no trailing newline). Key order is fixed alphabetical —
// the wrapper is NOT part of any signed preimage (only the spliced entry bytes are), but a
// deterministic export is diffable and cache-friendly.
func (r ExportRecord) MarshalLine() ([]byte, error) {
	canonical, err := r.Entry.CanonicalJSON()
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteString(`{"entry":`)
	buf.Write(canonical)
	buf.WriteString(`,"entryHash":"`)
	buf.WriteString(hex.EncodeToString(r.EntryHash))
	buf.WriteString(`"`)
	if r.KeyID != "" {
		buf.WriteString(`,"keyId":`)
		buf.Write(appendJSONString(nil, r.KeyID))
	}
	buf.WriteString(`,"prevHash":"`)
	buf.WriteString(hex.EncodeToString(r.PrevHash))
	buf.WriteString(`","seq":`)
	buf.WriteString(strconv.FormatInt(r.Seq, 10))
	if len(r.Signature) > 0 {
		buf.WriteString(`,"signature":"`)
		buf.WriteString(hex.EncodeToString(r.Signature))
		buf.WriteString(`"`)
	}
	buf.WriteString(`}`)
	return buf.Bytes(), nil
}

// exportLineJSON / entryJSON are the parse-side shapes.
type exportLineJSON struct {
	Entry     entryJSON `json:"entry"`
	EntryHash string    `json:"entryHash"`
	KeyID     string    `json:"keyId"`
	PrevHash  string    `json:"prevHash"`
	Seq       int64     `json:"seq"`
	Signature string    `json:"signature"`
}

type entryJSON struct {
	Account        string            `json:"account"`
	Amount         *string           `json:"amount"`
	IdempotencyKey string            `json:"idempotency_key"`
	OperatorID     string            `json:"operator_id"`
	Payload        map[string]string `json:"payload"`
	PoolID         string            `json:"pool_id"`
	SchemaVersion  int               `json:"schema_version"`
	Shares         *string           `json:"shares"`
	TS             string            `json:"ts"`
	Type           string            `json:"type"`
}

// ParseExportLine parses one NDJSON export line back into an ExportRecord. The parsed Entry
// round-trips through CanonicalJSON to the exact signed bytes iff the line is untampered — a
// value edit changes the recomputed entry hash, which is what the verifier detects.
func ParseExportLine(line []byte) (*ExportRecord, error) {
	var raw exportLineJSON
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("translog: unparseable export line: %w", err)
	}
	ts, err := time.Parse(TSFormat, raw.Entry.TS)
	if err != nil {
		return nil, fmt.Errorf("translog: export line seq %d: ts %q is not %q-formatted: %w", raw.Seq, raw.Entry.TS, TSFormat, err)
	}
	entry := Entry{
		SchemaVersion:  raw.Entry.SchemaVersion,
		OperatorID:     raw.Entry.OperatorID,
		PoolID:         raw.Entry.PoolID,
		Account:        raw.Entry.Account,
		Type:           raw.Entry.Type,
		TS:             ts,
		IdempotencyKey: raw.Entry.IdempotencyKey,
		Payload:        raw.Entry.Payload,
	}
	if raw.Entry.Amount != nil {
		a, aerr := money.Parse(*raw.Entry.Amount)
		if aerr != nil {
			return nil, fmt.Errorf("translog: export line seq %d: unparseable amount %q: %w", raw.Seq, *raw.Entry.Amount, aerr)
		}
		entry.Amount = &a
	}
	if raw.Entry.Shares != nil {
		s, serr := money.Parse(*raw.Entry.Shares)
		if serr != nil {
			return nil, fmt.Errorf("translog: export line seq %d: unparseable shares %q: %w", raw.Seq, *raw.Entry.Shares, serr)
		}
		entry.Shares = &s
	}
	prev, err := hex.DecodeString(raw.PrevHash)
	if err != nil {
		return nil, fmt.Errorf("translog: export line seq %d: prevHash is not hex: %w", raw.Seq, err)
	}
	eh, err := hex.DecodeString(raw.EntryHash)
	if err != nil {
		return nil, fmt.Errorf("translog: export line seq %d: entryHash is not hex: %w", raw.Seq, err)
	}
	rec := &ExportRecord{Seq: raw.Seq, Entry: entry, PrevHash: prev, EntryHash: eh, KeyID: raw.KeyID}
	if raw.Signature != "" {
		sig, serr := hex.DecodeString(raw.Signature)
		if serr != nil {
			return nil, fmt.Errorf("translog: export line seq %d: signature is not hex: %w", raw.Seq, serr)
		}
		rec.Signature = sig
	}
	return rec, nil
}
