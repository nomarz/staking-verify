package translog

import (
	"bytes"
	"testing"
)

func TestExport_MarshalParseRoundTrip(t *testing.T) {
	s := testSigner(t)
	e := goldenEntry(t)
	entryHash, canonical, err := ChainEntry(nil, e)
	if err != nil {
		t.Fatalf("ChainEntry: %v", err)
	}
	rec := ExportRecord{
		Seq: 7, Entry: e, PrevHash: Genesis(), EntryHash: entryHash,
		Signature: s.Sign(entryHash), KeyID: s.KeyID(),
	}
	line, err := rec.MarshalLine()
	if err != nil {
		t.Fatalf("MarshalLine: %v", err)
	}
	// The canonical entry bytes appear VERBATIM in the line — the export is byte-identical to
	// the signed preimage, not a re-serialization of it.
	if !bytes.Contains(line, canonical) {
		t.Fatalf("export line does not contain the exact canonical bytes:\nline: %s\ncanonical: %s", line, canonical)
	}

	parsed, err := ParseExportLine(line)
	if err != nil {
		t.Fatalf("ParseExportLine: %v", err)
	}
	if parsed.Seq != 7 || parsed.KeyID != s.KeyID() {
		t.Fatalf("parsed seq/keyId mismatch: %+v", parsed)
	}
	recanonical, err := parsed.Entry.CanonicalJSON()
	if err != nil {
		t.Fatalf("re-canonicalize: %v", err)
	}
	if !bytes.Equal(recanonical, canonical) {
		t.Fatalf("parsed entry re-canonicalizes to different bytes:\n got: %s\nwant: %s", recanonical, canonical)
	}
	recomputed, err := NextHash(parsed.PrevHash, recanonical)
	if err != nil {
		t.Fatalf("NextHash: %v", err)
	}
	if !bytes.Equal(recomputed, parsed.EntryHash) {
		t.Fatalf("recomputed hash mismatch")
	}
	if !VerifyEntryHash(s.PublicKey(), recomputed, parsed.Signature) {
		t.Fatalf("signature does not verify after round trip")
	}
}

func TestExport_UnsignedLineOmitsSignatureFields(t *testing.T) {
	e := goldenEntry(t)
	entryHash, _, err := ChainEntry(nil, e)
	if err != nil {
		t.Fatalf("ChainEntry: %v", err)
	}
	line, err := ExportRecord{Seq: 1, Entry: e, PrevHash: Genesis(), EntryHash: entryHash}.MarshalLine()
	if err != nil {
		t.Fatalf("MarshalLine: %v", err)
	}
	if bytes.Contains(line, []byte("signature")) || bytes.Contains(line, []byte("keyId")) {
		t.Fatalf("unsigned line carries signature fields: %s", line)
	}
	parsed, err := ParseExportLine(line)
	if err != nil {
		t.Fatalf("ParseExportLine: %v", err)
	}
	if parsed.Signature != nil || parsed.KeyID != "" {
		t.Fatalf("unsigned line parsed with signature fields: %+v", parsed)
	}
}
