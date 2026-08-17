package main

// STAKING-P3: Signed-Tree-Head verification — the -sth half of the verifier.
//
// Given the chain-verified export PLUS the published STH sequence (one pkg/translog wire line
// per head, as served by GET /staking/transparency/sth — the same bytes, no private format),
// this re-establishes, per pool, WITHOUT trusting any server-computed proof:
//
//  1. ROOTS — the RFC 6962 Merkle root over the export's first tree_size entry hashes is
//     recomputed FROM SCRATCH for every published head and must equal its root_hash. This is
//     the check that catches a rewritten history: a from-scratch regenerated chain can be made
//     internally self-consistent (hashes, signatures, replay all pass), but it cannot reproduce
//     a root someone recorded BEFORE the rewrite.
//  2. SIGNATURES — every head verifies under the registry key valid at ITS OWN timestamp,
//     using translog's STH context (domain-separated from receipt signatures).
//  3. CONSISTENCY — between every successive pair of heads, PROOF(old, D[new]) is generated
//     from the exported leaves and verified against BOTH published roots — the append-only
//     guarantee, established with the same primitives an offline auditor would use.
//
// The first failure aborts with the pool, the tree_size (reported in VerifyError.Seq), and the
// failing check.

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/wasabi-gaming/staking-verify/pkg/translog"
)

// STHSummary is the successful -sth verification report.
type STHSummary struct {
	Heads    int
	Unsigned int
	// LatestByPool maps pool id -> the largest verified tree_size.
	LatestByPool map[string]int64
}

// ParseSTHStream reads one STH wire line per row (blank lines skipped).
func ParseSTHStream(r io.Reader) ([]*translog.STH, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var out []*translog.STH
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		sth, err := translog.ParseSTHLine(line)
		if err != nil {
			return nil, fmt.Errorf("sth line %d: %w", lineNo, err)
		}
		out = append(out, sth)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("sth line %d: read: %w", lineNo, err)
	}
	return out, nil
}

// VerifySTHs runs the three checks in the file header over an already-chain-verified Summary
// (which must have been produced with Options.CollectLeaves — the leaf sequences are what roots
// are recomputed from).
func VerifySTHs(sum *Summary, sths []*translog.STH, opts Options) (*STHSummary, error) {
	out := &STHSummary{LatestByPool: map[string]int64{}}
	if len(sths) == 0 {
		return out, nil
	}

	byPool := map[string][]*translog.STH{}
	poolOrder := []string{}
	for _, sth := range sths {
		if _, seen := byPool[sth.PoolID]; !seen {
			poolOrder = append(poolOrder, sth.PoolID)
		}
		byPool[sth.PoolID] = append(byPool[sth.PoolID], sth)
	}
	sort.Strings(poolOrder)

	for _, poolID := range poolOrder {
		heads := byPool[poolID]
		sort.SliceStable(heads, func(i, j int) bool {
			if heads[i].TreeSize != heads[j].TreeSize {
				return heads[i].TreeSize < heads[j].TreeSize
			}
			return heads[i].TS.Before(heads[j].TS)
		})

		st := sum.Pools[poolID]
		if st == nil {
			return nil, &VerifyError{Seq: heads[0].TreeSize, Pool: poolID, Check: "sth",
				Msg: "STH names a pool with no events in the export — wrong export, or the pool's history was removed entirely"}
		}
		leaves := st.Leaves
		if int64(len(leaves)) != int64(st.Events) {
			return nil, &VerifyError{Seq: heads[0].TreeSize, Pool: poolID, Check: "sth",
				Msg: "internal: leaves were not collected during chain verification (CollectLeaves off)"}
		}

		var prev *translog.STH
		for _, sth := range heads {
			ts := sth.TreeSize // reported as Seq in errors below

			// Cross-binding: the head must belong to the same operator the events declare.
			if st.Operator != "" && sth.OperatorID != st.Operator {
				return nil, &VerifyError{Seq: ts, Pool: poolID, Check: "sth",
					Msg: fmt.Sprintf("STH operator %s does not match the export's operator %s", sth.OperatorID, st.Operator)}
			}
			if sth.TreeSize > int64(len(leaves)) {
				return nil, &VerifyError{Seq: ts, Pool: poolID, Check: "sth",
					Msg: fmt.Sprintf("STH covers %d events but the export holds only %d for this pool — export truncated, or the head is forged", sth.TreeSize, len(leaves))}
			}

			// 1. Recompute the root FROM the exported leaves — never trust the published value.
			recomputed := translog.MerkleRoot(leaves[:sth.TreeSize])
			if !bytes.Equal(recomputed, sth.RootHash) {
				return nil, &VerifyError{Seq: ts, Pool: poolID, Check: "sth",
					Msg: fmt.Sprintf("recomputed Merkle root %x at tree_size %d does not match the published root %x — the exported history is NOT the history this head was signed over", recomputed, sth.TreeSize, sth.RootHash)}
			}

			// 2. Signature under the key valid at the head's own timestamp.
			if len(sth.Signature) == 0 {
				if !opts.AllowUnsigned {
					return nil, &VerifyError{Seq: ts, Pool: poolID, Check: "sth-signature",
						Msg: "STH is unsigned (no signature/keyId); rerun with -allow-unsigned only if the producer is known to run unsigned"}
				}
				out.Unsigned++
			} else {
				if opts.Registry == nil {
					return nil, &VerifyError{Seq: ts, Pool: poolID, Check: "sth-signature", Msg: "signed STH but no key registry provided (-registry)"}
				}
				pub, rerr := opts.Registry.Resolve(sth.KeyID, sth.TS)
				if rerr != nil {
					return nil, &VerifyError{Seq: ts, Pool: poolID, Check: "sth-signature", Msg: rerr.Error()}
				}
				if !translog.VerifySTH(pub, *sth) {
					return nil, &VerifyError{Seq: ts, Pool: poolID, Check: "sth-signature",
						Msg: fmt.Sprintf("Ed25519 STH signature does not verify under key %s", sth.KeyID)}
				}
			}

			// 3. Append-only extension of the PREVIOUS head, proven with a self-generated
			// consistency proof verified against both published roots.
			if prev != nil {
				if prev.TreeSize == sth.TreeSize {
					if !bytes.Equal(prev.RootHash, sth.RootHash) {
						return nil, &VerifyError{Seq: ts, Pool: poolID, Check: "sth-consistency",
							Msg: fmt.Sprintf("two heads at tree_size %d publish DIFFERENT roots — the log forked", ts)}
					}
				} else {
					proof, perr := translog.ConsistencyProof(leaves, int(prev.TreeSize), int(sth.TreeSize))
					if perr != nil {
						return nil, &VerifyError{Seq: ts, Pool: poolID, Check: "sth-consistency", Msg: perr.Error()}
					}
					if !translog.VerifyConsistency(prev.RootHash, int(prev.TreeSize), sth.RootHash, int(sth.TreeSize), proof) {
						return nil, &VerifyError{Seq: ts, Pool: poolID, Check: "sth-consistency",
							Msg: fmt.Sprintf("the tree at %d is NOT an append-only extension of the tree at %d — history was rewritten between these heads", sth.TreeSize, prev.TreeSize)}
					}
				}
			}
			prev = sth
			out.Heads++
			if ts > out.LatestByPool[poolID] {
				out.LatestByPool[poolID] = ts
			}
		}
	}
	return out, nil
}

// ── STAKING-P5+: OpenTimestamps anchor reporting (pkg/attest/ots.go's Anchor/Verify) ──────────
//
// GET /staking/transparency/sth's additive "anchors" array (the producer's STH-publishing service's
// StakingSTHAnchorView) is DELIBERATELY NOT part of the "sths" wire objects or of translog's STH
// type at all — see that service's doc comment: mixing it in would break both the RFC 6962
// signed-payload shape and the "byte-compatible with -sth" promise (ParseSTHLine rejects unknown
// fields). So this is a SEPARATE, optional input (-anchors), matched back to already-verified
// heads by (poolId, treeSize).
//
// What VerifyAnchors checks is exactly one thing, done for real: the anchor's own embedded digest
// (decoded out of its opaque `ref`, WITHOUT importing pkg/attest — this binary deliberately
// imports nothing of the producer's internal/production code, so a bug in its OTSReceiptPayload
// encoding cannot silently become invisible to an independent verifier that trusted the same
// struct) equals SHA256(canonical(sth)) RECOMPUTED here from the already-verified head. That is
// the entire "digest binding" claim pkg/attest.OpenTimestampsAnchorer.Verify makes too, checked
// completely independently.
//
// What it does NOT check, on purpose, matching pkg/attest/ots.go's own honesty boundary: whether
// the anchor's proof bytes actually form a valid path to a real Bitcoin block. That requires
// parsing the OpenTimestamps binary proof format and consulting a Bitcoin node/SPV client —
// neither of which this tool does. A "confirmed" state reported here is TESTIMONY relayed from
// the anchor record (which itself relays testimony from a calendar server) — never proof. Anyone
// wanting the real thing runs the standalone `ots verify` tool against the digest this report
// prints and the calendar's stored proof bytes (recoverable from the ref's own JSON).

// stakingSTHAnchorRefPayload decodes ONLY the one field this verifier needs out of an anchor's
// opaque `ref` — by CONVENTION (every kind this repo ships happens to use this shape), not a
// contract enforced anywhere. A ref that isn't this shape simply reports "digest not checked"
// rather than failing the whole run — an anchor kind this tool doesn't understand is not an
// error, it's just nothing this pass can independently confirm.
type stakingSTHAnchorRefPayload struct {
	Digest string `json:"digest"`
}

// StakingSTHAnchorRecord is one element of GET .../sth's additive "anchors" array — the -anchors
// input, one JSON object per line (same NDJSON convention as -sth).
type StakingSTHAnchorRecord struct {
	PoolID      string `json:"poolId"`
	TreeSize    int64  `json:"treeSize"`
	Kind        string `json:"kind"`
	State       string `json:"state"`
	Ref         string `json:"ref"`
	SubmittedAt string `json:"submittedAt"`
	ConfirmedAt string `json:"confirmedAt,omitempty"`
}

// ParseAnchorStream reads one JSON object per line (blank lines skipped) — the -anchors input.
func ParseAnchorStream(r io.Reader) ([]StakingSTHAnchorRecord, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var out []StakingSTHAnchorRecord
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec StakingSTHAnchorRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, fmt.Errorf("anchor line %d: %w", lineNo, err)
		}
		out = append(out, rec)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("anchor line %d: read: %w", lineNo, err)
	}
	return out, nil
}

// AnchorReport is one line of VerifyAnchors' output: what a head's anchor CLAIMS, and what this
// tool actually independently checked.
type AnchorReport struct {
	PoolID   string
	TreeSize int64
	Kind     string
	// State is the record's OWN claimed state ("pending"/"confirmed") — testimony, not rechecked.
	State string
	// DigestOK is true iff DigestChecked is true and the ref's embedded digest matched the
	// recomputed sha256(canonical(sth)) — the one thing this pass verifies for real.
	DigestOK bool
	// DigestChecked is false when the ref is not the expected {"digest":"..."} shape (a
	// different/future anchor kind; NOT an error).
	DigestChecked bool
}

// VerifyAnchors checks every anchor record against the already-verified heads in sths (from
// VerifySTHs — this must run after that, same as -attest running after -sth in main.go). A record
// naming a (pool, tree_size) absent from sths is a hard failure (a forged anchor, or the wrong
// -sth file); a digest mismatch on a record that DOES have a matching head is also a hard failure
// (the anchor does not bind to what it claims to anchor). An unconfirmed/pending state is
// reported, never treated as a failure — Bitcoin confirmation taking hours is normal, not broken.
func VerifyAnchors(sths []*translog.STH, anchors []StakingSTHAnchorRecord) ([]AnchorReport, error) {
	byKey := map[string]*translog.STH{}
	for _, s := range sths {
		byKey[fmt.Sprintf("%s:%d", s.PoolID, s.TreeSize)] = s
	}
	var out []AnchorReport
	for _, a := range anchors {
		key := fmt.Sprintf("%s:%d", a.PoolID, a.TreeSize)
		sth, ok := byKey[key]
		if !ok {
			return nil, &VerifyError{Seq: a.TreeSize, Pool: a.PoolID, Check: "anchor",
				Msg: "anchor names a (pool, tree_size) with no corresponding verified STH — wrong -sth file, or the anchor is forged"}
		}
		rep := AnchorReport{PoolID: a.PoolID, TreeSize: a.TreeSize, Kind: a.Kind, State: a.State}
		var refPayload stakingSTHAnchorRefPayload
		if jerr := json.Unmarshal([]byte(a.Ref), &refPayload); jerr == nil && refPayload.Digest != "" {
			rep.DigestChecked = true
			canonical, cerr := sth.CanonicalJSON()
			if cerr != nil {
				return nil, &VerifyError{Seq: a.TreeSize, Pool: a.PoolID, Check: "anchor", Msg: cerr.Error()}
			}
			want := sha256.Sum256(canonical)
			got, herr := hex.DecodeString(refPayload.Digest)
			if herr != nil || !bytes.Equal(got, want[:]) {
				return nil, &VerifyError{Seq: a.TreeSize, Pool: a.PoolID, Check: "anchor",
					Msg: fmt.Sprintf("anchor digest %s does not match recomputed sha256(canonical(sth)) %x — the anchor does not bind to this head", refPayload.Digest, want)}
			}
			rep.DigestOK = true
		}
		out = append(out, rep)
	}
	return out, nil
}

// WriteAnchorReport prints the testimony-vs-proof summary. Never claims Bitcoin anchoring was
// independently verified here — see this section's header.
func WriteAnchorReport(w io.Writer, reports []AnchorReport) {
	if len(reports) == 0 {
		return
	}
	fmt.Fprintf(w, "ANCHORS: %d record(s) — digest binding independently recomputed and checked; the Bitcoin anchoring itself is TESTIMONY relayed from the calendar server via the platform, NOT independently re-verified by this tool — confirm with the external `ots verify` tool against the digest below\n", len(reports))
	for _, r := range reports {
		digest := "not checked (ref is not the expected {\"digest\":...} shape for this kind)"
		switch {
		case r.DigestChecked && r.DigestOK:
			digest = "OK (matches recomputed sha256(canonical(sth)))"
		case r.DigestChecked:
			digest = "MISMATCH"
		}
		fmt.Fprintf(w, "  pool %s tree_size %d: kind=%s claimed_state=%s digest=%s\n", r.PoolID, r.TreeSize, r.Kind, r.State, digest)
	}
}

// WriteSTHSummary renders the -sth success report.
func WriteSTHSummary(w io.Writer, sum *STHSummary) {
	fmt.Fprintf(w, "STH: %d head(s) verified across %d pool(s)\n", sum.Heads, len(sum.LatestByPool))
	if sum.Unsigned > 0 {
		fmt.Fprintf(w, "WARNING: %d head(s) were UNSIGNED (allowed by -allow-unsigned)\n", sum.Unsigned)
	}
	pools := make([]string, 0, len(sum.LatestByPool))
	for id := range sum.LatestByPool {
		pools = append(pools, id)
	}
	sort.Strings(pools)
	for _, id := range pools {
		fmt.Fprintf(w, "pool %s: latest verified tree_size %d\n", id, sum.LatestByPool[id])
	}
}
