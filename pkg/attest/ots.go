package attest

// The "opentimestamps" Anchorer — the first (and, this phase, only) real implementation of the
// anchor.go SEAM. Read that file's header first: a signed STH proves non-rewriting only
// RELATIVE TO A HEAD YOU ALREADY HOLD. Anchoring closes the gap for everyone else — a first-time
// visitor, or someone whose browser storage was cleared — by committing SHA256(canonical(sth))
// into a medium the operator cannot rewrite after the fact: the Bitcoin blockchain, via the
// OpenTimestamps (https://opentimestamps.org) calendar-aggregation protocol.
//
// ── WHAT THIS FILE CRYPTOGRAPHICALLY CHECKS TODAY, AND WHAT IT DOES NOT (read before trusting
//    anything this type reports) ──────────────────────────────────────────────────────────────
//
// Anchor() computes SHA256(sth.CanonicalJSON()) — the EXACT bytes translog.SignSTH/VerifySTH
// sign over, so an anchor and a signature are provably about the same head — and submits it to a
// small, hardcoded set of public OpenTimestamps calendar servers over HTTPS. Each calendar's
// response (the initial, NOT-yet-Bitcoin-confirmed ".ots" pending proof) is stored OPAQUELY: this
// file does not parse the OpenTimestamps binary proof-tree format. That is a deliberate scope
// boundary, not an oversight — decoding a full OTS Merkle-path-to-Bitcoin proof (parsing the
// operation tree, walking to a BitcoinBlockHeaderAttestation, and independently re-deriving that
// block's own merkle root) is real, non-trivial work that this phase does not implement. Doing it
// badly and reporting "verified" would be exactly the fabricated verification the task and this
// package's own header (see attest.go's WORDING DISCIPLINE) forbid.
//
// So, precisely:
//   - REAL, checked here: the receipt's digest equals SHA256(canonical(sth)) — Verify() recomputes
//     this from the STH every time, never trusts a stored value. A receipt whose digest does not
//     match cannot be silently associated with a different (or edited) head.
//   - REAL, done over HTTPS, not fabricated: the initial submission (POST /digest) and the
//     upgrade poll (GET /timestamp/<digest>) genuinely talk to the calendar servers and store
//     their genuine response bytes.
//   - NOT checked here, ever: that the stored proof bytes actually form a valid path to a real
//     Bitcoin block, that the referenced block is actually in the best chain, or anything else
//     that requires walking the OTS binary format and consulting a Bitcoin node/SPV client. Verify
//     () reports a clearly distinguishable PENDING state (ErrOTSPendingConfirmation) until a
//     calendar reports the proof upgraded, and even after that it reports the upgrade as
//     TESTIMONY from the calendar server — never as independently re-derived proof. A caller
//     wanting the real thing runs the standalone `ots verify` tool (or any other RFC-compliant OTS
//     verifier) against the stored proof bytes and the digest below — exactly the "testimony vs
//     proof" discipline auditor.go already uses for third-party statements, and the same honest
//     stub shape onchain.go uses for a gap that cannot be closed at all.
//
// ── PROTOCOL CONFIDENCE NOTE (read this before relying on the wire format below in production)
// ──────────────────────────────────────────────────────────────────────────────────────────────
//
// The OpenTimestamps calendar HTTP protocol implemented here (POST /digest with the raw 32-byte
// digest as body and Content-Type/Accept: application/vnd.opentimestamps.v1; GET
// /timestamp/<digest-hex> returning 200 with the upgraded proof bytes once Bitcoin-attested or
// 404 while still pending) matches the public opentimestamps-client reference implementation's
// documented calendar API as best recalled/researched while writing this file. It was NOT
// exercised against a live public calendar server from this environment (no outbound network
// access was available/appropriate to use here) — httptest-based unit tests below cover the
// client's own request construction, response handling, and error paths against a MOCKED server
// that speaks the protocol as understood, not against the real opentimestamps.org calendars. If
// this is deployed, the first AnchorOtsEnabled rollout should be watched for submission failures
// before being trusted unattended.
//
// ── OPERATIONAL SHAPE ────────────────────────────────────────────────────────────────────────
//
// Anchor() does not block on Bitcoin confirmation (that takes hours) — it registers the pending
// timestamp with each calendar and returns immediately. Upgrade() is the separate, later poll
// that asks each calendar whether the pending timestamp has been upgraded to a Bitcoin-attested
// proof; the producer's leader-elected STH sweep calls it periodically for every
// STH with a submitted-but-unconfirmed anchor.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/wasabi-gaming/staking-verify/pkg/translog"
)

// KindOpenTimestamps names Anchorer kind "opentimestamps" — persisted to staking_sth.anchor_kind.
const KindOpenTimestamps = "opentimestamps"

// DefaultOTSCalendarURLs are the public OpenTimestamps calendar servers this anchorer submits to
// when no override list is configured — 3 independent operators for redundancy (any one being
// down or slow does not block the others). These are well-known, long-standing public calendars
// per the OpenTimestamps project; see the file header's protocol-confidence note.
var DefaultOTSCalendarURLs = []string{
	"https://a.pool.opentimestamps.org",
	"https://b.pool.opentimestamps.org",
	"https://a.pool.eternitywall.com",
}

// otsDefaultHTTPTimeout bounds one calendar HTTP call. Generous for a calendar server (these are
// small, infrequent requests), short enough that a hung calendar cannot stall the caller
// indefinitely — callers additionally wrap Anchor/Upgrade in their own ctx deadline.
const otsDefaultHTTPTimeout = 15 * time.Second

// otsMaxProofBytes bounds how much of a calendar's response this client will read. A calendar
// response is a small binary proof (bytes to a few KB); anything wildly larger is not a proof
// this client understands and reading it unbounded would be a self-inflicted DoS surface.
const otsMaxProofBytes = 1 << 20 // 1 MiB

// otsReceiptSchemaVersion versions the JSON this file stores in AnchorReceipt.Ref.
const otsReceiptSchemaVersion = 1

// Errors returned by this file. Each is distinguishable so callers (and cmd/staking-verify) can
// branch on WHAT is wrong rather than string-matching.
var (
	// ErrOTSInvalid guards malformed inputs (nil sth, wrong receipt kind, unparseable ref).
	ErrOTSInvalid = errors.New("attest: invalid opentimestamps anchor")
	// ErrOTSSubmitFailed means every configured calendar server refused or was unreachable —
	// Anchor() returns this only when NONE succeeded; a partial success (some calendars ok, some
	// not) is not an error, it is redundancy doing its job.
	ErrOTSSubmitFailed = errors.New("attest: opentimestamps submission failed at every calendar server")
	// ErrOTSDigestMismatch is Verify's hard failure: the receipt's own embedded digest does not
	// equal SHA256(canonical(sth)) recomputed from the head being checked — the receipt does not
	// bind to this head, full stop, regardless of anything else it claims.
	ErrOTSDigestMismatch = errors.New("attest: opentimestamps receipt digest does not match sha256(canonical(sth))")
	// ErrOTSPendingConfirmation is Verify's DISTINGUISHABLE not-yet-verifiable state: the digest
	// binds correctly, but no calendar has yet reported Bitcoin confirmation, so there is nothing
	// to independently verify yet. This is the state VerifyWalletStatement's header warns every
	// Verify-shaped function in this package must not silently upgrade to "success".
	ErrOTSPendingConfirmation = errors.New("attest: opentimestamps anchor is pending bitcoin confirmation (not yet independently verifiable; digest binding checked and OK)")
	// ErrOTSStillPending is Upgrade's per-calendar/per-call signal that a calendar has not yet
	// upgraded the proof (still returns 404 from GET /timestamp/<digest>) — not a failure, just
	// "not yet, ask again later".
	ErrOTSStillPending = errors.New("attest: opentimestamps calendar reports this timestamp is still pending bitcoin confirmation")
)

// otsCalendarSubmission is one calendar's outcome for a single Anchor() call.
type otsCalendarSubmission struct {
	Calendar string `json:"calendar"`
	// Pending is the hex-encoded raw pending-proof bytes this calendar returned — OPAQUE, stored
	// verbatim, never parsed (see file header). Empty when this calendar's submission failed.
	Pending string `json:"pending,omitempty"`
	// Err records why this calendar's submission failed, if it did. Other calendars in the same
	// receipt may still have succeeded — redundancy is the point.
	Err string `json:"err,omitempty"`
}

// OTSReceiptPayload is the JSON this file stores, verbatim, as AnchorReceipt.Ref — an "opaque
// receipt reference" per anchor.go's doc comment. Digest is the one field cmd/staking-verify (a
// binary that deliberately does not import this package — see its own header) needs to
// independently recompute and compare; everything else is this anchorer's own bookkeeping.
type OTSReceiptPayload struct {
	SchemaVersion int                     `json:"schemaVersion"`
	Digest        string                  `json:"digest"` // hex sha256 of canonical(sth)
	Submissions   []otsCalendarSubmission `json:"submissions"`
	// UpgradedCalendar/UpgradedProof are set by Upgrade() once ANY calendar reports the proof
	// upgraded — UpgradedProof is again OPAQUE hex bytes, never parsed.
	UpgradedCalendar string `json:"upgradedCalendar,omitempty"`
	UpgradedProof    string `json:"upgradedProof,omitempty"`
}

// DigestSTH returns SHA256(sth.CanonicalJSON()) — the exact 32 bytes this anchorer submits to
// OpenTimestamps and the exact bytes Verify recomputes and compares against a receipt. Using
// CanonicalJSON (rather than, say, RootHash alone) means the anchor commits to the WHOLE signed
// statement — operator, pool, tree size and timestamp included — not just the root.
func DigestSTH(sth *translog.STH) ([]byte, error) {
	if sth == nil {
		return nil, fmt.Errorf("%w: nil sth", ErrOTSInvalid)
	}
	canonical, err := sth.CanonicalJSON()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(canonical)
	return sum[:], nil
}

// OpenTimestampsAnchorer implements Anchorer kind "opentimestamps".
type OpenTimestampsAnchorer struct {
	calendars  []string
	httpClient *http.Client
}

// NewOpenTimestampsAnchorer wires the anchorer. A nil/empty calendars list uses
// DefaultOTSCalendarURLs; a nil httpClient gets one built with otsDefaultHTTPTimeout.
func NewOpenTimestampsAnchorer(calendars []string, httpClient *http.Client) *OpenTimestampsAnchorer {
	if len(calendars) == 0 {
		calendars = DefaultOTSCalendarURLs
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: otsDefaultHTTPTimeout}
	}
	return &OpenTimestampsAnchorer{calendars: calendars, httpClient: httpClient}
}

// Kind returns "opentimestamps".
func (a *OpenTimestampsAnchorer) Kind() string { return KindOpenTimestamps }

// Anchor submits SHA256(canonical(sth)) to every configured calendar server and returns
// immediately with a PENDING receipt — it never waits for Bitcoin confirmation (that takes
// hours; see Upgrade). Succeeds as long as AT LEAST ONE calendar accepted the submission;
// ErrOTSSubmitFailed only when every one of them failed, so a caller knows redundancy has been
// exhausted rather than merely degraded.
func (a *OpenTimestampsAnchorer) Anchor(ctx context.Context, sth *translog.STH) (*AnchorReceipt, error) {
	if a == nil {
		return nil, fmt.Errorf("%w: nil anchorer", ErrOTSInvalid)
	}
	digest, err := DigestSTH(sth)
	if err != nil {
		return nil, err
	}
	payload := OTSReceiptPayload{SchemaVersion: otsReceiptSchemaVersion, Digest: hex.EncodeToString(digest)}
	var lastErr error
	okCount := 0
	for _, cal := range a.calendars {
		pending, serr := a.submitOne(ctx, cal, digest)
		sub := otsCalendarSubmission{Calendar: cal}
		if serr != nil {
			sub.Err = serr.Error()
			lastErr = serr
		} else {
			sub.Pending = hex.EncodeToString(pending)
			okCount++
		}
		payload.Submissions = append(payload.Submissions, sub)
	}
	if okCount == 0 {
		return nil, fmt.Errorf("%w: %d calendar(s) tried, last error: %v", ErrOTSSubmitFailed, len(a.calendars), lastErr)
	}
	refBytes, merr := json.Marshal(payload)
	if merr != nil {
		return nil, fmt.Errorf("%w: encoding receipt: %v", ErrOTSInvalid, merr)
	}
	return &AnchorReceipt{
		Kind:       KindOpenTimestamps,
		Ref:        string(refBytes),
		AnchoredAt: time.Now().UTC(),
	}, nil
}

// submitOne POSTs digest to one calendar's /digest endpoint and returns its raw pending-proof
// response bytes, opaque and unparsed.
func (a *OpenTimestampsAnchorer) submitOne(ctx context.Context, calendarURL string, digest []byte) ([]byte, error) {
	url := strings.TrimRight(calendarURL, "/") + "/digest"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(digest))
	if err != nil {
		return nil, fmt.Errorf("calendar %s: build request: %w", calendarURL, err)
	}
	req.Header.Set("Content-Type", "application/vnd.opentimestamps.v1")
	req.Header.Set("Accept", "application/vnd.opentimestamps.v1")
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calendar %s: %w", calendarURL, err)
	}
	defer resp.Body.Close()
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, otsMaxProofBytes))
	if rerr != nil {
		return nil, fmt.Errorf("calendar %s: reading response: %w", calendarURL, rerr)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("calendar %s: HTTP %d", calendarURL, resp.StatusCode)
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("calendar %s: empty response body", calendarURL)
	}
	return body, nil
}

// Upgrade polls every calendar this receipt was submitted to for the Bitcoin-attested upgrade of
// a still-pending proof. Returns:
//   - (receipt, nil) unchanged, when the receipt was ALREADY upgraded (idempotent no-op) or is
//     freshly upgraded by this call (the returned receipt's Ref carries the upgrade),
//   - (nil, ErrOTSStillPending) when every calendar this receipt names is still pending,
//   - (nil, err) for a genuine failure (malformed receipt, no calendar reachable at all — a
//     transport failure, distinct from "reachable but still pending").
//
// This is deliberately NOT part of the Anchorer interface (anchor.go's interface is fixed and
// shared across future kinds that may have no concept of "upgrade" at all, e.g. a witness
// co-signing scheme that is either signed or not) — callers that know they hold an
// OpenTimestamps receipt type-assert to *OpenTimestampsAnchorer to reach it, exactly the pattern
// the producer's STH upgrade sweep uses.
func (a *OpenTimestampsAnchorer) Upgrade(ctx context.Context, r *AnchorReceipt) (*AnchorReceipt, error) {
	if a == nil {
		return nil, fmt.Errorf("%w: nil anchorer", ErrOTSInvalid)
	}
	if r == nil || r.Kind != KindOpenTimestamps {
		return nil, fmt.Errorf("%w: not an opentimestamps receipt", ErrOTSInvalid)
	}
	var payload OTSReceiptPayload
	if err := json.Unmarshal([]byte(r.Ref), &payload); err != nil {
		return nil, fmt.Errorf("%w: unparseable receipt ref: %v", ErrOTSInvalid, err)
	}
	if payload.UpgradedProof != "" {
		return r, nil // already upgraded; idempotent no-op
	}
	digest, derr := hex.DecodeString(payload.Digest)
	if derr != nil || len(digest) != sha256.Size {
		return nil, fmt.Errorf("%w: receipt digest is not a valid sha256 hex string", ErrOTSInvalid)
	}

	var lastErr error
	sawReachable := false
	for _, sub := range payload.Submissions {
		if sub.Pending == "" {
			continue // this calendar's original submission failed; nothing to poll here
		}
		upgraded, uerr := a.fetchUpgrade(ctx, sub.Calendar, digest)
		if uerr != nil {
			if errors.Is(uerr, ErrOTSStillPending) {
				sawReachable = true
				continue
			}
			lastErr = uerr
			continue
		}
		payload.UpgradedCalendar = sub.Calendar
		payload.UpgradedProof = hex.EncodeToString(upgraded)
		break
	}
	if payload.UpgradedProof == "" {
		if sawReachable || lastErr == nil {
			return nil, ErrOTSStillPending
		}
		return nil, fmt.Errorf("attest: opentimestamps upgrade poll failed at every calendar, last error: %w", lastErr)
	}
	refBytes, merr := json.Marshal(payload)
	if merr != nil {
		return nil, fmt.Errorf("%w: encoding upgraded receipt: %v", ErrOTSInvalid, merr)
	}
	return &AnchorReceipt{Kind: KindOpenTimestamps, Ref: string(refBytes), AnchoredAt: r.AnchoredAt}, nil
}

// fetchUpgrade asks one calendar whether digest's timestamp has been upgraded. Per the
// OpenTimestamps calendar protocol (see file header's confidence note), a 200 response body IS
// the upgraded proof bytes (opaque, stored verbatim); a 404 means still pending; anything else is
// a genuine error.
func (a *OpenTimestampsAnchorer) fetchUpgrade(ctx context.Context, calendarURL string, digest []byte) ([]byte, error) {
	url := strings.TrimRight(calendarURL, "/") + "/timestamp/" + hex.EncodeToString(digest)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("calendar %s: build request: %w", calendarURL, err)
	}
	req.Header.Set("Accept", "application/vnd.opentimestamps.v1")
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calendar %s: %w", calendarURL, err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, otsMaxProofBytes))
		if rerr != nil {
			return nil, fmt.Errorf("calendar %s: reading response: %w", calendarURL, rerr)
		}
		if len(body) == 0 {
			return nil, fmt.Errorf("calendar %s: empty upgrade response body", calendarURL)
		}
		return body, nil
	case http.StatusNotFound:
		return nil, ErrOTSStillPending
	default:
		return nil, fmt.Errorf("calendar %s: HTTP %d", calendarURL, resp.StatusCode)
	}
}

// Verify checks the receipt's digest binding against sth (REAL, always recomputed here — see the
// file header) and reports the anchor's confirmation state. It returns:
//   - nil ONLY when the digest binds AND a calendar has reported the proof upgraded — even then,
//     see the file header: this means "digest binding proven and a calendar attests Bitcoin
//     confirmation exists", NEVER "the Bitcoin merkle path was independently re-derived here".
//   - ErrOTSDigestMismatch when the receipt does not bind to this head — a hard failure,
//     regardless of anything else the receipt claims.
//   - ErrOTSPendingConfirmation when the digest binds but no calendar has reported an upgrade
//     yet — the DISTINGUISHABLE "not yet verifiable" state the task (and VerifyWalletStatement's
//     header, which this mirrors) requires instead of silently returning success.
func (a *OpenTimestampsAnchorer) Verify(ctx context.Context, sth *translog.STH, r *AnchorReceipt) error {
	_ = ctx // no network call is made by Verify itself — see file header; kept for interface parity
	if sth == nil || r == nil {
		return fmt.Errorf("%w: nil sth or receipt", ErrOTSInvalid)
	}
	if r.Kind != KindOpenTimestamps {
		return fmt.Errorf("%w: receipt kind %q, want %q", ErrOTSInvalid, r.Kind, KindOpenTimestamps)
	}
	want, err := DigestSTH(sth)
	if err != nil {
		return err
	}
	var payload OTSReceiptPayload
	if jerr := json.Unmarshal([]byte(r.Ref), &payload); jerr != nil {
		return fmt.Errorf("%w: unparseable receipt ref: %v", ErrOTSInvalid, jerr)
	}
	got, herr := hex.DecodeString(payload.Digest)
	if herr != nil {
		return fmt.Errorf("%w: receipt digest is not hex", ErrOTSInvalid)
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("%w: receipt digest %x, sth digest %x", ErrOTSDigestMismatch, got, want)
	}
	if payload.UpgradedProof == "" {
		return ErrOTSPendingConfirmation
	}
	return nil
}
