package attest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/wasabi-gaming/staking-verify/pkg/translog"
)

func sampleOTSSTH() *translog.STH {
	return &translog.STH{
		SchemaVersion: translog.SchemaVersion1,
		OperatorID:    "11111111-1111-1111-1111-111111111111",
		PoolID:        "22222222-2222-2222-2222-222222222222",
		TreeSize:      42,
		RootHash:      bytes.Repeat([]byte{0xcd}, translog.HashSize),
		TS:            time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC),
	}
}

// TestDigestSTHMatchesCanonicalJSON pins DigestSTH to exactly sha256(CanonicalJSON()) — the
// contract Verify and cmd/staking-verify both depend on.
func TestDigestSTHMatchesCanonicalJSON(t *testing.T) {
	sth := sampleOTSSTH()
	canonical, err := sth.CanonicalJSON()
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	want := sha256.Sum256(canonical)
	got, err := DigestSTH(sth)
	if err != nil {
		t.Fatalf("DigestSTH: %v", err)
	}
	if !bytes.Equal(got, want[:]) {
		t.Fatalf("digest mismatch: got %x want %x", got, want)
	}
}

func TestDigestSTHNilRefused(t *testing.T) {
	if _, err := DigestSTH(nil); !errors.Is(err, ErrOTSInvalid) {
		t.Fatalf("want ErrOTSInvalid, got %v", err)
	}
}

// fakeCalendar builds an httptest server speaking the subset of the OpenTimestamps calendar
// protocol this file implements: POST /digest returns a fixed pending-proof body; GET
// /timestamp/<hex> returns upgraded per upgradeStatus/upgradeBody.
type fakeCalendar struct {
	pendingBody   []byte
	digestStatus  int // status POST /digest returns; 0 defaults to 200
	upgradeStatus int // status GET /timestamp/<hex> returns
	upgradeBody   []byte
	sawDigest     []byte
}

func (f *fakeCalendar) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/digest":
			body := make([]byte, 32)
			n, _ := r.Body.Read(body)
			f.sawDigest = append([]byte(nil), body[:n]...)
			status := f.digestStatus
			if status == 0 {
				status = http.StatusOK
			}
			w.WriteHeader(status)
			if status == http.StatusOK {
				_, _ = w.Write(f.pendingBody)
			}
		case r.Method == http.MethodGet && len(r.URL.Path) > len("/timestamp/"):
			w.WriteHeader(f.upgradeStatus)
			if f.upgradeStatus == http.StatusOK {
				_, _ = w.Write(f.upgradeBody)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func TestAnchorSubmitsToAllCalendarsAndStoresDigest(t *testing.T) {
	cal1 := &fakeCalendar{pendingBody: []byte("pending-proof-1")}
	cal2 := &fakeCalendar{pendingBody: []byte("pending-proof-2")}
	srv1 := httptest.NewServer(cal1.handler())
	defer srv1.Close()
	srv2 := httptest.NewServer(cal2.handler())
	defer srv2.Close()

	a := NewOpenTimestampsAnchorer([]string{srv1.URL, srv2.URL}, nil)
	sth := sampleOTSSTH()
	receipt, err := a.Anchor(t.Context(), sth)
	if err != nil {
		t.Fatalf("Anchor: %v", err)
	}
	if receipt.Kind != KindOpenTimestamps {
		t.Fatalf("kind = %q", receipt.Kind)
	}
	wantDigest, _ := DigestSTH(sth)
	if !bytes.Equal(cal1.sawDigest, wantDigest) || !bytes.Equal(cal2.sawDigest, wantDigest) {
		t.Fatalf("calendars did not receive the sth digest verbatim")
	}
	var payload OTSReceiptPayload
	if err := json.Unmarshal([]byte(receipt.Ref), &payload); err != nil {
		t.Fatalf("ref not valid json: %v", err)
	}
	if payload.Digest != hex.EncodeToString(wantDigest) {
		t.Fatalf("payload digest mismatch")
	}
	if len(payload.Submissions) != 2 {
		t.Fatalf("want 2 submissions, got %d", len(payload.Submissions))
	}
	for _, sub := range payload.Submissions {
		if sub.Err != "" {
			t.Fatalf("unexpected calendar failure: %s", sub.Err)
		}
	}
}

// TestAnchorSucceedsWithPartialCalendarFailure asserts redundancy: one calendar down does not
// fail the whole submission.
func TestAnchorSucceedsWithPartialCalendarFailure(t *testing.T) {
	good := &fakeCalendar{pendingBody: []byte("ok")}
	bad := &fakeCalendar{digestStatus: http.StatusInternalServerError}
	srvGood := httptest.NewServer(good.handler())
	defer srvGood.Close()
	srvBad := httptest.NewServer(bad.handler())
	defer srvBad.Close()

	a := NewOpenTimestampsAnchorer([]string{srvGood.URL, srvBad.URL}, nil)
	receipt, err := a.Anchor(t.Context(), sampleOTSSTH())
	if err != nil {
		t.Fatalf("Anchor should succeed with one good calendar: %v", err)
	}
	var payload OTSReceiptPayload
	_ = json.Unmarshal([]byte(receipt.Ref), &payload)
	failCount, okCount := 0, 0
	for _, sub := range payload.Submissions {
		if sub.Err != "" {
			failCount++
		} else {
			okCount++
		}
	}
	if failCount != 1 || okCount != 1 {
		t.Fatalf("want 1 fail + 1 ok, got fail=%d ok=%d", failCount, okCount)
	}
}

func TestAnchorFailsWhenEveryCalendarFails(t *testing.T) {
	bad := &fakeCalendar{digestStatus: http.StatusInternalServerError}
	srv := httptest.NewServer(bad.handler())
	defer srv.Close()

	a := NewOpenTimestampsAnchorer([]string{srv.URL}, nil)
	_, err := a.Anchor(t.Context(), sampleOTSSTH())
	if !errors.Is(err, ErrOTSSubmitFailed) {
		t.Fatalf("want ErrOTSSubmitFailed, got %v", err)
	}
}

// TestVerifyDigestBindingPassAndFail is the precise, always-real check this file performs.
func TestVerifyDigestBindingPassAndFail(t *testing.T) {
	a := NewOpenTimestampsAnchorer(nil, nil)
	sth := sampleOTSSTH()
	digest, _ := DigestSTH(sth)
	payload := OTSReceiptPayload{SchemaVersion: otsReceiptSchemaVersion, Digest: hex.EncodeToString(digest)}
	refBytes, _ := json.Marshal(payload)
	receipt := &AnchorReceipt{Kind: KindOpenTimestamps, Ref: string(refBytes), AnchoredAt: time.Now()}

	// Correct digest, no upgrade yet -> the distinguishable pending state, never nil.
	err := a.Verify(t.Context(), sth, receipt)
	if !errors.Is(err, ErrOTSPendingConfirmation) {
		t.Fatalf("want ErrOTSPendingConfirmation, got %v", err)
	}

	// Tampered head -> hard digest mismatch failure.
	tampered := sampleOTSSTH()
	tampered.TreeSize = 43
	if err := a.Verify(t.Context(), tampered, receipt); !errors.Is(err, ErrOTSDigestMismatch) {
		t.Fatalf("want ErrOTSDigestMismatch, got %v", err)
	}
}

// TestVerifyReportsConfirmedAfterUpgrade: once a receipt carries an upgraded proof, Verify
// returns nil (digest binding held AND a calendar attests confirmation) — but this only ever
// means "testimony received", documented explicitly in the file header; this test only pins the
// state-machine transition, not any claim about real Bitcoin verification.
func TestVerifyReportsConfirmedAfterUpgrade(t *testing.T) {
	sth := sampleOTSSTH()
	digest, _ := DigestSTH(sth)
	payload := OTSReceiptPayload{
		SchemaVersion:    otsReceiptSchemaVersion,
		Digest:           hex.EncodeToString(digest),
		UpgradedCalendar: "https://a.pool.opentimestamps.org",
		UpgradedProof:    hex.EncodeToString([]byte("upgraded-proof-bytes")),
	}
	refBytes, _ := json.Marshal(payload)
	receipt := &AnchorReceipt{Kind: KindOpenTimestamps, Ref: string(refBytes)}

	a := NewOpenTimestampsAnchorer(nil, nil)
	if err := a.Verify(t.Context(), sth, receipt); err != nil {
		t.Fatalf("Verify should report confirmed (nil): %v", err)
	}
}

func TestVerifyRejectsWrongKind(t *testing.T) {
	a := NewOpenTimestampsAnchorer(nil, nil)
	receipt := &AnchorReceipt{Kind: "rfc3161", Ref: "{}"}
	if err := a.Verify(t.Context(), sampleOTSSTH(), receipt); !errors.Is(err, ErrOTSInvalid) {
		t.Fatalf("want ErrOTSInvalid, got %v", err)
	}
}

// TestUpgradeStillPendingWhenCalendarReturns404 exercises the real HTTP call: this test DOES
// verify our client's own handling of the documented protocol against a mock server — it does
// NOT verify the protocol assumptions themselves against a real opentimestamps.org calendar (see
// the file header's confidence note).
func TestUpgradeStillPendingWhenCalendarReturns404(t *testing.T) {
	cal := &fakeCalendar{pendingBody: []byte("pending"), upgradeStatus: http.StatusNotFound}
	srv := httptest.NewServer(cal.handler())
	defer srv.Close()

	a := NewOpenTimestampsAnchorer([]string{srv.URL}, nil)
	sth := sampleOTSSTH()
	receipt, err := a.Anchor(t.Context(), sth)
	if err != nil {
		t.Fatalf("Anchor: %v", err)
	}
	_, err = a.Upgrade(t.Context(), receipt)
	if !errors.Is(err, ErrOTSStillPending) {
		t.Fatalf("want ErrOTSStillPending, got %v", err)
	}
}

func TestUpgradeSucceedsWhenCalendarReturns200(t *testing.T) {
	cal := &fakeCalendar{
		pendingBody:   []byte("pending"),
		upgradeStatus: http.StatusOK,
		upgradeBody:   []byte("bitcoin-attested-proof-bytes"),
	}
	srv := httptest.NewServer(cal.handler())
	defer srv.Close()

	a := NewOpenTimestampsAnchorer([]string{srv.URL}, nil)
	sth := sampleOTSSTH()
	receipt, err := a.Anchor(t.Context(), sth)
	if err != nil {
		t.Fatalf("Anchor: %v", err)
	}
	upgraded, err := a.Upgrade(t.Context(), receipt)
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	var payload OTSReceiptPayload
	if err := json.Unmarshal([]byte(upgraded.Ref), &payload); err != nil {
		t.Fatalf("upgraded ref not json: %v", err)
	}
	if payload.UpgradedProof != hex.EncodeToString(cal.upgradeBody) {
		t.Fatalf("upgraded proof not stored verbatim")
	}
	// Verify now reports confirmed (nil) rather than pending.
	if verr := a.Verify(t.Context(), sth, upgraded); verr != nil {
		t.Fatalf("Verify after upgrade: %v", verr)
	}

	// Idempotent: upgrading an already-upgraded receipt is a no-op success, not a re-fetch.
	again, err := a.Upgrade(t.Context(), upgraded)
	if err != nil {
		t.Fatalf("re-Upgrade: %v", err)
	}
	if again.Ref != upgraded.Ref {
		t.Fatalf("re-Upgrade should be a no-op")
	}
}

func TestUpgradeRejectsUnparseableReceipt(t *testing.T) {
	a := NewOpenTimestampsAnchorer(nil, nil)
	_, err := a.Upgrade(t.Context(), &AnchorReceipt{Kind: KindOpenTimestamps, Ref: "not json"})
	if !errors.Is(err, ErrOTSInvalid) {
		t.Fatalf("want ErrOTSInvalid, got %v", err)
	}
}

// TestNewOpenTimestampsAnchorerDefaultsCalendars pins that an empty override list falls back to
// the shipped default rather than submitting to nothing.
func TestNewOpenTimestampsAnchorerDefaultsCalendars(t *testing.T) {
	a := NewOpenTimestampsAnchorer(nil, nil)
	if len(a.calendars) != len(DefaultOTSCalendarURLs) {
		t.Fatalf("want %d default calendars, got %d", len(DefaultOTSCalendarURLs), len(a.calendars))
	}
}
