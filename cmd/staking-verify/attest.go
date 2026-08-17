package main

// STAKING-P5: attestation verification — the -attest half of the verifier.
//
// Input: the JSON response body of GET /api/v1/staking/transparency/attestations/:epoch, saved
// verbatim. The wire form AND the wallet-statement verification both live in pkg/attest (the
// LiabilityProofDoc one-contract rule), so this file is only the CLI shell: parse, verify,
// report.
//
// WHAT THIS TOOL ESTABLISHES — and prints, because the boundary IS the product here:
//   - every "wallet_attested" record's Ed25519 signature verifies over the RE-CANONICALIZED
//     statement (fields parsed from the document, never a served blob), under the record's own
//     embedded key — so the served numbers are exactly what the EMBEDDED key signed;
//   - WHOSE key that is requires a trust anchor the record cannot supply about itself: with
//     -wallet-key <hex>, or a -registry whose document carries a purpose:"wallet-attest" entry
//     (GET /staking/transparency/key publishes one per wallet attestation key), every record's
//     embedded key must EXACTLY match the pinned/registry key (key id AND key bytes, and the
//     registry entry's validity window must cover the statement's asOf) — a mismatch is a hard
//     failure, because an internally self-consistent statement under a fresh keypair passes
//     every other check by construction. Without a pin, the output SAYS the check did not
//     happen; it never claims the wallet service signed anything;
//   - when -sth is also given, every record's challenge equals a published Signed-Tree-Head
//     root of the SAME pool from that file — the freshness binding: the attestation was made
//     against a log state that was already public;
//   - the solvency ARITHMETIC: Σ attested vs the published liabilities total, reported as
//     data.
//
// What it deliberately does NOT establish, stated in the output verbatim: that the assets
// exist. A verified attestation means the signing party — the wallet service only when its key
// is pinned as above, an auditor — asserted the figure; trusting that party is the reader's
// decision, not this tool's. "auditor" records carry an opaque third-party signature this tool
// does not interpret; it reports the document hash and provenance for out-of-band checking.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/wasabi-gaming/staking-verify/internal/money"
	"github.com/wasabi-gaming/staking-verify/pkg/attest"
	"github.com/wasabi-gaming/staking-verify/pkg/translog"
)

// AttestOptions carries the optional trust-anchor material for -attest verification. Either (or
// both) pin the wallet attestation key; with neither, wallet signatures verify against their
// own embedded keys only, and the report says so.
type AttestOptions struct {
	// Registry is the parsed -registry document. Only its purpose:"wallet-attest" entries pin
	// anything here; a registry with none (e.g. one predating the purpose tag) supplies no
	// anchor and the report falls back to the unpinned wording.
	Registry *translog.KeyRegistry
	// WalletKey is the -wallet-key pin: the wallet service's Ed25519 attestation public key,
	// obtained out-of-band. nil = no direct pin.
	WalletKey ed25519.PublicKey
}

// walletPinAvailable reports whether ANY wallet-key anchor was supplied.
func (o AttestOptions) walletPinAvailable() bool {
	return len(o.WalletKey) != 0 || (o.Registry != nil && len(o.Registry.KeysWithPurpose(translog.KeyPurposeWalletAttest)) > 0)
}

// AttestSummary is the -attest verification report.
type AttestSummary struct {
	PoolID           string
	EpochID          int64
	EpochDate        string
	Currency         int
	Coverage         string
	PolTotal         money.Amount
	AttestedTotal    *money.Amount // nil under coverage "none"
	WalletVerified   int           // wallet_attested records whose signature verified
	AuditorRecorded  int           // auditor records (opaque signatures, reported not verified)
	ChallengeChecked bool          // whether -sth material was available for challenge matching
	// WalletKeyPinned: pin material (-wallet-key / a registry wallet-attest entry) was available
	// AND every wallet record's embedded key matched it exactly. False = the embedded keys were
	// checked against NOTHING independently published, and the report must say only that.
	WalletKeyPinned bool
	// WalletBases: each wallet record's own "basis" payload note (deduplicated), stating WHAT
	// the wallet summed — surfaced verbatim next to the comparison so the caveat travels with
	// the number (P2-P5 review M2).
	WalletBases []string
}

// checkWalletKeyPin enforces the trust anchor for one wallet_attested record: the embedded key
// must EXACTLY match every supplied pin — key id AND raw key bytes, and for a registry entry
// its purpose must be "wallet-attest" with a validity window covering the statement's asOf. Any
// deviation is a hard error: "a wallet-attest key exists somewhere in the registry" is NOT a
// match.
func checkWalletKeyPin(i int, st *attest.WalletStatement, opts AttestOptions) error {
	if len(opts.WalletKey) != 0 {
		if wantID := attest.WalletKeyID(opts.WalletKey); st.KeyID != wantID || !bytes.Equal(st.PublicKey, opts.WalletKey) {
			return fmt.Errorf("attest: record %d embedded key %s does NOT match the -wallet-key pin %s — the statement is self-consistent under its own key, but that key is not the wallet service's published attestation key",
				i, st.KeyID, wantID)
		}
	}
	if opts.Registry != nil && len(opts.Registry.KeysWithPurpose(translog.KeyPurposeWalletAttest)) > 0 {
		entry, ok := opts.Registry.Lookup(st.KeyID)
		if !ok {
			return fmt.Errorf("attest: record %d embedded key %s is NOT in the supplied registry — the statement is self-consistent under its own key, but that key was never published as the wallet service's",
				i, st.KeyID)
		}
		if entry.Purpose != translog.KeyPurposeWalletAttest {
			return fmt.Errorf("attest: record %d embedded key %s is registered with purpose %q, not %q — a key published for another job can never anchor a wallet attestation",
				i, st.KeyID, entry.Purpose, translog.KeyPurposeWalletAttest)
		}
		if !bytes.Equal(entry.PublicKey, st.PublicKey) {
			return fmt.Errorf("attest: record %d embedded key bytes do NOT match the registry's %s entry — same claimed key id, different key material", i, st.KeyID)
		}
		if _, err := opts.Registry.Resolve(st.KeyID, st.AsOf); err != nil {
			return fmt.Errorf("attest: record %d wallet key %s is outside its registry validity window at the statement's asOf: %w", i, st.KeyID, err)
		}
	}
	return nil
}

// VerifyAttestDoc parses and verifies one saved attestation document. sths carries the
// published heads from -sth when given (nil = challenge matching skipped, reported as such);
// opts carries the wallet-key trust anchor when given (none = the pin check is skipped and
// REPORTED as skipped, never silently passed).
func VerifyAttestDoc(r io.Reader, sths []*translog.STH, opts AttestOptions) (*AttestSummary, error) {
	doc, err := attest.ParseDoc(r)
	if err != nil {
		return nil, err
	}
	polTotal, err := money.Parse(doc.PolTotalAmount)
	if err != nil {
		return nil, fmt.Errorf("attest: polTotalAmount is not a decimal: %w", err)
	}
	sum := &AttestSummary{
		PoolID: doc.PoolID, EpochID: doc.EpochID, EpochDate: doc.EpochDate,
		Currency: doc.Currency, Coverage: doc.Coverage, PolTotal: polTotal,
		ChallengeChecked: sths != nil,
		WalletKeyPinned:  opts.walletPinAvailable(),
	}

	// Published roots of THIS pool, for the freshness binding.
	poolRoots := map[string]bool{}
	for _, sth := range sths {
		if sth.PoolID == doc.PoolID {
			poolRoots[hex.EncodeToString(sth.RootHash)] = true
		}
	}

	total := money.Zero
	for i, rec := range doc.Attestations {
		balance, berr := money.Parse(rec.AttestedBalance)
		if berr != nil {
			return nil, fmt.Errorf("attest: record %d attestedBalance is not a decimal: %w", i, berr)
		}
		if balance.IsNegative() {
			return nil, fmt.Errorf("attest: record %d carries a NEGATIVE attested balance %s — a negative attestation cancels real coverage arithmetic and is never valid", i, rec.AttestedBalance)
		}
		if sths != nil && !poolRoots[rec.Challenge] {
			return nil, fmt.Errorf("attest: record %d (kind %s) challenge %s matches NO published tree head of pool %s in the -sth material — the attestation is not bound to this pool's published log state",
				i, rec.Kind, rec.Challenge, doc.PoolID)
		}
		switch rec.Kind {
		case attest.KindWalletAttested:
			st, serr := attest.WalletStatementFromRecord(rec)
			if serr != nil {
				return nil, fmt.Errorf("attest: record %d: %w", i, serr)
			}
			if verr := attest.VerifyWalletStatement(*st); verr != nil {
				return nil, fmt.Errorf("attest: record %d wallet signature FAILED: %w", i, verr)
			}
			// The signature above verified under the record's OWN embedded key — internal
			// consistency only. The pin check below is what binds that key to the wallet
			// service; when no pin material was supplied it is skipped, and the report's
			// wording downgrades accordingly (never silently).
			if perr := checkWalletKeyPin(i, st, opts); perr != nil {
				return nil, perr
			}
			// Surface the record's own basis note beside the arithmetic (review M2): the wallet's
			// figure is its custodial ledger total, not money earmarked for staking, and that
			// caveat must travel WITH the number rather than live only in prose elsewhere.
			if basis := rec.Payload["basis"]; basis != "" {
				dup := false
				for _, b := range sum.WalletBases {
					if b == basis {
						dup = true
						break
					}
				}
				if !dup {
					sum.WalletBases = append(sum.WalletBases, basis)
				}
			}
			sum.WalletVerified++
		case attest.KindAuditor:
			// The auditor's signature is opaque third-party material; nothing here can (or
			// should pretend to) verify it. Counted and reported for out-of-band checking.
			sum.AuditorRecorded++
		default:
			return nil, fmt.Errorf("attest: record %d carries unknown kind %q", i, rec.Kind)
		}
		total = total.Add(balance)
	}
	if doc.Coverage == attest.CoverageAttested {
		// The document's own aggregate must equal the Σ of the records it serves.
		docTotal, derr := money.Parse(doc.AttestedTotal)
		if derr != nil {
			return nil, fmt.Errorf("attest: attestedTotal is not a decimal: %w", derr)
		}
		if !docTotal.Equal(total) {
			return nil, fmt.Errorf("attest: served attestedTotal %s != Σ of served records %s", doc.AttestedTotal, money.String(total))
		}
		sum.AttestedTotal = &total
	}
	return sum, nil
}

// WriteAttestSummary prints the report — attested figures as DATA, the trust boundary spelled
// out, never a solvency verdict.
func WriteAttestSummary(w io.Writer, sum *AttestSummary) {
	fmt.Fprintf(w, "attest: epoch %d (%s), pool %s, currency %d\n", sum.EpochID, sum.EpochDate, sum.PoolID, sum.Currency)
	if sum.Coverage == attest.CoverageNone {
		fmt.Fprintf(w, "attest: coverage NONE — nothing was attested for this epoch's window. Unattested is not \"attested insolvent\"; it is the absence of any claim.\n")
		fmt.Fprintf(w, "attest: published liabilities total %s has NO attested-asset figure beside it for this epoch\n", money.String(sum.PolTotal))
		return
	}
	// The wallet-record line claims exactly what was checked, never more: without pin material
	// the embedded key was matched against NOTHING independently published, and saying otherwise
	// is the overclaim this wording exists to prevent.
	if sum.WalletKeyPinned {
		fmt.Fprintf(w, "attest: %d wallet-attested record(s) verified — signature valid over the re-canonicalized statement, under the wallet service's published attestation key (embedded key matches the pinned wallet-attest key exactly)\n", sum.WalletVerified)
	} else {
		fmt.Fprintf(w, "attest: %d wallet-attested record(s): signature valid over the re-canonicalized statement under the record's OWN embedded key — NOT checked against any independently published wallet key (supply -wallet-key or a registry with a wallet-attest purpose entry to pin it)\n", sum.WalletVerified)
	}
	if sum.AuditorRecorded > 0 {
		fmt.Fprintf(w, "attest: %d auditor record(s) present — their third-party signatures are opaque to this tool; check them out-of-band against the auditor's published key material\n", sum.AuditorRecorded)
	}
	if sum.ChallengeChecked {
		fmt.Fprintf(w, "attest: every record's challenge matches a published tree head of this pool (freshness binding holds)\n")
	} else {
		fmt.Fprintf(w, "WARNING: no -sth material given — challenge freshness NOT checked against published tree heads\n")
	}
	attested := *sum.AttestedTotal
	// Review M2: "attested custodial balance (wallet ledger)", never "attested assets" — the
	// wallet's figure is SUM(wallets.balance) for the operator+currency, i.e. player custodial
	// balances the wallet ledger holds for its own account holders, a DIFFERENT liability pot
	// than staking. Rendering it as "assets vs liabilities" reads as coverage, which this number
	// cannot claim. The per-record basis notes print immediately below so the caveat travels
	// with the figure.
	fmt.Fprintf(w, "attest: attested custodial balance (wallet ledger) %s vs published PoL liabilities %s (difference = %s)\n",
		money.String(attested), money.String(sum.PolTotal), money.String(attested.Sub(sum.PolTotal)))
	for _, basis := range sum.WalletBases {
		fmt.Fprintf(w, "attest: basis of the attested figure — %s\n", basis)
	}
	fmt.Fprintf(w, "attest: NOTE — the custodial total is money the wallet ledger holds for its own account holders; it is not earmarked for staking liabilities. The comparison shows scale, not coverage.\n")
	fmt.Fprintf(w, "attest: NOTE — these are ATTESTED figures: each is a signed claim by the named party (the wallet service, an auditor). This tool verified the signatures and the arithmetic; it cannot verify the assets exist.\n")
}

// verifyAttestFile runs the -attest verification with the binary's exit-code conventions
// (0 verified, 1 failed, 2 usage/IO), mirroring verifyPoLFile. sths is the parsed -sth
// material when given (nil = challenge matching skipped, reported as a WARNING); opts carries
// the wallet-key pin material when given (none = the report's wording says the anchor was not
// checked).
func verifyAttestFile(path string, sths []*translog.STH, opts AttestOptions) {
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: open attestation doc: %v\n", err)
		os.Exit(2)
	}
	sum, verr := VerifyAttestDoc(f, sths, opts)
	f.Close()
	if verr != nil {
		fmt.Fprintln(os.Stderr, verr.Error())
		os.Exit(1)
	}
	WriteAttestSummary(os.Stdout, sum)
}
