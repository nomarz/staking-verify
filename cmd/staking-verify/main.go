// Command staking-verify is the STANDALONE verifier for the staking transparency log
// (STAKING-P2). It consumes nothing but a canonical NDJSON export (from
// GET /api/v1/staking/transparency/export, a file, or stdin) plus the published key registry
// (GET /api/v1/staking/transparency/key, saved to a file), and independently re-verifies:
//
//   - the per-pool hash chain (every entry_hash recomputed from prev_hash + the re-canonicalized
//     entry, genesis anchored at 32 zero bytes),
//   - every Ed25519 signature against the registry key valid at each entry's own timestamp
//     (rotation-safe in both directions), and
//   - every account's share balance, replayed purely from the events — no stored total is
//     trusted — with Σ(account shares) == pool total asserted throughout and every EPOCH event's
//     declared shares_close checked against the replay,
//   - and, with -sth (STAKING-P3), every published Signed Tree Head: its RFC 6962 Merkle root
//     recomputed from scratch over the exported entry hashes, its Ed25519 signature (STH
//     context), and append-only consistency between every successive pair of heads — the
//     outside-verifiable anchor that catches a from-scratch rewritten chain, which can be made
//     internally self-consistent but can never reproduce a root recorded before the rewrite.
//
// The key registry also carries a signingEnabled flag (review item 10): whether the operator's
// deployment is CURRENTLY configured to sign new events. An unsigned entry timestamped at or
// after the registry's active key's validFrom is always a hard failure regardless of
// -allow-unsigned — the registry says that entry should have carried a signature. An unsigned
// entry from before that (or from an operator with signingEnabled:false) is still gated behind
// -allow-unsigned as before, just reported with a message that says WHICH case applies instead
// of one generic warning — "this operator has never signed anything" and "one unexpected null
// signature" no longer look identical in the output.
//
// Exit codes: 0 = everything verifies (a summary is printed), 1 = verification failed (the
// first failing seq and check are printed), 2 = usage/IO error.
//
// This package deliberately imports NONE of the producer's internal/ code — only pkg/translog
// (the published canonicalization/chain/signature primitives) and the public money package — so
// an outside party can compile and run it against a published export without trusting the
// production write path.
//
// Usage:
//
//	staking-verify -registry keys.json export.ndjson
//	staking-verify -registry keys.json -sth sths.ndjson export.ndjson
//	curl -s https://<operator-host>/api/v1/staking/transparency/export | staking-verify -registry keys.json -
//
// The -sth file carries one wire-form STH JSON object per line — each element of
// GET /staking/transparency/sth's "sths" array (e.g. `curl -s .../sth | jq -c '.sths[]'`).
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/wasabi-gaming/staking-verify/pkg/translog"
)

// parseRegistrySigningStatus reads the additive signingEnabled/activeKeyId fields straight off
// the raw registry document (GET …/transparency/key, review item 10) — translog.KeyRegistry
// itself only models {"keys":[...]}, so these two fields are parsed independently here rather
// than added to that type, keeping it a pure key-list format usable for local files too. known
// is false when the document predates this field (an older saved registry, or a hand-built one),
// which callers must treat as "no opinion available", never as "unsigned".
func parseRegistrySigningStatus(raw []byte) (known, enabled bool, activeKeyID string) {
	var doc struct {
		SigningEnabled *bool  `json:"signingEnabled"`
		ActiveKeyID    string `json:"activeKeyId"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || doc.SigningEnabled == nil {
		return false, false, ""
	}
	return true, *doc.SigningEnabled, doc.ActiveKeyID
}

func main() {
	registryPath := flag.String("registry", "", "path to the published key registry JSON ({\"keys\":[...]}, as served by /staking/transparency/key). For -attest, its purpose:\"wallet-attest\" entries pin the wallet attestation key: every wallet-attested record's embedded key must match one exactly")
	allowUnsigned := flag.Bool("allow-unsigned", false, "accept entries with no signature (only for logs produced by an unsigned deployment)")
	sthPath := flag.String("sth", "", "path to published Signed Tree Heads, one wire-form JSON object per line (each element of /staking/transparency/sth's \"sths\" array); enables STAKING-P3 root/signature/consistency verification against the export")
	anchorsPath := flag.String("anchors", "", "path to published anchor records, one JSON object per line (each element of /staking/transparency/sth's additive \"anchors\" array, STAKING-P5+); requires -sth. Independently recomputes and checks the digest binding of any OpenTimestamps anchor against the matching verified head; Bitcoin anchoring itself is reported as TESTIMONY, never independently re-verified here — confirm with the external `ots` tool")
	polPath := flag.String("pol", "", "path to a saved GET /staking/transparency/pol/:epoch/proof response body (STAKING-P4); re-verifies every own leaf against the published proof-of-liabilities root and total. Usable standalone (no export argument) or alongside the chain verification")
	attestPath := flag.String("attest", "", "path to a saved GET /staking/transparency/attestations/:epoch response body (STAKING-P5); verifies every wallet-attested record's signature over its re-canonicalized statement and reports the attested-vs-liabilities arithmetic AS DATA (an attestation is a claim by a named party, not proof the assets exist). With -sth, additionally checks every record's challenge against the pool's published tree heads (the freshness binding). With -wallet-key or a -registry carrying a wallet-attest purpose entry, additionally requires every record's embedded key to match that published anchor exactly; WITHOUT either, signatures verify against the record's own embedded key only and the output says so. Usable standalone or alongside the chain verification")
	walletKeyHex := flag.String("wallet-key", "", "hex 32-byte Ed25519 public key to pin as the wallet service's attestation key for -attest (obtained out-of-band); every wallet-attested record's embedded key must match it exactly")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [-registry keys.json] [-allow-unsigned] [-sth sths.ndjson] [-anchors anchors.ndjson] [-pol proof.json] [-attest attestations.json] [-wallet-key hex] [<export.ndjson | ->]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if *anchorsPath != "" && *sthPath == "" {
		fmt.Fprintln(os.Stderr, "error: -anchors requires -sth (anchors are matched against verified heads)")
		os.Exit(2)
	}

	// Parsed up front (rather than inside the with-export branch, where -registry historically
	// lived) because the -attest wallet-key pin consumes the registry too — including on the
	// standalone path.
	var registry *translog.KeyRegistry
	var signingKnown, signingEnabled bool
	var activeKeyID string
	if *registryPath != "" {
		raw, err := os.ReadFile(*registryPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: read registry: %v\n", err)
			os.Exit(2)
		}
		registry, err = translog.ParseKeyRegistry(raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: parse registry: %v\n", err)
			os.Exit(2)
		}
		// Review item 10: signingEnabled/activeKeyId are ADDITIVE fields on the same document
		// (GET …/transparency/key) that translog.KeyRegistry itself does not model — parsed here,
		// separately, off the same raw bytes.
		signingKnown, signingEnabled, activeKeyID = parseRegistrySigningStatus(raw)
	}
	attestOpts := AttestOptions{Registry: registry}
	if *walletKeyHex != "" {
		raw, err := hex.DecodeString(*walletKeyHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: -wallet-key is not hex: %v\n", err)
			os.Exit(2)
		}
		if len(raw) != ed25519.PublicKeySize {
			fmt.Fprintf(os.Stderr, "error: -wallet-key is %d bytes, want %d\n", len(raw), ed25519.PublicKeySize)
			os.Exit(2)
		}
		attestOpts.WalletKey = ed25519.PublicKey(raw)
	}

	// STAKING-P4/P5: -pol and -attest verify from their own material and need no export —
	// allow them standalone. Standalone -attest still consumes -sth when given (parse-only:
	// the heads' own signatures/roots are verified by the with-export flow; here they supply
	// the published root set the challenges must match).
	if flag.NArg() == 0 && (*polPath != "" || *attestPath != "") {
		if *polPath != "" {
			verifyPoLFile(*polPath)
		}
		if *attestPath != "" {
			var sths []*translog.STH
			if *sthPath != "" {
				f, ferr := os.Open(*sthPath)
				if ferr != nil {
					fmt.Fprintf(os.Stderr, "error: open sth file: %v\n", ferr)
					os.Exit(2)
				}
				var perr error
				sths, perr = ParseSTHStream(f)
				f.Close()
				if perr != nil {
					fmt.Fprintf(os.Stderr, "error: %v\n", perr)
					os.Exit(2)
				}
			}
			verifyAttestFile(*attestPath, sths, attestOpts)
		}
		return
	}
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}

	var in io.Reader
	if arg := flag.Arg(0); arg == "-" {
		in = os.Stdin
	} else {
		f, err := os.Open(arg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: open export: %v\n", err)
			os.Exit(2)
		}
		defer f.Close()
		in = f
	}

	opts := Options{
		Registry: registry, AllowUnsigned: *allowUnsigned, CollectLeaves: *sthPath != "",
		RegistrySigningKnown: signingKnown, RegistrySigningEnabled: signingEnabled, RegistryActiveKeyID: activeKeyID,
	}
	sum, err := VerifyStream(in, opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	WriteSummary(os.Stdout, sum, time.Now())

	// STAKING-P3: verify the published Signed Tree Heads against the (now chain-verified)
	// export — recomputed roots, STH signatures, and append-only consistency between heads.
	var verifiedSTHs []*translog.STH
	if *sthPath != "" {
		f, ferr := os.Open(*sthPath)
		if ferr != nil {
			fmt.Fprintf(os.Stderr, "error: open sth file: %v\n", ferr)
			os.Exit(2)
		}
		sths, perr := ParseSTHStream(f)
		f.Close()
		if perr != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", perr)
			os.Exit(2)
		}
		sthSum, verr := VerifySTHs(sum, sths, opts)
		if verr != nil {
			fmt.Fprintln(os.Stderr, verr.Error())
			os.Exit(1)
		}
		WriteSTHSummary(os.Stdout, sthSum)
		verifiedSTHs = sths

		// STAKING-P5+: -anchors reports each anchored head's external-anchoring state, with the
		// digest binding independently recomputed against the heads just verified above. See
		// sth.go's "OpenTimestamps anchor reporting" section for exactly what this does and does
		// not check.
		if *anchorsPath != "" {
			f, aerr := os.Open(*anchorsPath)
			if aerr != nil {
				fmt.Fprintf(os.Stderr, "error: open anchors file: %v\n", aerr)
				os.Exit(2)
			}
			anchors, perr := ParseAnchorStream(f)
			f.Close()
			if perr != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", perr)
				os.Exit(2)
			}
			reports, verr := VerifyAnchors(sths, anchors)
			if verr != nil {
				fmt.Fprintln(os.Stderr, verr.Error())
				os.Exit(1)
			}
			WriteAnchorReport(os.Stdout, reports)
		}
	}

	// STAKING-P4: verify a saved proof-of-liabilities response, independent of the chain checks
	// above (the PoL tree commits to balances, not to the event log).
	if *polPath != "" {
		verifyPoLFile(*polPath)
	}

	// STAKING-P5: verify a saved attestation document. Runs AFTER the -sth verification so the
	// challenge freshness check matches against heads that just verified end-to-end.
	if *attestPath != "" {
		verifyAttestFile(*attestPath, verifiedSTHs, attestOpts)
	}
}

// verifyPoLFile runs the -pol verification with the binary's exit-code conventions
// (0 verified, 1 failed, 2 usage/IO).
func verifyPoLFile(path string) {
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: open pol proof: %v\n", err)
		os.Exit(2)
	}
	polSum, verr := VerifyPoLStream(f)
	f.Close()
	if verr != nil {
		fmt.Fprintln(os.Stderr, verr.Error())
		os.Exit(1)
	}
	WritePoLSummary(os.Stdout, polSum)
}
