package cmd

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"open-trust/core"
)

func RunVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)

	provPath    := fs.String("provenance", "provenance.json", "path to provenance.json")
	online      := fs.Bool("online", false, "fetch and verify social proof URLs (requires internet)")
	noCol       := fs.Bool("no-colour", false, "disable ANSI colour output (useful for CI/scripts)")
	registryURL := fs.String("registry", "",
		"trust registry URL for an additional online check\n"+
			"  Git URL : git@github.com:org/registry.git\n"+
			"  Raw URL : https://raw.githubusercontent.com/org/registry/main")
	localDir := fs.String("registry-dir", defaultRegistryDir(), "local cache directory for the cloned registry")

	fs.Usage = func() {
		PrintCommandBanner("verify", "verify a binary against its provenance.json")
		fmt.Println(`Performs a multi-step verification of a binary:

  Step 1  INTEGRITY    SHA-256 + SHA-512 of the binary vs. provenance.json
  Step 2  SIGNATURE    Ed25519 signature of the developer's key
  Step 3  SOCIAL       Optional: fingerprint found at social proof URLs
  Step 4  ATTESTATIONS Peer signatures, trust level calculation
  Step 5  REGISTRY     Optional: compare against published community registry

Exit code 0 = all checks passed.
Exit code 1 = at least one critical check failed.

Flags:`)
		fs.PrintDefaults()
		fmt.Println(`
Examples:
  # Offline verification (fast, no internet)
  open-trust verify ./my-app-linux-amd64

  # With social proof checks
  open-trust verify --online ./my-app-linux-amd64

  # With registry check (Git)
  open-trust verify --registry git@github.com:org/registry.git ./my-app`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		fs.Usage()
		return fmt.Errorf("binary path is required as a positional argument")
	}

	SetColour(!*noCol)
	binaryPath := fs.Arg(0)

	// ── Load provenance ───────────────────────────────────────────────────────

	p, err := core.LoadProvenance(*provPath)
	if err != nil {
		printFail("Cannot load provenance.json: %s", *provPath)
		return fmt.Errorf(
			"load provenance: %w\n\n"+
				"  Make sure provenance.json is in the current directory or use --provenance <path>.\n"+
				"  If you don't have provenance.json, ask the developer for it.", err)
	}

	allPassed := true

	// ── Header ────────────────────────────────────────────────────────────────

	fmt.Println()
	fmt.Println(colBold("OPEN-TRUST VERIFICATION REPORT"))
	printDivider()
	fmt.Printf("  Binary      : %s\n", binaryPath)
	fmt.Printf("  Provenance  : %s\n", *provPath)
	fmt.Printf("  Signer      : %s\n", colBold(p.Identity.DisplayName))
	fmt.Printf("  Fingerprint : %s\n", p.Identity.PubKeyFingerprint)
	fmt.Printf("  Signed at   : %s\n", p.Signature.Timestamp)
	fmt.Println()

	// ── Step 1: Integrity ─────────────────────────────────────────────────────

	printSection("STEP 1 — INTEGRITY  (binary hash)")

	sha256hex, sha512hex, err := core.HashFileProgress(binaryPath, func(n, total int64) {
		PrintProgress(n, total, "hashing")
	})
	ClearProgress()

	if err != nil {
		printFail("Cannot read binary file: %s", binaryPath)
		allPassed = false
		fmt.Printf("  → %s\n", err)
	} else {
		if sha256hex == p.Artifact.SHA256 {
			printOK("SHA-256 matches")
			fmt.Printf("       %s\n", colDim(sha256hex))
		} else {
			printFail("SHA-256 MISMATCH — the binary has been modified since signing!")
			fmt.Printf("       Computed : %s\n", sha256hex)
			fmt.Printf("       Expected : %s\n", p.Artifact.SHA256)
			fmt.Println()
			fmt.Println("  Possible causes:")
			fmt.Println("  • Someone tampered with the binary after it was signed")
			fmt.Println("  • You are verifying the wrong file")
			fmt.Println("  • The binary was re-packaged (e.g. installer wrapper added)")
			allPassed = false
		}

		if sha512hex == p.Artifact.SHA512 {
			printOK("SHA-512 matches (%s…)", sha512hex[:24])
		} else {
			printFail("SHA-512 MISMATCH — secondary integrity check also failed")
			allPassed = false
		}
	}
	fmt.Println()

	// ── Step 2: Signature ─────────────────────────────────────────────────────

	printSection("STEP 2 — SIGNATURE  (Ed25519)")

	pubkeyBytes, err := base64.RawURLEncoding.DecodeString(p.Identity.PubKeyEd25519)
	if err != nil {
		printFail("Public key in provenance.json is malformed — the manifest may have been tampered with.")
		return fmt.Errorf("decode pubkey: %w", err)
	}
	pubkey := ed25519.PublicKey(pubkeyBytes)

	// Fingerprint consistency: the fingerprint field must match the actual pubkey.
	computedFP := core.Fingerprint(pubkey)
	if computedFP != p.Identity.PubKeyFingerprint {
		printFail("Fingerprint in provenance.json does not match the embedded public key!")
		fmt.Println("  → The manifest has been tampered with — the pubkey or fingerprint field was modified.")
		allPassed = false
	}

	payloadBytes := core.SigningPayload(p.Artifact.SHA256, p.Artifact.SHA512, p.Signature.Timestamp)
	sigBytes, err := base64.RawURLEncoding.DecodeString(p.Signature.Value)
	if err != nil {
		printFail("Signature value in provenance.json is not valid base64.")
		allPassed = false
	} else if core.Verify(payloadBytes, sigBytes, pubkey) {
		printOK("Ed25519 signature is valid")
		fmt.Printf("       Algorithm : %s\n", p.Signature.Algorithm)
		fmt.Printf("       Signed at : %s\n", p.Signature.Timestamp)
	} else {
		printFail("Ed25519 signature is INVALID!")
		fmt.Println()
		fmt.Println("  This means one of the following:")
		fmt.Println("  • provenance.json was modified after signing (the SHA-256, SHA-512,")
		fmt.Println("    or timestamp fields were changed)")
		fmt.Println("  • provenance.json belongs to a different binary")
		fmt.Println("  • The signature field was tampered with")
		allPassed = false
	}
	fmt.Println()

	// ── Step 3: Social proofs ─────────────────────────────────────────────────

	printSection("STEP 3 — SOCIAL PROOFS")

	if len(p.Identity.SocialProofs) == 0 {
		printWarn("No social proofs declared — cannot verify developer identity.")
		fmt.Println("  The developer did not link any public profile to this key.")
	}

	for _, sp := range p.Identity.SocialProofs {
		label := fmt.Sprintf("%-10s  %s", sp.Platform, sp.Handle)
		if !*online {
			printWarn("%s  %s", label,
				colDim("(not checked — pass --online to verify)"))
		} else {
			if verifyProofURL(sp.ProofURL, p.Identity.PubKeyFingerprint) {
				printOK("%s", label)
				fmt.Printf("       Fingerprint found at: %s\n", sp.ProofURL)
			} else {
				printFail("%s  — fingerprint NOT found at proof URL", label)
				fmt.Printf("       URL: %s\n", sp.ProofURL)
				fmt.Println("       The developer should update their proof to include their fingerprint.")
				allPassed = false
			}
		}
	}
	fmt.Println()

	// ── Step 4: Attestations ──────────────────────────────────────────────────

	printSection(fmt.Sprintf("STEP 4 — PEER ATTESTATIONS  (threshold: %d)", p.TrustChain.Threshold))

	validAttestations := 0

	if len(p.Attestations) == 0 {
		printWarn("No attestations present — artifact has not been peer-reviewed yet.")
		fmt.Println("  Trust level will remain SELF-SIGNED until peers attest.")
	}

	for i, att := range p.Attestations {
		attPubBytes, err := base64.RawURLEncoding.DecodeString(att.AttesterPubKey)
		if err != nil {
			printFail("[%d] Cannot decode attester public key — attestation is malformed.", i+1)
			continue
		}
		attPubkey := ed25519.PublicKey(attPubBytes)

		if core.Fingerprint(attPubkey) != att.AttesterFingerprint {
			printFail("[%d] Attester fingerprint mismatch — this attestation was tampered with.", i+1)
			continue
		}

		attPayload := core.AttestationPayload(p.Artifact.SHA256, att.Statement, att.Timestamp)
		attSig, err := base64.RawURLEncoding.DecodeString(att.Signature)
		if err != nil {
			printFail("[%d] Attestation signature is not valid base64.", i+1)
			continue
		}

		if !core.Verify(attPayload, attSig, attPubkey) {
			printFail("[%d] Attestation signature INVALID — fp: %s…", i+1, att.AttesterFingerprint[:16])
			fmt.Println("       This attestation has been tampered with and must be ignored.")
			continue
		}

		validAttestations++
		printOK("[%d] Valid attestation — fp: %s…", i+1, att.AttesterFingerprint[:16])
		fmt.Printf("       Scope    : %s\n", att.Scope)
		fmt.Printf("       Statement: %q\n", att.Statement)
		fmt.Printf("       Signed   : %s\n", att.Timestamp)
	}
	fmt.Println()

	// ── Step 5: Registry check (optional) ────────────────────────────────────

	if *registryURL != "" {
		printSection("STEP 5 — REGISTRY CHECK  (online)")

		remoteP, regErr := fetchFromRegistry(*registryURL, *localDir, p)
		switch {
		case regErr != nil && errors.Is(regErr, os.ErrNotExist):
			printWarn("Not found in registry — artifact may not have been published yet.")
			fmt.Println("  Run: open-trust publish --registry " + *registryURL)
		case regErr != nil:
			printWarn("Registry temporarily unreachable.")
			fmt.Printf("  Error: %v\n", regErr)
			fmt.Println("  This is not a security failure — try again with an internet connection.")
		case remoteP.Artifact.SHA256 != p.Artifact.SHA256:
			printFail("SHA-256 MISMATCH between local provenance and registry!")
			fmt.Printf("  Local    : %s\n", p.Artifact.SHA256)
			fmt.Printf("  Registry : %s\n", remoteP.Artifact.SHA256)
			fmt.Println()
			fmt.Println("  This is a serious warning. Possible causes:")
			fmt.Println("  • The local provenance.json was replaced with a fake one")
			fmt.Println("  • The registry was tampered with (very unlikely with Git)")
			fmt.Println("  • A version mismatch (different release published)")
			allPassed = false
		default:
			printOK("SHA-256 matches registry — provenance is authentic")
			fmt.Printf("       Registry : %s\n", *registryURL)
			if remoteP.TrustChain.RegistryCID != "" {
				fmt.Printf("       Commit   : %s\n", remoteP.TrustChain.RegistryCID)
			}
		}
		fmt.Println()
	}

	// ── Trust level ───────────────────────────────────────────────────────────

	trustLevel := core.ComputeTrustLevel(p, validAttestations)
	printDivider()

	switch trustLevel {
	case core.TrustTrusted:
		fmt.Printf("  TRUST LEVEL: %s\n",
			colOK(colBold(fmt.Sprintf("TRUSTED  (%d/%d attestations)", validAttestations, p.TrustChain.Threshold))))
	case core.TrustPeer:
		fmt.Printf("  TRUST LEVEL: %s\n",
			colWarn(fmt.Sprintf("PEER-ATTESTED  (%d/%d — needs %d more)",
				validAttestations, p.TrustChain.Threshold, p.TrustChain.Threshold-validAttestations)))
	case core.TrustSelf:
		fmt.Printf("  TRUST LEVEL: %s\n",
			colWarn("SELF-SIGNED  (social proofs present, no peer attestations yet)"))
	default:
		fmt.Printf("  TRUST LEVEL: %s\n",
			colFail("UNKNOWN  (no social proofs and no attestations)"))
	}

	printDivider()
	fmt.Println()

	if !allPassed {
		printFail("One or more verification checks failed — do not trust this binary.")
		fmt.Println()
		return fmt.Errorf("verification failed")
	}

	return nil
}

// fetchFromRegistry retrieves the registry provenance for p using git or HTTP.
func fetchFromRegistry(registryURL, localDir string, p *core.Provenance) (*core.Provenance, error) {
	fp  := p.Identity.PubKeyFingerprint
	sha := p.Artifact.SHA256

	if core.IsGitURL(registryURL) {
		if err := core.CheckGitAvailable(); err != nil {
			return nil, err
		}
		if err := core.EnsureRegistry(registryURL, localDir); err != nil {
			return nil, fmt.Errorf("sync registry: %w", err)
		}
		return core.LookupEntry(localDir, fp, sha)
	}

	return core.FetchEntryHTTP(registryURL, fp, sha)
}

// verifyProofURL fetches proofURL and checks whether it contains fingerprint.
func verifyProofURL(proofURL, fingerprint string) bool {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(proofURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return false
	}
	return strings.Contains(string(body), fingerprint)
}
