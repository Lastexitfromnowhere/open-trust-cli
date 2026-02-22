package cmd

import (
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"path/filepath"

	"open-trust/core"
)

var validScopes = map[string]bool{
	"source":   true,
	"binary":   true,
	"identity": true,
}

func RunAttest(args []string) error {
	fs := flag.NewFlagSet("attest", flag.ContinueOnError)

	keyPath   := fs.String("key", filepath.Join(defaultKeyDir(), "identity.key.json"), "path to your keystore file")
	statement := fs.String("statement", "", `what you are attesting (required)\n  e.g. "Built from source at commit abc123"`)
	scope     := fs.String("scope", "binary", `what you verified: "source", "binary", or "identity"`)

	fs.Usage = func() {
		PrintCommandBanner("attest", "issue a peer attestation")
		fmt.Println(`Signs and appends an attestation to a provenance.json file.
You are asserting that you have independently verified the artifact.

  "source"   → you reviewed and built from source
  "binary"   → you downloaded and reproduced the binary hash
  "identity" → you verified the developer's real-world identity

Only attest things you have actually checked.

Flags:`)
		fs.PrintDefaults()
		fmt.Println(`
Example:
  open-trust attest \
    --key ~/.open-trust/bob.key.json \
    --statement "Built from source at commit d4a1b2c, hash matches" \
    --scope source \
    ./provenance.json`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		fs.Usage()
		return fmt.Errorf("provenance.json path is required as a positional argument")
	}
	if *statement == "" {
		printFail("--statement is required: describe what you personally verified.")
		return fmt.Errorf("--statement is required")
	}
	if !validScopes[*scope] {
		printFail("Unknown scope %q — must be: source, binary, or identity", *scope)
		return fmt.Errorf("invalid --scope: %q", *scope)
	}

	provPath := fs.Arg(0)

	PrintCommandBanner("attest", "sign a peer attestation")

	// ── Load provenance ───────────────────────────────────────────────────────

	p, err := core.LoadProvenance(provPath)
	if err != nil {
		printFail("Cannot open provenance.json: %s", provPath)
		return fmt.Errorf(
			"load provenance: %w\n\n"+
				"  Make sure the path is correct and the file is valid JSON.", err)
	}

	printInfo("Attesting: %s v%s", p.Artifact.Name, p.Artifact.Version)
	fmt.Printf("  Signer      : %s\n", p.Identity.DisplayName)
	fmt.Printf("  SHA-256     : %s\n", p.Artifact.SHA256[:32]+"…")
	fmt.Println()

	// ── Load attester's private key ───────────────────────────────────────────

	printInfo("Keystore: %s", *keyPath)
	pass, err := readPassphrase("Passphrase: ")
	if err != nil {
		return fmt.Errorf("read passphrase: %w", err)
	}

	s := spin("Decrypting key (Argon2id)…")
	privkey, err := core.LoadKey(*keyPath, pass)
	if err != nil {
		s.fail("Wrong passphrase or corrupted keystore.")
		return fmt.Errorf(
			"could not decrypt keystore: %w\n\n"+
				"  • Check your passphrase\n"+
				"  • Verify the --key path points to the right file", err)
	}
	s.ok("Key decrypted")

	attPubkey      := privkey.Public().(ed25519.PublicKey)
	attFingerprint := core.Fingerprint(attPubkey)

	// ── Guard: prevent self-attestation ───────────────────────────────────────

	if attFingerprint == p.Identity.PubKeyFingerprint {
		printFail("Self-attestation detected — this is not allowed.")
		return fmt.Errorf(
			"you cannot attest your own artifact\n\n" +
				"  An attestation from the same key that signed the artifact provides\n" +
				"  no additional trust signal.  Ask a different developer to attest.")
	}

	// ── Guard: prevent duplicate attestation ──────────────────────────────────

	for _, existing := range p.Attestations {
		if existing.AttesterFingerprint == attFingerprint {
			printWarn("This key has already attested this artifact.")
			return fmt.Errorf(
				"duplicate attestation — fingerprint %s… already present\n\n"+
					"  Each key may only attest once per artifact.", attFingerprint[:16])
		}
	}

	// ── Sign attestation ──────────────────────────────────────────────────────

	timestamp := core.NowUTC()
	payload   := core.AttestationPayload(p.Artifact.SHA256, *statement, timestamp)
	sigBytes  := core.Sign(payload, privkey)

	attestation := core.Attestation{
		AttesterPubKey:      base64.RawURLEncoding.EncodeToString(attPubkey),
		AttesterFingerprint: attFingerprint,
		Statement:           *statement,
		Scope:               *scope,
		Signature:           base64.RawURLEncoding.EncodeToString(sigBytes),
		Timestamp:           timestamp,
	}

	p.Attestations = append(p.Attestations, attestation)

	if err := p.Save(provPath); err != nil {
		return fmt.Errorf("save provenance: %w", err)
	}

	// ── Summary ───────────────────────────────────────────────────────────────

	total := len(p.Attestations)
	fmt.Println()
	printDivider()
	printOK("Attestation appended to %s", provPath)
	fmt.Printf("  Attester    : %s\n", colBold(attFingerprint))
	fmt.Printf("  Scope       : %s\n", *scope)
	fmt.Printf("  Statement   : %q\n", *statement)
	fmt.Printf("  Timestamp   : %s\n", timestamp)
	fmt.Printf("  Progress    : %d / %d attestations\n", total, p.TrustChain.Threshold)

	if total >= p.TrustChain.Threshold {
		fmt.Println()
		printOK("Threshold reached — this artifact is now %s", colBold("TRUSTED"))
	} else {
		remaining := p.TrustChain.Threshold - total
		printInfo("Need %d more attestation(s) to reach TRUSTED status.", remaining)
	}
	printDivider()
	fmt.Println()

	return nil
}
