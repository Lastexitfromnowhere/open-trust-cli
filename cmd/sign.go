package cmd

import (
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"path/filepath"
	"strings"

	"open-trust/core"
)

func RunSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)

	keyPath         := fs.String("key", filepath.Join(defaultKeyDir(), "identity.key.json"), "path to your keystore file")
	artifactName    := fs.String("name", "", "artifact name (default: binary filename)")
	artifactVersion := fs.String("version", "", "artifact version, e.g. 1.2.0")
	displayName     := fs.String("display-name", "", "your name as shown in the manifest")
	outPath         := fs.String("out", "provenance.json", "output provenance.json path")
	threshold       := fs.Int("threshold", 2, "number of peer attestations required for TRUSTED status")
	socialRaw       := fs.String("social", "", `comma-separated social proofs: "platform:handle:proof_url,..."`)

	fs.Usage = func() {
		PrintCommandBanner("sign", "sign a binary and produce a provenance.json")
		fmt.Println(`Computes SHA-256 + SHA-512 of your binary, signs them with your Ed25519
private key, and writes a signed provenance.json manifest.  Share the
manifest alongside your binary so anyone can verify it.

Flags:`)
		fs.PrintDefaults()
		fmt.Println(`
Example:
  open-trust sign \
    --name my-app --version 1.2.0 \
    --display-name "Alice Dupont" \
    --social "github:alice:https://gist.github.com/alice/abc" \
    ./my-app-linux-amd64`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		fs.Usage()
		return fmt.Errorf("binary path is required as a positional argument")
	}

	binaryPath := fs.Arg(0)
	if *artifactName == "" {
		*artifactName = filepath.Base(binaryPath)
	}
	if *displayName == "" {
		*displayName = "Unknown"
	}

	PrintCommandBanner("sign", "hash + sign a binary")

	// ── Load private key ──────────────────────────────────────────────────────

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
				"  Possible causes:\n"+
				"  • Wrong passphrase\n"+
				"  • Keystore file has been modified or corrupted\n"+
				"  • Wrong --key path (using the wrong keystore)", err)
	}
	s.ok("Key decrypted successfully")

	pubkey := privkey.Public().(ed25519.PublicKey)

	// ── Hash the binary ───────────────────────────────────────────────────────

	fmt.Println()
	printInfo("Hashing: %s", binaryPath)

	sha256hex, sha512hex, err := core.HashFileProgress(binaryPath, func(n, total int64) {
		PrintProgress(n, total, "computing SHA-256 + SHA-512")
	})
	ClearProgress()

	if err != nil {
		printFail("Could not read binary: %s", binaryPath)
		return fmt.Errorf(
			"hash binary: %w\n\n"+
				"  Possible causes:\n"+
				"  • File does not exist at the given path\n"+
				"  • Insufficient read permissions", err)
	}

	printOK("SHA-256 : %s", sha256hex)
	printOK("SHA-512 : %s", sha512hex[:32]+"…")

	// ── Build signing payload and sign ────────────────────────────────────────

	timestamp := core.NowUTC()
	payload   := core.SigningPayload(sha256hex, sha512hex, timestamp)
	sigBytes  := core.Sign(payload, privkey)
	fingerprint := core.Fingerprint(pubkey)

	// ── Parse social proofs ───────────────────────────────────────────────────

	var socialProofs []core.SocialProof
	if *socialRaw != "" {
		for _, entry := range strings.Split(*socialRaw, ",") {
			// SplitN limit=3 preserves colons inside URLs.
			parts := strings.SplitN(strings.TrimSpace(entry), ":", 3)
			if len(parts) != 3 {
				return fmt.Errorf(
					"social proof %q has the wrong format\n"+
						"  Expected: platform:handle:proof_url\n"+
						"  Example : github:alice:https://gist.github.com/alice/abc", entry)
			}
			socialProofs = append(socialProofs, core.SocialProof{
				Platform: parts[0],
				Handle:   parts[1],
				ProofURL: parts[2],
			})
		}
	}

	// ── Assemble provenance manifest ──────────────────────────────────────────

	p := &core.Provenance{
		SchemaVersion: core.SchemaVersion,
		Artifact: core.Artifact{
			Name:           *artifactName,
			Version:        *artifactVersion,
			SHA256:         sha256hex,
			SHA512:         sha512hex,
			BuildTimestamp: timestamp,
			BuildEnv:       core.CurrentBuildEnv(),
		},
		Identity: core.Identity{
			DisplayName:       *displayName,
			PubKeyEd25519:     base64.RawURLEncoding.EncodeToString(pubkey),
			PubKeyFingerprint: fingerprint,
			SocialProofs:      socialProofs,
		},
		Signature: core.Signature{
			Algorithm:    "Ed25519",
			SignedPayload: base64.RawURLEncoding.EncodeToString(payload),
			Value:        base64.RawURLEncoding.EncodeToString(sigBytes),
			Timestamp:    timestamp,
		},
		Attestations: []core.Attestation{},
		TrustChain: core.TrustChain{
			Threshold: *threshold,
		},
	}

	if err := p.Save(*outPath); err != nil {
		return fmt.Errorf("write provenance.json: %w", err)
	}

	// ── Summary ───────────────────────────────────────────────────────────────

	fmt.Println()
	printDivider()
	printOK("provenance.json written: %s", *outPath)
	fmt.Printf("  Artifact    : %s %s\n", *artifactName, *artifactVersion)
	fmt.Printf("  Signer      : %s\n", *displayName)
	fmt.Printf("  Fingerprint : %s\n", colBold(fingerprint))
	fmt.Printf("  Timestamp   : %s\n", timestamp)
	fmt.Printf("  Threshold   : %s peer attestations for TRUSTED\n", fmt.Sprintf("%d", *threshold))
	printDivider()
	fmt.Println()
	printInfo("Next steps:")
	fmt.Println("  1. Share provenance.json alongside your binary.")
	fmt.Printf("  2. Ask %d peer(s) to run: open-trust attest ./provenance.json\n", *threshold)
	fmt.Println("  3. Publish to a registry: open-trust publish --registry git@…")
	fmt.Println()

	return nil
}
