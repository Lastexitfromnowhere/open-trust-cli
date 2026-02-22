package cmd

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"open-trust/core"
)

func RunKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	outDir := fs.String("out", defaultKeyDir(), "directory where the keystore will be saved")
	name   := fs.String("name", "identity", "keystore filename prefix (saved as <name>.key.json)")

	fs.Usage = func() {
		PrintCommandBanner("keygen", "generate an Ed25519 keypair")
		fmt.Println(`Generates a new Ed25519 keypair and saves it encrypted on disk.
The private key is protected by Argon2id + AES-256-GCM — only your
passphrase can decrypt it.  Back up the .key.json file somewhere safe.

Flags:`)
		fs.PrintDefaults()
		fmt.Println(`
After keygen, publish your fingerprint so peers can verify your identity:
  → Paste it in a public GitHub Gist
  → Post it on Mastodon / your website
  → Then run: open-trust sign --help`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	PrintCommandBanner("keygen", "generate an Ed25519 keypair")

	// ── Collect and confirm passphrase ────────────────────────────────────────

	pass1, err := readPassphrase("Passphrase (min 8 chars): ")
	if err != nil {
		return fmt.Errorf("read passphrase: %w", err)
	}
	if len(pass1) < 8 {
		printFail("Passphrase too short — minimum 8 characters required.")
		return fmt.Errorf("passphrase must be at least 8 characters")
	}

	pass2, err := readPassphrase("Confirm passphrase      : ")
	if err != nil {
		return fmt.Errorf("read passphrase: %w", err)
	}
	if string(pass1) != string(pass2) {
		printFail("Passphrases do not match — please try again.")
		return fmt.Errorf("passphrases do not match")
	}

	// ── Generate keypair ──────────────────────────────────────────────────────

	fmt.Println()
	s := spin("Generating Ed25519 keypair…")
	pubkey, privkey, err := core.GenerateKeypair()
	if err != nil {
		s.fail("Keypair generation failed")
		return fmt.Errorf("generate keypair: %w", err)
	}
	s.ok("Ed25519 keypair generated")

	// ── Encrypt and save ──────────────────────────────────────────────────────

	if err := os.MkdirAll(*outDir, 0700); err != nil {
		return fmt.Errorf("create key directory: %w", err)
	}

	keystorePath := filepath.Join(*outDir, *name+".key.json")
	if _, err := os.Stat(keystorePath); err == nil {
		printFail("Keystore already exists: %s", keystorePath)
		return fmt.Errorf("keystore already exists — use a different --name or --out to avoid overwriting")
	}

	s = spin("Encrypting key with Argon2id + AES-256-GCM (this takes a few seconds)…")
	if err := core.SaveKey(keystorePath, privkey, pass1); err != nil {
		s.fail("Encryption failed")
		return fmt.Errorf("save keystore: %w", err)
	}
	s.ok("Key encrypted and saved")

	// ── Report ────────────────────────────────────────────────────────────────

	fingerprint := core.Fingerprint(pubkey)
	pubkeyB64   := base64.RawURLEncoding.EncodeToString(pubkey)

	fmt.Println()
	printDivider()
	fmt.Printf("  Keystore    : %s\n", keystorePath)
	fmt.Printf("  Public key  : %s\n", colDim(pubkeyB64))
	fmt.Printf("  Fingerprint : %s\n", colBold(fingerprint))
	printDivider()
	fmt.Println()
	printWarn("Back up your keystore file — it cannot be recovered if lost.")
	fmt.Println()
	printInfo("Next: paste your fingerprint in a public GitHub Gist, then:")
	fmt.Printf("  %s open-trust sign --key %s --name myapp ./mybinary\n",
		colDim("$"), keystorePath)
	fmt.Println()

	return nil
}

// defaultKeyDir returns ~/.open-trust as the default key storage directory.
func defaultKeyDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".open-trust"
	}
	return filepath.Join(home, ".open-trust")
}
