// Package cmd implements the open-trust CLI.
// Each sub-command lives in its own file; this file routes os.Args to the
// correct handler. No third-party CLI framework is used to keep the
// dependency surface minimal and auditable.
package cmd

import (
	"fmt"
	"os"
)

const version = "0.1.0"

const usage = `open-trust ` + version + ` — Decentralised code signing

Usage:
  open-trust <command> [flags]

Commands:
  keygen    Generate an Ed25519 keypair (stored encrypted on disk)
  sign      Hash a binary and produce a signed provenance.json
  verify    Verify a binary against its provenance.json
  attest    Issue a peer attestation and append it to a provenance.json
  publish   Publish provenance.json to a Git-based trust registry

Run 'open-trust <command> --help' for command-specific flags.
`

// Execute dispatches to the correct sub-command based on os.Args.
func Execute() error {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		return nil
	}

	switch os.Args[1] {
	case "keygen":
		return RunKeygen(os.Args[2:])
	case "sign":
		return RunSign(os.Args[2:])
	case "verify":
		return RunVerify(os.Args[2:])
	case "attest":
		return RunAttest(os.Args[2:])
	case "publish":
		return RunPublish(os.Args[2:])
	case "--help", "-h", "help":
		fmt.Print(usage)
		return nil
	default:
		return fmt.Errorf("unknown command %q — run 'open-trust --help'", os.Args[1])
	}
}
