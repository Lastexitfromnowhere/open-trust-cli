package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

const envPassphrase = "OPEN_TRUST_PASSPHRASE"

// readPassphrase reads a passphrase in this priority order:
//  1. OPEN_TRUST_PASSPHRASE environment variable (useful for CI/CD)
//  2. Interactive terminal prompt with echo disabled
//  3. Plain stdin line (fallback when stdin is not a TTY, e.g. tests)
//
// Note: passing secrets via environment variables is acceptable for
// automated pipelines but should not be used on shared machines.
func readPassphrase(prompt string) ([]byte, error) {
	// Priority 1: environment variable.
	if v := os.Getenv(envPassphrase); v != "" {
		return []byte(v), nil
	}

	fmt.Print(prompt)

	// Priority 2: interactive TTY — password is not echoed.
	if term.IsTerminal(int(os.Stdin.Fd())) {
		pass, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		return pass, err
	}

	// Priority 3: piped stdin — read one line (testing / scripted use).
	// In this mode the passphrase is visible in the shell; acceptable for tests.
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		fmt.Println()
		return []byte(strings.TrimRight(scanner.Text(), "\r\n")), nil
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("no passphrase provided")
}
