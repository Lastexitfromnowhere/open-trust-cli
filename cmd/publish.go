package cmd

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"open-trust/core"
)

// envToken is the environment variable that can carry a GitHub PAT for
// HTTPS authentication without interactive prompts (useful for CI/CD).
const envToken = "OPEN_TRUST_GITHUB_TOKEN"

func RunPublish(args []string) error {
	fs := flag.NewFlagSet("publish", flag.ContinueOnError)

	provPath    := fs.String("provenance", "provenance.json", "path to the local provenance.json to publish")
	registryURL := fs.String("registry", core.DefaultRegistryURL,
		"Git URL of the trust registry\n"+
			"  SSH  : git@github.com:Lastexitfromnowhere/open-trust-registry.git\n"+
			"  HTTPS: https://github.com/Lastexitfromnowhere/open-trust-registry.git")
	localDir    := fs.String("local-dir", "",
		"persistent local clone of the registry (default: use a temp directory)\n"+
			"  Set this to reuse a clone across multiple publish calls")
	authorName  := fs.String("author-name", "", "git commit author name  (falls back to global git config)")
	authorEmail := fs.String("author-email", "", "git commit author email (falls back to global git config)")
	noPush      := fs.Bool("no-push", false,
		"stop after commit — do not push automatically\n"+
			"  The clone directory is preserved so you can push manually")

	fs.Usage = func() {
		PrintCommandBanner("publish", "push a provenance.json to the trust registry")
		fmt.Printf(`Clones the registry into a temporary directory, writes your provenance.json
in two index layouts, commits, and pushes.

Default registry: %s

Registry layout written:
  keys/<fingerprint>/identity.json                 ← fingerprint index (for verify)
  keys/<fingerprint>/signatures/<sha256>.json      ← fingerprint index
  signatures/<app-name>/<version>/provenance.json  ← human-readable (for browsing)

Authentication:
  SSH  → your existing SSH agent / ~/.ssh/id_ed25519
  HTTPS→ set %s=<your-github-PAT>

Push conflicts are resolved automatically with git rebase + retry.

Flags:
`, core.DefaultRegistryURL, envToken)
		fs.PrintDefaults()
		fmt.Println(`
Example (SSH):
  open-trust publish --author-name "Alice" --author-email "alice@example.com"

Example (HTTPS with token):
  OPEN_TRUST_GITHUB_TOKEN=ghp_xxx open-trust publish

Example (no auto-push):
  open-trust publish --no-push`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	PrintCommandBanner("publish", "push provenance to registry")

	// ── Preflight ─────────────────────────────────────────────────────────────

	if err := core.CheckGitAvailable(); err != nil {
		printFail("git not found in PATH.")
		return fmt.Errorf(
			"%w\n\n"+
				"  Install Git and make sure it is in your PATH:\n"+
				"  → https://git-scm.com/downloads", err)
	}

	// ── Load provenance ───────────────────────────────────────────────────────

	p, err := core.LoadProvenance(*provPath)
	if err != nil {
		printFail("Cannot read provenance.json: %s", *provPath)
		return fmt.Errorf("load provenance: %w", err)
	}

	printInfo("Publishing : %s v%s", p.Artifact.Name, p.Artifact.Version)
	fmt.Printf("  Signer      : %s\n", p.Identity.DisplayName)
	fmt.Printf("  Fingerprint : %s\n", colBold(p.Identity.PubKeyFingerprint[:16]+"…"))
	fmt.Printf("  SHA-256     : %s\n", p.Artifact.SHA256[:32]+"…")
	fmt.Println()

	// ── Resolve registry URL (inject token if available) ──────────────────────

	effectiveURL := *registryURL
	if token := os.Getenv(envToken); token != "" {
		effectiveURL = core.InjectGitHubToken(effectiveURL, token)
		printInfo("GitHub token detected — using HTTPS authentication.")
	}

	// ── Resolve clone directory ───────────────────────────────────────────────

	useTempDir := *localDir == ""
	cloneDir   := *localDir

	if useTempDir {
		tmpDir, err := os.MkdirTemp("", "open-trust-publish-*")
		if err != nil {
			return fmt.Errorf("create temp directory: %w", err)
		}
		cloneDir = tmpDir
		printInfo("Using temp directory: %s", colDim(cloneDir))
	}

	// keepDir tracks whether to preserve the temp dir on exit.
	// Starts false (clean up on success); set to true on failures so the user
	// can inspect or push manually.
	keepDir := false

	defer func() {
		if useTempDir {
			if keepDir {
				printWarn("Temp registry clone preserved (push failed):")
				fmt.Printf("  Path: %s\n", cloneDir)
				fmt.Printf("  To push manually: cd \"%s\" && git push\n", cloneDir)
			} else {
				os.RemoveAll(cloneDir)
			}
		}
	}()

	// ── Clone / pull registry ─────────────────────────────────────────────────

	s := spin("Cloning registry (this may take a few seconds)…")
	if err := core.EnsureRegistry(effectiveURL, cloneDir); err != nil {
		s.fail("Failed to clone/sync registry.")
		keepDir = true
		return fmt.Errorf(
			"sync registry: %w\n\n"+
				"  Possible causes:\n"+
				"  • SSH key not configured for GitHub — try HTTPS with a token:\n"+
				"    export %s=ghp_your_token\n"+
				"  • Repository does not exist or you lack write access\n"+
				"  • Network unreachable", err, envToken)
	}
	s.ok("Registry cloned: " + colDim(*registryURL))

	// ── Write entries ─────────────────────────────────────────────────────────

	s = spin("Writing registry entries…")
	written, err := core.WriteEntry(cloneDir, p)
	if err != nil {
		s.fail("Failed to write registry entries.")
		keepDir = true
		return fmt.Errorf("write entry: %w", err)
	}
	s.ok(fmt.Sprintf("Entries written (%d files)", len(written)))

	for _, f := range written {
		fmt.Printf("  %s %s\n", colDim("+"), filepath.ToSlash(f))
	}
	fmt.Println()

	// ── Stage ─────────────────────────────────────────────────────────────────

	if err := core.GitStage(cloneDir, written); err != nil {
		printFail("git add failed.")
		keepDir = true
		return fmt.Errorf("git add: %w", err)
	}

	// ── Commit ────────────────────────────────────────────────────────────────

	fp        := p.Identity.PubKeyFingerprint
	commitMsg := buildCommitMessage(p, fp)

	s = spin("Committing…")
	if err := core.GitCommit(cloneDir, commitMsg, *authorName, *authorEmail); err != nil {
		if strings.Contains(err.Error(), "nothing to commit") {
			s.ok("Nothing changed — this exact provenance is already in the registry.")
			printRegistryURLs(*registryURL, cloneDir, fp, p)
			return nil
		}
		s.fail("Commit failed.")
		keepDir = true
		return fmt.Errorf(
			"git commit: %w\n\n"+
				"  If git says 'Please tell me who you are', pass:\n"+
				"    --author-name \"Your Name\" --author-email \"you@example.com\"\n"+
				"  or configure global git identity:\n"+
				"    git config --global user.name \"Your Name\"\n"+
				"    git config --global user.email \"you@example.com\"", err)
	}

	commitSHA, _ := core.HeadSHA(cloneDir)
	s.ok("Committed: " + colDim(commitSHA))

	// ── Push (or --no-push) ───────────────────────────────────────────────────

	if *noPush {
		keepDir = true // preserve clone so user can push manually
		fmt.Println()
		printWarn("--no-push: skipping automatic push.")
		fmt.Printf("  Clone preserved at: %s\n", cloneDir)
		fmt.Printf("  Push when ready  : cd \"%s\" && git push\n", cloneDir)
		fmt.Println()
		return nil
	}

	s = spin("Pushing to remote registry…")
	if err := core.GitPush(cloneDir); err != nil {
		s.fail("Push failed — see instructions below.")
		keepDir = true // preserve clone for manual push
		return fmt.Errorf(
			"git push: %w\n\n"+
				"  Your commit is preserved locally. To push manually:\n"+
				"    cd \"%s\"\n"+
				"    git push\n\n"+
				"  Common fixes:\n"+
				"  • SSH: add your public key to GitHub → Settings → SSH keys\n"+
				"  • HTTPS: set OPEN_TRUST_GITHUB_TOKEN=ghp_your_token",
			err, cloneDir)
	}

	if finalSHA, err := core.HeadSHA(cloneDir); err == nil {
		commitSHA = finalSHA
	}
	s.ok("Pushed to " + *registryURL)

	// ── Update local provenance.json with registry anchor ─────────────────────

	p.TrustChain.RegistryCID = commitSHA
	if saveErr := p.Save(*provPath); saveErr != nil {
		printWarn("Could not update local provenance.json with registry_cid: %v", saveErr)
	} else {
		printInfo("Local %s anchored to commit %s", *provPath, colBold(commitSHA[:12]+"…"))
	}

	// ── Summary ───────────────────────────────────────────────────────────────

	fmt.Println()
	printDivider()
	printOK("Published successfully!")
	fmt.Printf("  Commit      : %s\n", colBold(commitSHA))
	printRegistryURLs(*registryURL, cloneDir, fp, p)
	printDivider()
	fmt.Println()

	return nil
}

// buildCommitMessage returns a structured, auditable git commit message.
func buildCommitMessage(p *core.Provenance, fingerprint string) string {
	return fmt.Sprintf(
		"publish: %s v%s by %s…\n\nArtifact  : %s\nSHA-256   : %s\nSigned by : %s",
		p.Artifact.Name,
		p.Artifact.Version,
		fingerprint[:16],
		p.Artifact.Name+" v"+p.Artifact.Version,
		p.Artifact.SHA256,
		fingerprint,
	)
}

// printRegistryURLs shows all paths and GitHub browse links after a successful publish.
func printRegistryURLs(registryURL, cloneDir, fingerprint string, p *core.Provenance) {
	sha256 := p.Artifact.SHA256

	appPath := core.RegistryAppPath(cloneDir, p.Artifact.Name, p.Artifact.Version)
	sigPath := core.RegistrySignaturePath(cloneDir, fingerprint, sha256)

	fmt.Println()
	fmt.Println("  Registry entries written:")
	fmt.Printf("    Browse by app  → %s\n", filepath.ToSlash(appPath))
	fmt.Printf("    Fingerprint idx→ %s\n", filepath.ToSlash(sigPath))

	browse := toHTTPS(registryURL)
	if browse != "" {
		name := sanitizeForURL(p.Artifact.Name)
		ver  := sanitizeForURL(p.Artifact.Version)
		fmt.Println()
		fmt.Println("  GitHub:")
		fmt.Printf("    By app name  → %s/tree/main/signatures/%s/%s/\n", browse, name, ver)
		fmt.Printf("    By key       → %s/tree/main/keys/%s/\n", browse, fingerprint[:16]+"…")
	}
	fmt.Println()
	fmt.Println("  Verify offline:")
	fmt.Println("    open-trust verify --provenance provenance.json <binary>")
	fmt.Println()
	fmt.Println("  Verify against registry:")
	fmt.Printf("    open-trust verify --registry %s --provenance provenance.json <binary>\n", registryURL)
}

func sanitizeForURL(s string) string {
	// Same logic as core.sanitizeName but accessible here
	var out []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '.':
			out = append(out, c)
		case c >= 'A' && c <= 'Z':
			out = append(out, c+32)
		case c == ' ', c == '/', c == '\\', c == '_':
			out = append(out, '-')
		}
	}
	return string(out)
}

func toHTTPS(gitURL string) string {
	if strings.HasPrefix(gitURL, "git@") {
		s := strings.TrimPrefix(gitURL, "git@")
		s = strings.Replace(s, ":", "/", 1)
		s = strings.TrimSuffix(s, ".git")
		return "https://" + s
	}
	if strings.HasPrefix(gitURL, "https://") {
		return strings.TrimSuffix(gitURL, ".git")
	}
	return ""
}

func defaultRegistryDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".open-trust", "registry")
	}
	return filepath.Join(home, ".open-trust", "registry")
}
