// registry.go manages interactions with a Git-based trust registry.
//
// Registry layout on disk (mirrored from the remote Git repo):
//
//	registry/
//	├── keys/
//	│   └── [pubkey_fingerprint]/
//	│       ├── identity.json                  developer's public identity record
//	│       └── signatures/
//	│           └── [artifact_sha256].json     full provenance.json (fingerprint index)
//	└── signatures/
//	    └── [artifact_name]/
//	        └── [version]/
//	            └── provenance.json            human-readable browsing index
//
// Both paths are written on publish.  The keys/ tree is used for cryptographic
// lookup (by fingerprint + sha256).  The signatures/ tree allows browsing by
// app name on GitHub.
//
// All Git operations shell out to the system `git` binary so that the user's
// existing SSH keys, credential helpers and proxy settings are automatically
// respected.  No extra Go dependency is required.
package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ── Constants ─────────────────────────────────────────────────────────────────

const (
	keysDir       = "keys"
	signaturesDir = "signatures"
	identityFile  = "identity.json"
)

// DefaultRegistryURL is the community trust registry hosted on GitHub.
const DefaultRegistryURL = "https://github.com/Lastexitfromnowhere/open-trust-registry.git"

// ── IdentityRecord ────────────────────────────────────────────────────────────

// IdentityRecord is written to keys/[fingerprint]/identity.json.
// It is the public, non-secret portion of a developer's keystore.
type IdentityRecord struct {
	DisplayName       string        `json:"display_name"`
	PubKeyEd25519     string        `json:"pubkey_ed25519"`
	PubKeyFingerprint string        `json:"pubkey_fingerprint"`
	SocialProofs      []SocialProof `json:"social_proofs"`
	FirstSeen         string        `json:"first_seen"`   // RFC3339, preserved across updates
	LastUpdated       string        `json:"last_updated"` // RFC3339, updated on every publish
}

// ── Path helpers ──────────────────────────────────────────────────────────────

// RegistryKeyDir returns the directory for a given fingerprint.
func RegistryKeyDir(registryRoot, fingerprint string) string {
	return filepath.Join(registryRoot, keysDir, fingerprint)
}

// RegistryIdentityPath returns the path of identity.json for a fingerprint.
func RegistryIdentityPath(registryRoot, fingerprint string) string {
	return filepath.Join(RegistryKeyDir(registryRoot, fingerprint), identityFile)
}

// RegistrySignaturePath returns the fingerprint-indexed path of the provenance file.
// Used for cryptographic lookup: keys/<fp>/signatures/<sha256>.json
func RegistrySignaturePath(registryRoot, fingerprint, artifactSHA256 string) string {
	return filepath.Join(RegistryKeyDir(registryRoot, fingerprint), signaturesDir, artifactSHA256+".json")
}

// RegistryAppPath returns the human-readable path for browsing by app name:
// signatures/<sanitized_name>/<version>/provenance.json
func RegistryAppPath(registryRoot, artifactName, version string) string {
	name := sanitizeName(artifactName)
	ver  := sanitizeName(version)
	if ver == "" {
		ver = "unversioned"
	}
	return filepath.Join(registryRoot, signaturesDir, name, ver, "provenance.json")
}

// sanitizeName converts a string to a filesystem-safe slug:
// lowercase, spaces and slashes replaced by hyphens, most special chars removed.
func sanitizeName(s string) string {
	var out []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '.':
			out = append(out, c)
		case c >= 'A' && c <= 'Z':
			out = append(out, c+32) // to lowercase
		case c == ' ', c == '/', c == '\\', c == '_':
			out = append(out, '-')
		// skip all other characters
		}
	}
	return string(out)
}

// InjectGitHubToken rewrites an HTTPS GitHub URL to embed a personal access
// token for authentication in CI/CD pipelines.  SSH URLs are returned as-is.
// The token is used as: https://x-access-token:<TOKEN>@github.com/...
func InjectGitHubToken(repoURL, token string) string {
	if token == "" {
		return repoURL
	}
	const prefix = "https://github.com/"
	if !strings.HasPrefix(repoURL, prefix) {
		return repoURL // only works for HTTPS GitHub URLs
	}
	return "https://x-access-token:" + token + "@github.com/" + repoURL[len(prefix):]
}

// ── Git low-level helpers ─────────────────────────────────────────────────────

// CheckGitAvailable returns an error if git is not found in PATH.
func CheckGitAvailable() error {
	if _, err := exec.LookPath("git"); err != nil {
		return fmt.Errorf("git executable not found in PATH — please install Git")
	}
	return nil
}

// runGit executes a git command in workdir, capturing stderr for error messages.
// stdout is discarded; use runGitOutput when stdout is needed.
func runGit(workdir string, args ...string) error {
	cmd := exec.Command("git", args...)
	if workdir != "" {
		cmd.Dir = workdir
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return fmt.Errorf("git %s: %w\n  %s", args[0], err, msg)
		}
		return fmt.Errorf("git %s: %w", args[0], err)
	}
	return nil
}

// runGitOutput executes a git command and returns trimmed stdout.
func runGitOutput(workdir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	if workdir != "" {
		cmd.Dir = workdir
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		return "", fmt.Errorf("git %s: %w\n  %s", args[0], err, msg)
	}
	return strings.TrimSpace(stdout.String()), nil
}

// ── Registry lifecycle ────────────────────────────────────────────────────────

// EnsureRegistry clones repoURL to localPath if it does not exist, or pulls
// the latest changes if it does.  Returns the path to the local registry root.
func EnsureRegistry(repoURL, localPath string) error {
	dotGit := filepath.Join(localPath, ".git")
	if _, err := os.Stat(dotGit); os.IsNotExist(err) {
		return cloneRegistry(repoURL, localPath)
	}
	return pullRegistry(localPath)
}

// cloneRegistry performs a shallow clone of repoURL into localPath.
func cloneRegistry(repoURL, localPath string) error {
	fmt.Printf("Cloning registry: %s → %s\n", repoURL, localPath)
	if err := os.MkdirAll(filepath.Dir(localPath), 0755); err != nil {
		return fmt.Errorf("create parent dir: %w", err)
	}
	// --depth=1 keeps the clone fast; full history is not needed for a trust store.
	if err := runGit("", "clone", "--depth=1", repoURL, localPath); err != nil {
		return fmt.Errorf("clone registry: %w", err)
	}
	fmt.Println("Registry cloned successfully.")
	return nil
}

// pullRegistry fetches and rebases the registry.
// Rebase (instead of merge) keeps the history linear and avoids merge commits
// that would clutter the trust store log.
func pullRegistry(localPath string) error {
	fmt.Println("Syncing registry (git pull --rebase)...")

	// Fetch first so we have up-to-date remote refs.
	if err := runGit(localPath, "fetch", "--depth=1", "origin"); err != nil {
		return fmt.Errorf("fetch origin: %w", err)
	}

	// Rebase local changes (our write) on top of the remote.
	if err := runGit(localPath, "rebase", "origin/HEAD"); err != nil {
		// Rebase failure means a real conflict — abort and report clearly.
		_ = runGit(localPath, "rebase", "--abort")
		return fmt.Errorf("rebase failed (manual resolution required): %w", err)
	}

	return nil
}

// ── Writing entries ───────────────────────────────────────────────────────────

// WriteEntry writes identity.json and the provenance file to the local registry.
// It returns the relative paths of the files written (for git add).
func WriteEntry(registryRoot string, p *Provenance) ([]string, error) {
	fp := p.Identity.PubKeyFingerprint
	sigDir := filepath.Join(RegistryKeyDir(registryRoot, fp), signaturesDir)

	if err := os.MkdirAll(sigDir, 0755); err != nil {
		return nil, fmt.Errorf("create registry dirs: %w", err)
	}

	// ── identity.json ─────────────────────────────────────────────────────────
	identityPath := RegistryIdentityPath(registryRoot, fp)
	record, err := loadOrNewIdentity(identityPath, p)
	if err != nil {
		return nil, err
	}

	idData, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal identity: %w", err)
	}
	if err := os.WriteFile(identityPath, idData, 0644); err != nil {
		return nil, fmt.Errorf("write identity.json: %w", err)
	}

	// ── keys/<fp>/signatures/<sha256>.json  (fingerprint index) ─────────────
	sigPath := RegistrySignaturePath(registryRoot, fp, p.Artifact.SHA256)
	if _, err := os.Stat(sigPath); err == nil {
		fmt.Printf("  Note: %s already exists in registry — overwriting.\n", filepath.Base(sigPath))
	}

	provData, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal provenance: %w", err)
	}
	if err := os.WriteFile(sigPath, provData, 0644); err != nil {
		return nil, fmt.Errorf("write signature file: %w", err)
	}

	// ── signatures/<name>/<version>/provenance.json  (human-readable index) ──
	appPath := RegistryAppPath(registryRoot, p.Artifact.Name, p.Artifact.Version)
	if err := os.MkdirAll(filepath.Dir(appPath), 0755); err != nil {
		return nil, fmt.Errorf("create app signature dir: %w", err)
	}
	if err := os.WriteFile(appPath, provData, 0644); err != nil {
		return nil, fmt.Errorf("write app provenance file: %w", err)
	}

	// Return registry-relative paths for git add.
	relIdentity, _ := filepath.Rel(registryRoot, identityPath)
	relSig, _ := filepath.Rel(registryRoot, sigPath)
	relApp, _ := filepath.Rel(registryRoot, appPath)

	return []string{relIdentity, relSig, relApp}, nil
}

// loadOrNewIdentity reads an existing identity.json (to preserve first_seen)
// or creates a fresh one from the provenance.
func loadOrNewIdentity(identityPath string, p *Provenance) (*IdentityRecord, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	firstSeen := now

	// If identity.json already exists, preserve first_seen.
	if data, err := os.ReadFile(identityPath); err == nil {
		var existing IdentityRecord
		if json.Unmarshal(data, &existing) == nil && existing.FirstSeen != "" {
			firstSeen = existing.FirstSeen
		}
	}

	return &IdentityRecord{
		DisplayName:       p.Identity.DisplayName,
		PubKeyEd25519:     p.Identity.PubKeyEd25519,
		PubKeyFingerprint: p.Identity.PubKeyFingerprint,
		SocialProofs:      p.Identity.SocialProofs,
		FirstSeen:         firstSeen,
		LastUpdated:       now,
	}, nil
}

// ── Git staging, commit, push ─────────────────────────────────────────────────

// GitStage stages the given registry-relative file paths.
func GitStage(registryRoot string, relPaths []string) error {
	args := append([]string{"add", "--"}, relPaths...)
	return runGit(registryRoot, args...)
}

// GitCommit creates a commit.  authorName and authorEmail are optional;
// if empty, git falls back to the global config.
func GitCommit(registryRoot, message, authorName, authorEmail string) error {
	args := []string{}

	// Inject per-command identity without touching the global git config.
	if authorName != "" {
		args = append(args, "-c", "user.name="+authorName)
	}
	if authorEmail != "" {
		args = append(args, "-c", "user.email="+authorEmail)
	}

	args = append(args, "commit", "-m", message)
	return runGit(registryRoot, args...)
}

// HeadSHA returns the current HEAD commit SHA of the registry.
func HeadSHA(registryRoot string) (string, error) {
	return runGitOutput(registryRoot, "rev-parse", "HEAD")
}

// GitPush pushes to origin.  On non-fast-forward failure it rebases and
// retries once — handling the common race condition of two simultaneous pushes.
func GitPush(registryRoot string) error {
	err := runGit(registryRoot, "push", "origin", "HEAD")
	if err == nil {
		return nil
	}

	// Check if this looks like a non-fast-forward rejection.
	errStr := err.Error()
	if !strings.Contains(errStr, "non-fast-forward") &&
		!strings.Contains(errStr, "rejected") &&
		!strings.Contains(errStr, "fetch first") {
		return err // unrelated error — surface as-is
	}

	fmt.Println("  Push rejected (remote has new commits). Rebasing and retrying...")
	if pullErr := pullRegistry(registryRoot); pullErr != nil {
		return fmt.Errorf("rebase before retry: %w", pullErr)
	}
	if retryErr := runGit(registryRoot, "push", "origin", "HEAD"); retryErr != nil {
		return fmt.Errorf("push after rebase: %w\n  Hint: check your SSH key or token has write access to the registry", retryErr)
	}

	fmt.Println("  Retry succeeded.")
	return nil
}

// ── Registry lookup (verify) ──────────────────────────────────────────────────

// LookupEntry reads a provenance.json from the local registry cache.
// Returns os.ErrNotExist if the entry has not been published yet.
func LookupEntry(registryRoot, fingerprint, artifactSHA256 string) (*Provenance, error) {
	sigPath := RegistrySignaturePath(registryRoot, fingerprint, artifactSHA256)
	p, err := LoadProvenance(sigPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no registry entry for fingerprint %s / sha256 %s: %w",
				fingerprint[:16]+"…", artifactSHA256[:16]+"…", os.ErrNotExist)
		}
		return nil, err
	}
	return p, nil
}

// FetchEntryHTTP fetches a provenance.json directly via HTTP without cloning
// the full registry.  baseURL should be the raw content base of the repository,
// e.g. "https://raw.githubusercontent.com/org/registry/main".
func FetchEntryHTTP(baseURL, fingerprint, artifactSHA256 string) (*Provenance, error) {
	// Construct the raw file URL.
	base := strings.TrimRight(baseURL, "/")
	url := fmt.Sprintf("%s/keys/%s/signatures/%s.json", base, fingerprint, artifactSHA256)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("not found in registry: %s", url)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP %d from %s", resp.StatusCode, url)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20)) // max 2 MiB
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var p Provenance
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("parse remote provenance: %w", err)
	}
	return &p, nil
}

// IsGitURL returns true if registryURL should be handled via git clone/pull.
//
// The only case treated as a raw HTTP base URL (not git) is an https:// URL
// that does NOT end in ".git" — this is the GitHub raw content pattern:
//   https://raw.githubusercontent.com/org/registry/main
//
// Everything else — SSH URLs, HTTPS .git URLs, local paths — is handled
// as a git remote.
func IsGitURL(registryURL string) bool {
	if strings.HasPrefix(registryURL, "https://") && !strings.HasSuffix(registryURL, ".git") {
		return false // raw HTTPS base URL for FetchEntryHTTP
	}
	return true // git SSH, HTTPS .git, local file path, etc.
}

// GitHubRepoSlug extracts the "owner/repo" slug from a GitHub URL.
// Handles both HTTPS and SSH formats:
//
//	https://github.com/owner/repo.git  →  "owner/repo"
//	git@github.com:owner/repo.git      →  "owner/repo"
//
// Returns "" if the URL is not a recognised GitHub URL.
func GitHubRepoSlug(gitURL string) string {
	s := strings.TrimSuffix(gitURL, ".git")
	if strings.HasPrefix(s, "https://github.com/") {
		return strings.TrimPrefix(s, "https://github.com/")
	}
	if strings.HasPrefix(s, "git@github.com:") {
		return strings.TrimPrefix(s, "git@github.com:")
	}
	return ""
}
