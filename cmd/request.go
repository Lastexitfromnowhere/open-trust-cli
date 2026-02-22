package cmd

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"

	"open-trust/core"
)

func RunRequestAttest(args []string) error {
	fs := flag.NewFlagSet("request-attest", flag.ContinueOnError)

	provPath    := fs.String("provenance", "provenance.json", "path to the provenance.json to advertise")
	registryURL := fs.String("registry", core.DefaultRegistryURL,
		"Git URL of the trust registry (used to derive the GitHub repo)")
	message := fs.String("message", "", "optional context message added to the issue body")

	fs.Usage = func() {
		PrintCommandBanner("request-attest", "open a GitHub issue to request peer attestations")
		fmt.Printf(`Opens an issue in the trust registry repository so that other developers
can discover your binary and attest it.

The issue embeds your provenance.json and step-by-step instructions for
any volunteer attester. Once enough peers attest, you reach TRUSTED status.

Default registry: %s

Authentication:
  Set %s=<your-github-PAT> (needs issues:write scope on the registry repo)

Flags:
`, core.DefaultRegistryURL, envToken)
		fs.PrintDefaults()
		fmt.Println(`
Example:
  OPEN_TRUST_GITHUB_TOKEN=ghp_xxx open-trust request-attest

Example with custom message:
  open-trust request-attest --message "Tested on Windows 11 and macOS 14"`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	PrintCommandBanner("request-attest", "request peer attestations via GitHub")

	// ── GitHub token ──────────────────────────────────────────────────────────

	token := os.Getenv(envToken)
	if token == "" {
		printFail("GitHub token not set.")
		return fmt.Errorf(
			"environment variable %s is required\n\n"+
				"  Create a Personal Access Token at https://github.com/settings/tokens\n"+
				"  Required scope: repo (or issues:write on the registry repo)\n\n"+
				"  Then run:\n"+
				"    export %s=ghp_your_token\n"+
				"    open-trust request-attest", envToken, envToken)
	}

	// ── Load provenance ───────────────────────────────────────────────────────

	p, err := core.LoadProvenance(*provPath)
	if err != nil {
		printFail("Cannot read provenance.json: %s", *provPath)
		return fmt.Errorf("load provenance: %w", err)
	}

	printInfo("Requesting attestations for: %s v%s", p.Artifact.Name, p.Artifact.Version)
	fmt.Printf("  Developer   : %s\n", p.Identity.DisplayName)
	fmt.Printf("  Fingerprint : %s\n", colBold(p.Identity.PubKeyFingerprint[:16]+"…"))
	fmt.Printf("  SHA-256     : %s\n", p.Artifact.SHA256[:32]+"…")
	fmt.Println()

	// ── Derive GitHub repo slug ───────────────────────────────────────────────

	slug := core.GitHubRepoSlug(*registryURL)
	if slug == "" {
		return fmt.Errorf(
			"cannot derive a GitHub repo from registry URL: %q\n\n"+
				"  Use a GitHub URL, e.g.:\n"+
				"    --registry https://github.com/owner/open-trust-registry.git", *registryURL)
	}

	// ── Serialise provenance.json ─────────────────────────────────────────────

	provJSON, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("serialise provenance: %w", err)
	}

	// ── Build issue ───────────────────────────────────────────────────────────

	title := fmt.Sprintf("[ATTEST REQUEST] %s v%s — by %s",
		p.Artifact.Name, p.Artifact.Version, p.Identity.DisplayName)

	msgSection := ""
	if *message != "" {
		msgSection = fmt.Sprintf("\n> **Note from developer:** %s\n", *message)
	}

	fp := p.Identity.PubKeyFingerprint
	date := ""
	if len(p.Signature.Timestamp) >= 10 {
		date = p.Signature.Timestamp[:10]
	}

	body := fmt.Sprintf(`## Attestation Request
%s
| | |
|---|---|
| **App** | %s v%s |
| **Developer** | %s |
| **Fingerprint** | `+"`%s`"+` |
| **SHA-256** | `+"`%s`"+` |
| **Signed on** | %s |

---

### How to attest

1. Install the [open-trust CLI](https://github.com/Lastexitfromnowhere/open-trust-cli)
2. Copy the `+"`provenance.json`"+` from the block below and save it as a file
3. Run:

`+"```bash"+`
open-trust attest \
  --key      your-key.key.json \
  --provenance provenance.json \
  --statement "I reviewed the source code and it matches this binary" \
  --scope    "source-review"
`+"```"+`

4. Post the **modified** `+"`provenance.json`"+` as a comment on this issue

> This binary needs **%d attestation(s)** to reach TRUSTED status.
> You only need the `+"`provenance.json`"+` — **never** share your private key.

---

<details>
<summary>📄 provenance.json (click to expand)</summary>

`+"```json"+`
%s
`+"```"+`

</details>`,
		msgSection,
		p.Artifact.Name, p.Artifact.Version,
		p.Identity.DisplayName,
		fp,
		p.Artifact.SHA256,
		date,
		p.TrustChain.Threshold,
		string(provJSON),
	)

	// ── POST to GitHub Issues API ─────────────────────────────────────────────

	type issueRequest struct {
		Title string `json:"title"`
		Body  string `json:"body"`
	}
	type issueResponse struct {
		HTMLURL string `json:"html_url"`
		Number  int    `json:"number"`
	}

	payload, _ := json.Marshal(issueRequest{Title: title, Body: body})

	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/issues", slug)
	req, err := http.NewRequest(http.MethodPost, apiURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("Content-Type", "application/json")

	s := spin("Opening GitHub issue…")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.fail("HTTP request failed.")
		return fmt.Errorf("github api: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		s.fail("GitHub returned an error.")
		return fmt.Errorf(
			"github api responded %d\n\n"+
				"  Body: %s\n\n"+
				"  Common fixes:\n"+
				"  • 401 Unauthorized — token invalid or expired\n"+
				"  • 403 Forbidden    — token lacks 'repo' or 'issues:write' scope\n"+
				"  • 404 Not Found    — registry repo %q does not exist or is private",
			resp.StatusCode, string(respBody), slug)
	}

	var result issueResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("parse github response: %w", err)
	}

	s.ok(fmt.Sprintf("Issue #%d created", result.Number))

	// ── Summary ───────────────────────────────────────────────────────────────

	fmt.Println()
	printDivider()
	printOK("Attestation request published!")
	fmt.Printf("  Issue : %s\n", colBold(result.HTMLURL))
	fmt.Printf("  Title : %s\n", title)
	fmt.Println()
	fmt.Println("  Share this link with developers you trust.")
	fmt.Println("  They will post the attested provenance.json as a comment.")
	fmt.Println("  Then run: open-trust publish")
	printDivider()
	fmt.Println()

	return nil
}
