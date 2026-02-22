// manifest.go defines the Trust Manifest (provenance.json) data model
// and trust-level computation logic.
package core

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"time"
)

// SchemaVersion is the current provenance.json format version.
const SchemaVersion = "1.0"

// ── Artifact ────────────────────────────────────────────────────────────────

// Artifact describes the binary being attested.
type Artifact struct {
	Name           string   `json:"name"`
	Version        string   `json:"version"`
	SHA256         string   `json:"sha256"`          // lowercase hex
	SHA512         string   `json:"sha512"`          // lowercase hex
	BuildTimestamp string   `json:"build_timestamp"` // RFC3339 UTC
	BuildEnv       BuildEnv `json:"build_env"`
}

// BuildEnv captures the environment in which the binary was signed.
type BuildEnv struct {
	OS              string `json:"os"`
	Arch            string `json:"arch"`
	CompilerVersion string `json:"compiler_version"`
}

// ── Identity ─────────────────────────────────────────────────────────────────

// Identity represents the developer who signed the artifact.
type Identity struct {
	DisplayName       string        `json:"display_name"`
	PubKeyEd25519     string        `json:"pubkey_ed25519"`     // base64url
	PubKeyFingerprint string        `json:"pubkey_fingerprint"` // hex SHA-256
	SocialProofs      []SocialProof `json:"social_proofs"`
}

// SocialProof links an identity to a verifiable external handle.
// The proof_url must be publicly readable and contain the key fingerprint.
type SocialProof struct {
	Platform string `json:"platform"` // e.g. "github", "mastodon", "keybase"
	Handle   string `json:"handle"`
	ProofURL string `json:"proof_url"` // URL of a public document containing the fingerprint
}

// ── Signature ────────────────────────────────────────────────────────────────

// Signature holds the developer's cryptographic signature over the artifact.
type Signature struct {
	Algorithm    string `json:"algorithm"`     // always "Ed25519"
	SignedPayload string `json:"signed_payload"` // base64url of the raw payload bytes
	Value        string `json:"value"`          // base64url of the 64-byte signature
	Timestamp    string `json:"timestamp"`      // RFC3339 UTC, part of the signed payload
}

// ── Attestation ──────────────────────────────────────────────────────────────

// Attestation is a signed endorsement from a peer developer.
// The attester signs: "<artifact_sha256>|<statement>|<timestamp>"
type Attestation struct {
	AttesterPubKey      string `json:"attester_pubkey"`      // base64url
	AttesterFingerprint string `json:"attester_fingerprint"` // hex SHA-256
	Statement           string `json:"statement"`            // human-readable claim
	Scope               string `json:"scope"`                // "source" | "binary" | "identity"
	Signature           string `json:"signature"`            // base64url
	Timestamp           string `json:"timestamp"`            // RFC3339 UTC
}

// ── TrustChain ───────────────────────────────────────────────────────────────

// TrustChain defines how many valid peer attestations are required for TRUSTED status.
type TrustChain struct {
	Threshold   int    `json:"threshold"`              // minimum valid attestations
	RegistryCID string `json:"registry_cid,omitempty"` // IPFS CID or Git commit SHA
}

// ── Provenance ───────────────────────────────────────────────────────────────

// Provenance is the root structure of the trust manifest (provenance.json).
type Provenance struct {
	SchemaVersion string        `json:"schema_version"`
	Artifact      Artifact      `json:"artifact"`
	Identity      Identity      `json:"identity"`
	Signature     Signature     `json:"signature"`
	Attestations  []Attestation `json:"attestations"`
	TrustChain    TrustChain    `json:"trust_chain"`
}

// Save serialises provenance to a pretty-printed JSON file.
func (p *Provenance) Save(path string) error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal provenance: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

// LoadProvenance reads and parses a provenance.json file.
func LoadProvenance(path string) (*Provenance, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read provenance: %w", err)
	}
	var p Provenance
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse provenance: %w", err)
	}
	return &p, nil
}

// ── Trust Level ──────────────────────────────────────────────────────────────

// TrustLevel represents the computed confidence in a provenance record.
type TrustLevel int

const (
	TrustUnknown TrustLevel = 0 // No social proof, no attestations
	TrustSelf    TrustLevel = 1 // Social proofs present, no valid attestations
	TrustPeer    TrustLevel = 2 // 1+ valid attestations, below threshold
	TrustTrusted TrustLevel = 3 // Meets or exceeds attestation threshold
)

func (t TrustLevel) String() string {
	switch t {
	case TrustUnknown:
		return "UNKNOWN"
	case TrustSelf:
		return "SELF-SIGNED"
	case TrustPeer:
		return "PEER-ATTESTED"
	case TrustTrusted:
		return "TRUSTED"
	default:
		return "INVALID"
	}
}

// ComputeTrustLevel derives the trust level from attestation count and social proofs.
func ComputeTrustLevel(p *Provenance, validAttestations int) TrustLevel {
	if validAttestations >= p.TrustChain.Threshold {
		return TrustTrusted
	}
	if validAttestations > 0 {
		return TrustPeer
	}
	if len(p.Identity.SocialProofs) > 0 {
		return TrustSelf
	}
	return TrustUnknown
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// NowUTC returns the current UTC time formatted as RFC3339.
func NowUTC() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// CurrentBuildEnv captures the signing machine's runtime environment.
func CurrentBuildEnv() BuildEnv {
	return BuildEnv{
		OS:              runtime.GOOS,
		Arch:            runtime.GOARCH,
		CompilerVersion: runtime.Version(),
	}
}
