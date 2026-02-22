// Package core provides the cryptographic primitives for open-trust.
// All operations use well-audited standard library components:
//   - Ed25519   (crypto/ed25519)  : asymmetric signing
//   - AES-256-GCM (crypto/aes)   : authenticated encryption of private key
//   - Argon2id  (x/crypto/argon2): password-based key derivation
//   - SHA-256 / SHA-512           : artifact integrity
package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters — deliberately conservative for a key-protection context.
const (
	argon2Time    uint32 = 3
	argon2Memory  uint32 = 64 * 1024 // 64 MiB
	argon2Threads uint8  = 4
	argon2KeyLen  uint32 = 32 // 256-bit AES key
	saltLen              = 16 // 128-bit salt
	nonceLen             = 12 // 96-bit GCM nonce (standard)
)

// KeyStore is the on-disk representation of an encrypted Ed25519 private key.
// All binary fields are base64url-encoded (no padding) for JSON safety.
type KeyStore struct {
	Version     string `json:"version"`
	Algorithm   string `json:"algorithm"`    // "argon2id+aes256gcm"
	Salt        string `json:"salt"`         // base64url, Argon2id salt
	Nonce       string `json:"nonce"`        // base64url, AES-GCM nonce
	Ciphertext  string `json:"ciphertext"`   // base64url, encrypted 32-byte seed
	PubKey      string `json:"pubkey"`       // base64url, Ed25519 public key
	Fingerprint string `json:"fingerprint"`  // hex SHA-256 of public key
}

// GenerateKeypair creates a new Ed25519 keypair using a CSPRNG.
func GenerateKeypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// Fingerprint returns the lowercase hex-encoded SHA-256 digest of pubkey.
// This is the canonical identifier for a key across the system.
func Fingerprint(pubkey ed25519.PublicKey) string {
	h := sha256.Sum256(pubkey)
	return hex.EncodeToString(h[:])
}

// SaveKey encrypts privkey with the given passphrase and writes a KeyStore
// JSON file to path with permissions 0600 (owner read/write only).
func SaveKey(path string, privkey ed25519.PrivateKey, passphrase []byte) error {
	pubkey := privkey.Public().(ed25519.PublicKey)

	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}

	// Derive a 256-bit AES key from the passphrase via Argon2id.
	aesKey := argon2.IDKey(passphrase, salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}

	// We encrypt only the 32-byte seed. The full private key is deterministically
	// re-derived from the seed via ed25519.NewKeyFromSeed, so storing the seed
	// is sufficient and minimises the ciphertext size.
	ciphertext := gcm.Seal(nil, nonce, privkey.Seed(), nil)

	ks := KeyStore{
		Version:     "1",
		Algorithm:   "argon2id+aes256gcm",
		Salt:        base64.RawURLEncoding.EncodeToString(salt),
		Nonce:       base64.RawURLEncoding.EncodeToString(nonce),
		Ciphertext:  base64.RawURLEncoding.EncodeToString(ciphertext),
		PubKey:      base64.RawURLEncoding.EncodeToString(pubkey),
		Fingerprint: Fingerprint(pubkey),
	}

	data, err := json.MarshalIndent(ks, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal keystore: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}

// LoadKey reads a KeyStore file and decrypts the private key.
// Returns an explicit error if the passphrase is wrong (GCM authentication failure).
func LoadKey(path string, passphrase []byte) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read keystore: %w", err)
	}

	var ks KeyStore
	if err := json.Unmarshal(data, &ks); err != nil {
		return nil, fmt.Errorf("parse keystore: %w", err)
	}

	salt, err := base64.RawURLEncoding.DecodeString(ks.Salt)
	if err != nil {
		return nil, fmt.Errorf("decode salt: %w", err)
	}
	nonce, err := base64.RawURLEncoding.DecodeString(ks.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(ks.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}

	aesKey := argon2.IDKey(passphrase, salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	seed, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// GCM Open fails on wrong passphrase — never expose internal detail.
		return nil, errors.New("invalid passphrase or corrupted keystore")
	}

	return ed25519.NewKeyFromSeed(seed), nil
}

// Sign signs payload with privkey and returns the raw 64-byte Ed25519 signature.
func Sign(payload []byte, privkey ed25519.PrivateKey) []byte {
	return ed25519.Sign(privkey, payload)
}

// Verify verifies an Ed25519 signature. Returns true only on success.
func Verify(payload, signature []byte, pubkey ed25519.PublicKey) bool {
	return ed25519.Verify(pubkey, payload, signature)
}

// HashFile streams path through SHA-256 and SHA-512 simultaneously,
// returning both digests as lowercase hex strings.
func HashFile(path string) (sha256hex, sha512hex string, err error) {
	return HashFileProgress(path, nil)
}

// HashFileProgress is like HashFile but calls onProgress(bytesRead, totalBytes)
// after each read chunk.  Pass nil to skip progress reporting.
func HashFileProgress(path string, onProgress func(n, total int64)) (sha256hex, sha512hex string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return "", "", fmt.Errorf("stat file: %w", err)
	}
	total := info.Size()

	h256 := sha256.New()
	h512 := sha512.New()

	var src io.Reader = f
	if onProgress != nil && total > 0 {
		src = &progressReader{Reader: f, total: total, fn: onProgress}
	}

	if _, err := io.Copy(io.MultiWriter(h256, h512), src); err != nil {
		return "", "", fmt.Errorf("hash file: %w", err)
	}

	return hex.EncodeToString(h256.Sum(nil)), hex.EncodeToString(h512.Sum(nil)), nil
}

// progressReader wraps an io.Reader and calls fn after every read.
type progressReader struct {
	io.Reader
	total   int64
	current int64
	fn      func(n, total int64)
}

func (p *progressReader) Read(b []byte) (n int, err error) {
	n, err = p.Reader.Read(b)
	if n > 0 {
		p.current += int64(n)
		p.fn(p.current, p.total)
	}
	return
}

// SigningPayload constructs the canonical byte sequence that is signed.
// Format: "<sha256hex>|<sha512hex>|<rfc3339_timestamp>"
// The pipe delimiter is chosen because it cannot appear in hex or RFC3339 strings.
func SigningPayload(sha256hex, sha512hex, timestamp string) []byte {
	return []byte(sha256hex + "|" + sha512hex + "|" + timestamp)
}

// AttestationPayload constructs the canonical byte sequence signed by an attester.
// Format: "<artifact_sha256hex>|<statement>|<rfc3339_timestamp>"
func AttestationPayload(artifactSHA256, statement, timestamp string) []byte {
	return []byte(artifactSHA256 + "|" + statement + "|" + timestamp)
}
