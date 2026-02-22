# 🛡️ Open-Trust CLI

**The sovereign alternative to expensive code-signing certificates.** Open-Trust breaks the monopoly of Certificate Authorities (CAs) by replacing annual taxes with mathematical proof (Ed25519) and peer-to-peer validation.

---

## 🚀 User Guide

### 1. Installation
```bash
git clone https://github.com/Lastexitfromnowhere/open-trust-cli.git
cd open-trust-cli
go build -o open-trust
```

### 2. Create your Identity (Keygen)
Generate your Ed25519 key pair secured by Argon2id. Your private key remains **only** on your local machine.
```bash
./open-trust keygen
```
> ⚠️ Keep your passphrase safe. It cannot be recovered if lost.

### 3. Sign a Binary (Sign)
Calculates SHA-256/SHA-512 hashes and generates a `provenance.json` certificate.
```bash
./open-trust sign --name "MyProject" ./my-software.exe
```

### 4. Publish to Registry (Publish)
Automatically uploads your signature to the default public trust registry.
```bash
# Standard publication
./open-trust publish

# Specify a custom registry or provenance file
./open-trust publish --provenance ./provenance.json --registry https://github.com/Lastexitfromnowhere/open-trust-registry.git
```

### 5. Get Peer Attestations (Attest)

Peer attestations are the social proof layer of Open-Trust. Each attestation is a cryptographic signature from another developer vouching for your binary. Once you reach the threshold (default: 2), your artifact reaches **TRUSTED** status.

**Flow:**

```
You                            Peer (Alice)
 |                                  |
 |── send provenance.json ────────► |
 |                                  |── open-trust attest \
 |                                  |     --key alice.key.json \
 |                                  |     --provenance provenance.json \
 |                                  |     --statement "Reviewed source, matches binary" \
 |                                  |     --scope "source-review"
 |◄── receive provenance.json ───── |
 |
 |── open-trust publish  (attestations are embedded inside)
```

**For the attester (Alice):**
```bash
# She needs her own keypair first
./open-trust keygen

# Then she attests your provenance.json
./open-trust attest \
  --key      alice.key.json \
  --provenance provenance.json \
  --statement "I reviewed the source code and it matches this binary" \
  --scope    "source-review"
```

**Attestation flags:**

| Flag | Description |
|------|-------------|
| `--key` | Attester's own key file |
| `--provenance` | The provenance.json to attest |
| `--statement` | Free-text statement ("tested on Windows 11", "reviewed source"…) |
| `--scope` | Category: `source-review`, `binary-test`, `identity-check`… |

> The attester only needs your `provenance.json` — **never** your private key.
> Trust threshold can be adjusted at sign time via `--threshold`.

---

### 6. Verify a File (Verify)
```bash
# Offline (cryptographic checks only)
./open-trust verify --provenance ./provenance.json ./my-software.exe

# Online (also cross-checks against the registry)
./open-trust verify --provenance ./provenance.json --registry https://github.com/Lastexitfromnowhere/open-trust-registry.git ./my-software.exe
```

---

## 🔍 Trust Ecosystem

The project relies on three inseparable pillars:

1. **The Engine (CLI)**: This repository. Allows hashing, signing, and publishing.
2. **The Registry (Data)**: [open-trust-registry](https://github.com/Lastexitfromnowhere/open-trust-registry). A public, immutable database of all signatures.
3. **The Dashboard (Web)**: [Online Verifier](https://lastexitfromnowhere.github.io/open-trust-dashboard/). Allows users to verify your files via simple drag-and-drop.

---

## 🛡️ Security & Philosophy

- **Zero-Knowledge**: Your files are never uploaded. All hashing happens locally in your browser or via the CLI.
- **Total Transparency**: The code is 100% open-source to ensure there are no backdoors.
- **Censorship Resistant**: By using Git as a database, the signature history is auditable and decentralized.

---
*Open-Trust: Empowering independent creators with sovereign trust.*
