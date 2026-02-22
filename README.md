# 🛡️ Open-Trust CLI

> **"La confiance ne s'achète pas, elle se mérite."**

**Open-Trust** est un moteur de signature cryptographique souverain conçu pour les développeurs indépendants. Il brise le monopole des autorités de certification (CA) payantes en remplaçant les taxes annuelles par une preuve mathématique et une validation par les pairs.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org)

---

## ✊ Pourquoi Open-Trust ?

Les systèmes actuels (Windows SmartScreen, macOS Gatekeeper) imposent une "taxe sur la visibilité". Si vous ne payez pas des centaines de dollars par an, votre logiciel est marqué comme dangereux. 

**Open-Trust change la donne :**
- **Zéro Frais :** Pas d'abonnement. Votre identité vous appartient.
- **Souveraineté :** Basé sur la cryptographie Ed25519 (rapide et sécurisée).
- **Transparence :** Chaque signature est ancrée dans un registre public immuable sur GitHub.
- **Respect de la vie privée :** Aucun fichier n'est uploadé. Tout se passe localement.

---

## 🚀 Installation

Assurez-vous d'avoir [Go](https://go.dev/doc/install) installé sur votre machine :

```bash
git clone [https://github.com/Lastexitfromnowhere/open-trust-cli.git](https://github.com/Lastexitfromnowhere/open-trust-cli.git)
cd open-trust-cli
go build -o open-trust
