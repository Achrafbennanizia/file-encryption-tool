# File Encryption Tool (AES-256-GCM, Python)

Kleines CLI-Tool zur Datei-Verschlüsselung mit AES.  
Demonstriert grundlegende Sicherheitsprinzipien und Kryptographie-Konzepte aus dem Studium.

## Ziel

- Vertraulichkeit von Dateien mit moderner symmetrischer Verschlüsselung
- Passwortbasierte Schlüsselableitung (PBKDF2)
- Einfaches, nachvollziehbares Dateiformat
- Geeignet als Demo-Projekt für Security / Cryptography

## Tech-Stack

- **Sprache:** Python 3.11+ (oder ähnlich)
- **Krypto-Bibliothek:** [`cryptography`](https://cryptography.io/)
- **Algorithmus:** AES-256 im GCM-Modus (authentifizierte Verschlüsselung)
- **KDF:** PBKDF2-HMAC-SHA256

## Konzept

1. Benutzer gibt ein Passwort ein.
2. Aus Passwort + zufälligem Salt wird mit PBKDF2 ein 256-Bit-Schlüssel abgeleitet.
3. Die Datei wird mit AES-256-GCM verschlüsselt.
4. Im Ausgabefile werden gespeichert:
   - Magic-Header (`FENC1`)
   - Salt
   - Nonce (IV)
   - Ciphertext inkl. Authentifizierungs-Tag

Bei der Entschlüsselung werden Salt und Nonce aus der Datei gelesen, der Schlüssel erneut abgeleitet und die Datei über AES-GCM entschlüsselt und verifiziert. Manipulationen oder falsche Passwörter führen zu einem Fehler.

## Installation

```bash
git clone <DEIN_REPO_LINK> file-encryption-tool
cd file-encryption-tool

python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

pip install -r requirements.txt
```
# file-encryption-tool
