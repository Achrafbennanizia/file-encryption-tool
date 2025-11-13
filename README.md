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
## Verwendung
Datei verschlüsseln
```bash
python filecrypt.py encrypt -i geheim.txt -o geheim.enc
```
- Passwort wird sicher per Prompt abgefragt (zweimal zur Bestätigung).
- Output ist eine Binärdatei (geheim.enc).

Optional kannst du das Passwort (für Tests) direkt angeben:
```bash
python filecrypt.py encrypt -i geheim.txt -o geheim.enc -p "test123!"
```
⚠️ Warnung: Passwort auf der Kommandozeile ist unsicher (History, ps, Logs).

Datei entschlüsseln
```bash
python filecrypt.py decrypt -i geheim.enc -o geheim_entschluesselt.txt
```
- Passwort wird einmal abgefragt.
- Bei falschem Passwort oder manipulierten Daten gibt das Tool einen Fehler aus.

Hilfe
```bash
python filecrypt.py -h
python filecrypt.py encrypt -h
python filecrypt.py decrypt -h
```

## Sicherheitsaspekte

- AES-256-GCM bietet Vertraulichkeit und Integrität (authentifizierte Verschlüsselung).
- PBKDF2 mit hoher Iterationszahl erschwert Brute-Force-Angriffe auf das Passwort.
- Salt und Nonce sind zufällig und werden pro Verschlüsselung neu erzeugt.
- Der Schlüssel wird nie in der Datei gespeichert.
- Trotzdem ist das Tool nur als Lern- & Demo-Projekt gedacht und nicht als vollwertiger Ersatz für professionelle Lösungen wie age, gpg etc.
