#!/usr/bin/env python3
"""
File Encryption Tool
- AES-256-GCM
- Passwort -> Key mit PBKDF2
- Einfaches CLI: encrypt / decrypt
"""

import argparse
import getpass
import os
import sys
from typing import Optional

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# Dateiformat:
# [MAGIC 5B][SALT 16B][NONCE 12B][CIPHERTEXT+TAG ...]
MAGIC = b"FENC1"
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32        # 32 Bytes = 256 Bit
PBKDF2_ITERATIONS = 200_000


def derive_key(password: bytes, salt: bytes) -> bytes:
    """Leitet aus Passwort+Salt einen AES-Schlüssel ab (PBKDF2-HMAC-SHA256)."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password)


def encrypt_file(input_path: str, output_path: str, password: str) -> None:
    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"Eingabedatei nicht gefunden: {input_path}")

    salt = os.urandom(SALT_SIZE)
    key = derive_key(password.encode("utf-8"), salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)

    with open(input_path, "rb") as f:
        plaintext = f.read()

    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    with open(output_path, "wb") as f:
        f.write(MAGIC)
        f.write(salt)
        f.write(nonce)
        f.write(ciphertext)


def decrypt_file(input_path: str, output_path: str, password: str) -> None:
    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"Eingabedatei nicht gefunden: {input_path}")

    with open(input_path, "rb") as f:
        magic = f.read(len(MAGIC))
        if magic != MAGIC:
            raise ValueError("Ungültiges Dateiformat oder keine FENC1-Datei.")
        salt = f.read(SALT_SIZE)
        nonce = f.read(NONCE_SIZE)
        ciphertext = f.read()

    key = derive_key(password.encode("utf-8"), salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag as e:
        raise ValueError("Entschlüsselung fehlgeschlagen (falsches Passwort oder manipulierte Datei).") from e

    with open(output_path, "wb") as f:
        f.write(plaintext)


def prompt_password(confirm: bool = False) -> str:
    """Fragt Passwort sicher per getpass ab."""
    pw = getpass.getpass("Passwort: ")
    if confirm:
        pw2 = getpass.getpass("Passwort wiederholen: ")
        if pw != pw2:
            print("Passwörter stimmen nicht überein.", file=sys.stderr)
            sys.exit(1)
    if not pw:
        print("Leeres Passwort ist nicht erlaubt.", file=sys.stderr)
        sys.exit(1)
    return pw


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Kleines CLI-Tool zur Datei-Verschlüsselung mit AES-256-GCM."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # encrypt
    enc = subparsers.add_parser("encrypt", help="Datei verschlüsseln")
    enc.add_argument("-i", "--input", required=True, help="Eingabedatei (klar)")
    enc.add_argument("-o", "--output", required=True, help="Ausgabedatei (verschlüsselt)")
    enc.add_argument("-p", "--password", help="Passwort im Klartext (nicht empfohlen)")

    # decrypt
    dec = subparsers.add_parser("decrypt", help="Datei entschlüsseln")
    dec.add_argument("-i", "--input", required=True, help="Eingabedatei (verschlüsselt)")
    dec.add_argument("-o", "--output", required=True, help="Ausgabedatei (klar)")
    dec.add_argument("-p", "--password", help="Passwort im Klartext (nicht empfohlen)")

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "encrypt":
        password = args.password or prompt_password(confirm=True)
        try:
            encrypt_file(args.input, args.output, password)
            print(f"✅ Verschlüsselt: {args.input} -> {args.output}")
        except Exception as e:
            print(f"Fehler beim Verschlüsseln: {e}", file=sys.stderr)
            return 1

    elif args.command == "decrypt":
        password = args.password or prompt_password(confirm=False)
        try:
            decrypt_file(args.input, args.output, password)
            print(f"✅ Entschlüsselt: {args.input} -> {args.output}")
        except Exception as e:
            print(f"Fehler beim Entschlüsseln: {e}", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
