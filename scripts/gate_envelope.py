#!/usr/bin/env python3
"""Authenticated hybrid encryption for opaque gate-request envelopes."""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AAD = b"youthscout-gate-envelope-v1"
FIELDS = {"version", "wrapped_key", "nonce", "ciphertext"}


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def unb64(value: object) -> bytes:
    if not isinstance(value, str):
        raise ValueError("invalid envelope")
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError("invalid envelope") from exc


def encrypt(public_pem: bytes, plaintext: bytes) -> dict[str, object]:
    try:
        public_key = serialization.load_pem_public_key(public_pem)
        symmetric_key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)
        wrapped_key = public_key.encrypt(
            symmetric_key,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=AAD),
        )
        ciphertext = AESGCM(symmetric_key).encrypt(nonce, plaintext, AAD)
    except Exception as exc:
        raise ValueError("envelope encryption failed") from exc
    return {"version": 1, "wrapped_key": b64(wrapped_key), "nonce": b64(nonce), "ciphertext": b64(ciphertext)}


def decrypt(private_pem: bytes, envelope: dict[str, object], password: bytes | None = None) -> bytes:
    if not isinstance(envelope, dict) or set(envelope) != FIELDS or envelope.get("version") != 1:
        raise ValueError("invalid envelope")
    try:
        private_key = serialization.load_pem_private_key(private_pem, password=password)
        symmetric_key = private_key.decrypt(
            unb64(envelope["wrapped_key"]),
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=AAD),
        )
        return AESGCM(symmetric_key).decrypt(unb64(envelope["nonce"]), unb64(envelope["ciphertext"]), AAD)
    except (InvalidTag, ValueError, TypeError) as exc:
        raise ValueError("invalid envelope") from exc


def cli() -> None:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    encrypt_cmd = commands.add_parser("encrypt")
    encrypt_cmd.add_argument("--public-key", type=Path, required=True)
    encrypt_cmd.add_argument("--input", type=Path, required=True)
    encrypt_cmd.add_argument("--output", type=Path, required=True)
    decrypt_cmd = commands.add_parser("decrypt")
    decrypt_cmd.add_argument("--private-key", type=Path, required=True)
    decrypt_cmd.add_argument("--passphrase-env", required=True)
    decrypt_cmd.add_argument("--input", type=Path, required=True)
    decrypt_cmd.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "encrypt":
        result = encrypt(args.public_key.read_bytes(), args.input.read_bytes())
        args.output.write_text(json.dumps(result, sort_keys=True), encoding="utf-8")
    else:
        passphrase = os.environ.get(args.passphrase_env)
        if not passphrase:
            raise SystemExit("required passphrase environment variable is empty")
        plaintext = decrypt(args.private_key.read_bytes(), json.loads(args.input.read_text()), passphrase.encode())
        args.output.write_bytes(plaintext)


if __name__ == "__main__":
    cli()
