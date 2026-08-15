from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "gate_envelope.py"

spec = importlib.util.spec_from_file_location("gate_envelope", SCRIPT)
envelope = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(envelope)


@pytest.fixture
def keypair() -> tuple[bytes, bytes]:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return (
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )


def test_encrypt_decrypt_round_trip(keypair: tuple[bytes, bytes]) -> None:
    private, public = keypair
    source = b'{"private_routing_metadata":"must stay encrypted"}'

    encoded = envelope.encrypt(public, source)

    assert envelope.decrypt(private, encoded) == source
    assert b"private_routing_metadata" not in json.dumps(encoded).encode()


def test_rejects_modified_ciphertext(keypair: tuple[bytes, bytes]) -> None:
    private, public = keypair
    encoded = envelope.encrypt(public, b"gate request")
    encoded["ciphertext"] = encoded["ciphertext"][:-2] + "AA"

    with pytest.raises(ValueError, match="envelope"):
        envelope.decrypt(private, encoded)
