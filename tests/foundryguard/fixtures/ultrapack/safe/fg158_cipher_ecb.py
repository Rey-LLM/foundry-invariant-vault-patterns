import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY = bytes.fromhex(os.environ["DATA_KEY"])


def seal(data: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(KEY).encrypt(nonce, data, None)
