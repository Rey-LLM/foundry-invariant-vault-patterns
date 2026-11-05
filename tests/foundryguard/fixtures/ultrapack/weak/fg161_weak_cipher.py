import os

from Crypto.Cipher import DES3

KEY = bytes.fromhex(os.environ["CARD_KEY"])


def seal(data: bytes, iv: bytes) -> bytes:
    return DES3.new(KEY, DES3.MODE_CBC, iv).encrypt(data)
