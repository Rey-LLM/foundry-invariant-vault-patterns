import os

from Crypto.Cipher import AES

KEY = os.environ["DATA_KEY"].encode()


def seal(data: bytes) -> bytes:
    return AES.new(KEY, AES.MODE_ECB).encrypt(data)
