from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def wrap_key(public_key, data_key: bytes) -> bytes:
    return public_key.encrypt(data_key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
