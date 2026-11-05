from cryptography.hazmat.primitives.asymmetric import padding


def wrap_key(public_key, data_key: bytes) -> bytes:
    return public_key.encrypt(data_key, padding.PKCS1v15())
