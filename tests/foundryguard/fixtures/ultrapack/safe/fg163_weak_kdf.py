import hashlib
import os


def hash_password(password: str) -> bytes:
    salt = os.urandom(16)
    return salt + hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
