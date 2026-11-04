import hashlib


def digest(pw):
    return hashlib.md5(pw.encode()).hexdigest()
