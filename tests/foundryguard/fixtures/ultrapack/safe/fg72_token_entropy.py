import secrets


def reset_token():
    return secrets.token_hex(32)
