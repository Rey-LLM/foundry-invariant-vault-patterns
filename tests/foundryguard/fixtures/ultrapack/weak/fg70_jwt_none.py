import jwt


def claims(tok):
    return jwt.decode(tok, options={"verify_signature": False})
