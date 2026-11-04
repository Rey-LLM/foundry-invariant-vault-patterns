import hashlib
import hmac

KEY = b""


def verify(body, signature):
    expected = hmac.new(KEY, body, hashlib.sha256).hexdigest()
    if signature == expected:
        return True
    return False
