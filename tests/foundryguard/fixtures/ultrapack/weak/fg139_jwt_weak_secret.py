import jwt


def issue(user_id):
    return jwt.encode({"sub": user_id}, "changeme", algorithm="HS256")
