import os

import jwt


def issue(user_id):
    return jwt.encode({"sub": user_id}, os.environ["JWT_KEY"], algorithm="HS256")
