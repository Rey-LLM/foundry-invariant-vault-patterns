from flask import make_response


def login(sid):
    resp = make_response("ok")
    resp.set_cookie("session", sid, secure=True, httponly=True, samesite="Lax")
    return resp
