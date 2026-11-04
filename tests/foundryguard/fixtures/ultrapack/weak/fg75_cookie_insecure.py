from flask import make_response


def login(sid):
    resp = make_response("ok")
    resp.set_cookie("session", sid)
    return resp
