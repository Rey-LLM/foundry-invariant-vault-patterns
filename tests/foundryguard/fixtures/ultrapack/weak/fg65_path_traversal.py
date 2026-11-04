from flask import request


def read():
    return open(request.args["f"]).read()
