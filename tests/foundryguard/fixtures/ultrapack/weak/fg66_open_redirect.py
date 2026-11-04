from flask import redirect, request


def back():
    return redirect(request.args.get("next"))
