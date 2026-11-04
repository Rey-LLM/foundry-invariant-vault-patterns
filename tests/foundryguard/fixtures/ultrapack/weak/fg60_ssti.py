from flask import render_template_string, request


def hello():
    return render_template_string("Hello " + request.args.get("name", ""))
