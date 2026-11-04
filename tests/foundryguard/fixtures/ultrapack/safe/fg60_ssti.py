from flask import render_template, request


def hello():
    return render_template("hello.html", name=request.args.get("name", ""))
