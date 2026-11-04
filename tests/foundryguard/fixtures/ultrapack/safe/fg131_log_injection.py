import logging
from flask import Flask, request

app = Flask(__name__)


@app.get("/search")
def search():
    q = request.args.get("q", "")
    logging.info("search for %r", q.replace("\r", " ").replace("\n", " "))
    return "ok"
