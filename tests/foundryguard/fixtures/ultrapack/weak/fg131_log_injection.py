import logging
from flask import Flask, request

app = Flask(__name__)


@app.get("/search")
def search():
    logging.info("search for %s", request.args.get("q"))
    return "ok"
