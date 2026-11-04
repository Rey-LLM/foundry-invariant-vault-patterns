import requests
from flask import request

SOURCES = {"news": "https://news.example.com/feed"}


def preview():
    key = request.args.get("source")
    r = requests.get(SOURCES[key], timeout=5)
    return r.text
