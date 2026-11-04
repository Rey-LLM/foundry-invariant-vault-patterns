import requests
from flask import request


def preview():
    url = request.args.get("url")
    r = requests.get(url, timeout=5)
    return r.text
