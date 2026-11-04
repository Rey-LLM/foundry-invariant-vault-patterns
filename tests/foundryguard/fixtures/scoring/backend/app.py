import os
import pickle
import sqlite3

import requests
from flask import Flask, redirect, request

app = Flask(__name__)
API_KEY = "sk-live-0123456789abcdefghijklmnop"
hits = 0


@app.route("/user")
def user():
    global hits
    hits += 1
    name = request.args.get("name")
    db = sqlite3.connect("app.db")
    return str(db.execute(f"SELECT * FROM users WHERE name = '{name}'").fetchall())


@app.route("/load", methods=["POST"])
def load():
    return pickle.loads(request.data)


@app.route("/ping")
def ping():
    os.system("ping -c 1 " + request.args["host"])
    return requests.get("https://example.com/health", verify=False).text


@app.route("/go")
def go():
    return redirect(request.args["next"])


def collect(item, bucket=[]):
    bucket.append(item)
    return bucket


if __name__ == "__main__":
    app.run(debug=True)
