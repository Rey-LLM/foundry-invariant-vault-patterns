from flask import Flask, request

app = Flask(__name__)


@app.post("/items")
def items():
    return request.get_json()
