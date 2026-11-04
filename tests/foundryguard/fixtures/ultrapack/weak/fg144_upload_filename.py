import os

from flask import Flask, request

app = Flask(__name__)
UPLOAD_DIR = "/srv/uploads"


@app.post("/avatar")
def avatar():
    f = request.files["file"]
    f.save(os.path.join(UPLOAD_DIR, f.filename))
    return "ok"
