import os

from flask import Flask, request
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_DIR = "/srv/uploads"


@app.post("/avatar")
def avatar():
    f = request.files["file"]
    f.save(os.path.join(UPLOAD_DIR, secure_filename(f.filename)))
    return "ok"
