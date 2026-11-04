from flask import Flask

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1024

if __name__ == "__main__":
    app.run(debug=True)
