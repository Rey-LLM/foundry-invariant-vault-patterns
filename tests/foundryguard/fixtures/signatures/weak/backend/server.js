const express = require("express");
const cors = require("cors");
const multer = require("multer");
const { exec } = require("child_process");

const app = express();
const SIGNER_PRIVATE_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const upload = multer({ dest: "uploads/" });

app.use(cors({ origin: "*" }));
app.use(express.json());

app.post("/login", (req, res) => {
  const token = Math.random().toString(36).slice(2);
  res.json({ token });
});

app.post("/avatar", upload.single("file"), (req, res) => res.sendStatus(204));

app.get("/calc", (req, res) => {
  res.json({ value: eval(req.query.expr) });
});

app.get("/ping", (req, res) => {
  exec("ping -c 1 " + req.query.host, (err, out) => res.send(out));
});

module.exports = { app, SIGNER_PRIVATE_KEY };
