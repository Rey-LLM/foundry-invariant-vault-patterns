const crypto = require("crypto");
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const multer = require("multer");

const app = express();
const upload = multer({ dest: "uploads/", limits: { fileSize: 1024 * 1024 } });

app.use(helmet());
app.use(cors({ origin: ["https://app.example.com"] }));
app.use(express.json({ limit: "100kb" }));
app.use("/login", rateLimit({ windowMs: 60000, max: 5 }));

app.post("/login", (req, res) => {
  const token = crypto.randomBytes(32).toString("hex");
  res.json({ token });
});

app.post("/avatar", upload.single("file"), (req, res) => res.sendStatus(204));

module.exports = { app, signerKey: process.env.SIGNER_KEY };
