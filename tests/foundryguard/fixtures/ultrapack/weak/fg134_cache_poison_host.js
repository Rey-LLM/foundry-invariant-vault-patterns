const express = require("express");
const app = express();

app.get("/", (req, res) => {
  const base = "https://" + req.get("X-Forwarded-Host");
  res.send(`<script src="${base}/app.js"></script>`);
});
