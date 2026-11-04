const express = require("express");
const app = express();
const LANGS = new Set(["en", "de"]);

app.get("/doc", (req, res) => {
  const lang = String(req.query.lang);
  res.setHeader("Content-Language", LANGS.has(lang) ? lang : "en");
  res.send("ok");
});
