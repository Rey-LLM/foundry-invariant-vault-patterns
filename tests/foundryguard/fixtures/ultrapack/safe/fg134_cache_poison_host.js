const express = require("express");
const app = express();
const base = process.env.PUBLIC_BASE_URL;

app.get("/", (req, res) => {
  res.send(`<script src="${base}/app.js"></script>`);
});
