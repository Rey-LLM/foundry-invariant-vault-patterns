const express = require("express");
const app = express();

app.get("/me", (req, res) => {
  res.set("Cache-Control", "private, no-store");
  res.json(req.user);
});
