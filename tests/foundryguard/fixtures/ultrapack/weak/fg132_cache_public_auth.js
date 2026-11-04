const express = require("express");
const app = express();

app.get("/me", (req, res) => {
  res.set("Cache-Control", "public, max-age=600");
  res.json(req.user);
});
