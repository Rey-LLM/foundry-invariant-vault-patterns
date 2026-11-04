const express = require("express");
const app = express();

app.get("/doc", (req, res) => {
  res.setHeader("Content-Language", req.query.lang);
  res.send("ok");
});
