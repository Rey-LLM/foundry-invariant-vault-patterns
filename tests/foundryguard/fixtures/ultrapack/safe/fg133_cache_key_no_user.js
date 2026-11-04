const express = require("express");
const cache = require("./cache");
const app = express();

app.get("/dashboard", async (req, res) => {
  const body = await render(req.user);
  cache.set(`${req.user.id}:${req.originalUrl}`, body, 60);
  res.send(body);
});
