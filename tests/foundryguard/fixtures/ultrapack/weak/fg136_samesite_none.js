const express = require("express");
const app = express();

app.post("/login", (req, res) => {
  res.cookie("sid", "x", { httpOnly: true, secure: true, sameSite: "none" });
  res.end();
});
