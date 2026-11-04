const express = require("express");
const app = express();

app.post("/login", async (req, res) => {
  const user = await checkPassword(req.body.email, req.body.password);
  if (!user) return res.sendStatus(401);
  req.session.userId = user.id;
  res.redirect("/");
});
