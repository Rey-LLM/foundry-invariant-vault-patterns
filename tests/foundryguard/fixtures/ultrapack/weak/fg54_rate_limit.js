const express = require("express");
const helmet = require("helmet");
const app = express();
app.use(helmet());

app.post("/login", (req, res) => res.sendStatus(200));
