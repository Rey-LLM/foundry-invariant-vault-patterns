const jwt = require("jsonwebtoken");
const fs = require("fs");

const publicKey = fs.readFileSync(process.env.JWT_PUBLIC_KEY_PATH);

function auth(req, res, next) {
  req.user = jwt.verify(req.headers.authorization.slice(7), publicKey, { algorithms: ["RS256"] });
  next();
}

module.exports = { auth };
