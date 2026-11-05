const jwt = require("jsonwebtoken");

const key = Buffer.from(process.env.JWT_KEY, "base64");

function auth(req, res, next) {
  const claims = jwt.verify(req.headers.authorization.slice(7), key, { algorithms: ["HS256"] });
  req.user = claims;
  next();
}

module.exports = { auth };
