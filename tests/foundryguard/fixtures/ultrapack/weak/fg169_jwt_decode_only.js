const jwt = require("jsonwebtoken");

function auth(req, res, next) {
  const claims = jwt.decode(req.headers.authorization.slice(7));
  if (!claims || !claims.sub) return res.status(401).end();
  req.user = claims;
  next();
}

module.exports = { auth };
