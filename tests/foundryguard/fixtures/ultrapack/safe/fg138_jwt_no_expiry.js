const jwt = require("jsonwebtoken");

function issue(user) {
  return jwt.sign({ sub: user.id }, process.env.JWT_KEY, { algorithm: "HS256", expiresIn: "15m" });
}

module.exports = { issue };
