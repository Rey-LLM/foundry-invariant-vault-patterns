const argon2 = require("argon2");
const User = require("./models/user");

async function register(req, res) {
  const user = await User.create({
    email: req.body.email,
    passwordHash: await argon2.hash(req.body.password),
  });
  res.status(201).json({ id: user.id });
}

module.exports = { register };
