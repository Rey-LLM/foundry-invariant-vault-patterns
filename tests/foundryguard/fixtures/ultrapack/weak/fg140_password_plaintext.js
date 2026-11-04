const User = require("./models/user");

async function register(req, res) {
  const user = await User.create({
    email: req.body.email,
    password: req.body.password,
  });
  res.status(201).json({ id: user.id });
}

module.exports = { register };
