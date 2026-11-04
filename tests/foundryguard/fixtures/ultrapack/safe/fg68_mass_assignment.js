const { User } = require("./models");

async function signup(req, res) {
  const user = await User.create({ name: String(req.body.name), email: String(req.body.email) });
  res.json({ id: user.id });
}
module.exports = { signup };
