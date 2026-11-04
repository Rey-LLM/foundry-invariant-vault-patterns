const { User } = require("./models");

async function signup(req, res) {
  const user = await User.create(req.body);
  res.json({ id: user.id });
}
module.exports = { signup };
