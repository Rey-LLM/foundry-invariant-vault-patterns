const { User } = require("./models");

async function login(req, res) {
  const user = await User.findOne(req.body);
  res.json({ ok: Boolean(user) });
}
module.exports = { login };
