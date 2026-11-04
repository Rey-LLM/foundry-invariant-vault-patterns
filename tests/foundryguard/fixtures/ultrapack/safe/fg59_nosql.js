const { User } = require("./models");

async function login(req, res) {
  const user = await User.findOne({ email: String(req.body.email) });
  res.json({ ok: Boolean(user) });
}
module.exports = { login };
