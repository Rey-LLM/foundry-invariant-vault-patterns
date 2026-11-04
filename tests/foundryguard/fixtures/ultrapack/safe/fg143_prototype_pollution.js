const settings = Object.create(null);
const ALLOWED = ["theme", "lang"];

function update(req, res) {
  for (const k of ALLOWED) if (typeof req.body[k] === "string") settings[k] = req.body[k];
  res.json(settings);
}

module.exports = { update };
