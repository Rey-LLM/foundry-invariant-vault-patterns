const _ = require("lodash");
const settings = {};

function update(req, res) {
  _.merge(settings, req.body);
  res.json(settings);
}

module.exports = { update };
