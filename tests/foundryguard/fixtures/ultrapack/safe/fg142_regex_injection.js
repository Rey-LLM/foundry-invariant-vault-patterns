const escapeRegExp = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

function search(req, res) {
  const re = new RegExp(escapeRegExp(req.query.q), "i");
  res.json(items.filter((i) => re.test(i.name)));
}

module.exports = { search };
