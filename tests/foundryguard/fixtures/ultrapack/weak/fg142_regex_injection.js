function search(req, res) {
  const re = new RegExp(req.query.q, "i");
  res.json(items.filter((i) => re.test(i.name)));
}

module.exports = { search };
