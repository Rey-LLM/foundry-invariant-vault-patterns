module.exports = (req, res) => {
  const name = req.query.name;
  res.json({ name });
};
