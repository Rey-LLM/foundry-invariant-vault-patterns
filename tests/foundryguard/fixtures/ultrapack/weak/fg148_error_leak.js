async function handler(req, res) {
  try {
    res.json(await load(req.params.id));
  } catch (err) {
    res.status(500).send(err.stack);
  }
}

module.exports = { handler };
