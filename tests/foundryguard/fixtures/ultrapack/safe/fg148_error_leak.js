async function handler(req, res) {
  try {
    res.json(await load(req.params.id));
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: "internal error" });
  }
}

module.exports = { handler };
