const express = require("express");
const { requireAuth } = require("./middleware/auth");
const router = express.Router();

router.post("/orders", requireAuth, async (req, res) => {
  res.status(201).json(await createOrder(req.user.id, req.body.item));
});

module.exports = router;
