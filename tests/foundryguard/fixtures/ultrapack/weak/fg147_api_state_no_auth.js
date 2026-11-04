const express = require("express");
const router = express.Router();

router.post("/orders", async (req, res) => {
  res.status(201).json(await createOrder(req.body.item));
});

module.exports = router;
