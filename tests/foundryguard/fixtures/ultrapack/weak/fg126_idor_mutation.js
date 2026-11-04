const express = require("express");
const Order = require("./models/order");
const router = express.Router();

router.delete("/orders/:id", async (req, res) => {
  await Order.findByIdAndDelete(req.params.id);
  res.sendStatus(204);
});

module.exports = router;
