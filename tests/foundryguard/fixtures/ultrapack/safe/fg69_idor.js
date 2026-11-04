const { Order } = require("./models");

module.exports = (app) => {
  app.get("/orders/:id", async (req, res) => {
    const order = await Order.findById(req.params.id);
    if (!order || order.ownerId !== req.user.id) return res.sendStatus(403);
    res.json(order);
  });
};
