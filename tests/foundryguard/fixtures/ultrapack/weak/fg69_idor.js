const { Order } = require("./models");

module.exports = (app) => {
  app.get("/orders/:id", async (req, res) => {
    const order = await Order.findById(req.params.id);
    res.json(order);
  });
};
