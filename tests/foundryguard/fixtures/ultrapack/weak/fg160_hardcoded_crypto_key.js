const crypto = require("crypto");

function signWebhook(body) {
  return crypto.createHmac("sha256", "whk_live_3f9a1c77e2").update(body).digest("hex");
}

module.exports = { signWebhook };
