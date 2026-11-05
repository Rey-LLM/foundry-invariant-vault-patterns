const crypto = require("crypto");

const webhookKey = Buffer.from(process.env.WEBHOOK_KEY, "base64");

function signWebhook(body) {
  return crypto.createHmac("sha256", webhookKey).update(body).digest("hex");
}

module.exports = { signWebhook };
