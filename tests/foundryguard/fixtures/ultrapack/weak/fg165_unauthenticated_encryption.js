const crypto = require("crypto");

const key = Buffer.from(process.env.DATA_KEY, "base64");

function seal(text) {
  const iv = crypto.randomBytes(16);
  const c = crypto.createCipheriv("aes-256-cbc", key, iv);
  return Buffer.concat([iv, c.update(text, "utf8"), c.final()]).toString("base64");
}

module.exports = { seal };
