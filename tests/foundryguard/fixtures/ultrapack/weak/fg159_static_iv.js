const crypto = require("crypto");

const key = Buffer.from(process.env.DATA_KEY, "base64");

function seal(text) {
  const c = crypto.createCipheriv("aes-256-gcm", key, Buffer.alloc(12));
  const out = Buffer.concat([c.update(text, "utf8"), c.final()]);
  return Buffer.concat([out, c.getAuthTag()]).toString("base64");
}

module.exports = { seal };
