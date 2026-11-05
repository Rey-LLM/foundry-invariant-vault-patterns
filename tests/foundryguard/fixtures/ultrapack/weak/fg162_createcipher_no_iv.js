const crypto = require("crypto");

function seal(text, password) {
  const c = crypto.createCipher("aes-256-cbc", password);
  return c.update(text, "utf8", "hex") + c.final("hex");
}

module.exports = { seal };
