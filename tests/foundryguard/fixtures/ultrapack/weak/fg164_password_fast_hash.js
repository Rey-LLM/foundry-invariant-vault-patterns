const crypto = require("crypto");

async function register(db, email, password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const digest = crypto.createHash("sha256").update(salt + password).digest("hex");
  await db.users.insert({ email, salt, digest });
}

module.exports = { register };
