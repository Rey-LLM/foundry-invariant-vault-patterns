const argon2 = require("argon2");

async function register(db, email, password) {
  const digest = await argon2.hash(password, { type: argon2.argon2id });
  await db.users.insert({ email, digest });
}

module.exports = { register };
